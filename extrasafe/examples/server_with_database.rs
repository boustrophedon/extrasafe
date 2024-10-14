//! A fully functioning example of a web server, an on-disk database, and an http client.
//!
//! We start a web server thread, which in turn "opens a connection" to a database server, which is
//! just sqlite running in another thread. The server has a /read and a /write endpoint. The write
//! endpoint writes a message to the db, and the read endpoint returns all the messages in the db.
//!
//! We run two clients that write to the database, then have a third client read back the messages
//! from it. Additionally, the read client also makes a request to a real https server to
//! demonstrate DNS and HTTPS support.
//!
//! There are some things to note here: I'm using threads to make it simpler to communicate between
//! the database and the web server, but this means that they share the same memory. If one of the
//! components in one thread had an RCE, this means that it would effectively have the same
//! capability as the sum of all the threads' capabilities because it could e.g. change the buffer
//! that a thread that can write to files is using to write from.
//!
//! In order to get more secure isolation, you'd want to have each thread run in separate
//! processes and communicate over a system IPC mechanism like pipes or local sockets. (This is
//! what web browsers do, for example.) You could maybe also play around with using pthreads
//! directly to pass the right flags to clone to not share memory when creating new threads, but I
//! think you'd still have issues where if a thread can read/write files, it would be able to read
//! its own process' binary in memory and modify it at runtime, since they would share the same
//! pid.

use extrasafe::builtins::{danger_zone::Threads, Networking, SystemIO};
use extrasafe::SafetyContext;

use crossbeam::channel;
use crossbeam_queue::SegQueue;

use warp::Filter;

use std::sync::Arc;

/// This is essentially the wire format for our DB connection
enum DBMsg {
    // Send a list of all the messages in the db over the channel.
    List(channel::Sender<Vec<String>>),
    // Write a message to the db.
    Write(String),
}

type DbConn = Arc<SegQueue<DBMsg>>;

fn with_db(
    db: DbConn,
) -> impl Filter<Extract = (DbConn,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || db.clone())
}

fn run_server() {
    // make queue (use crossbeam to show it works with extrasafe's builtin list)

    // pretend this is your db connection
    let queue: DbConn = Arc::new(SegQueue::new());
    // warp annoyance workaround
    let db_queue = queue.clone();
    let read_queue = queue.clone();
    let write_queue = queue;

    // spawn db server thread
    std::thread::Builder::new()
        .name("db".into())
        .spawn(move || run_db(&db_queue)).unwrap();
    
    // set up runtime
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:5575").unwrap();

    // extrasafe context
    SafetyContext::new()
        .enable(Networking::nothing()
            .allow_running_tcp_servers()).unwrap()
        .apply_to_current_thread()
        .unwrap();

    // set up server routes
    let routes = warp::path("write")
        .and(warp::post())
        .and(warp::body::bytes())
        .and(with_db(write_queue))
        .map(|param: bytes::Bytes, msg_queue: DbConn| {
            let s = std::str::from_utf8(&param).unwrap();
            msg_queue.push(DBMsg::Write(s.into()));

            "ok"
        })
        .or(warp::path("read")
            .and(warp::get())
            .and(with_db(read_queue))
            .map(|msg_queue: DbConn| {
                let (send, recv) = crossbeam_channel::bounded(1);

                msg_queue.push(DBMsg::List(send));

                let messages = recv.recv().unwrap();

                messages.join("\n")
            })
        );

    let svc = warp::service(routes);
    let make_svc = hyper::service::make_service_fn(move |_| {
        let warp_svc = svc.clone();
        async move { Ok::<_, std::convert::Infallible>(warp_svc) }
    });

    // https://docs.rs/tokio/latest/tokio/net/struct.TcpListener.html#method.from_std
    // requires a runtime to be active when converting the std::net::TcpListener to a tokio
    // listener
    let _in_runtime = runtime.enter();
    let server = hyper::Server::from_tcp(listener).unwrap();

    println!("Server about to start listening...");
    // block on server
    runtime.block_on(server.serve(make_svc)).unwrap();
}

fn run_db(queue: &DbConn) {
    let dir = tempfile::tempdir().unwrap();
    let mut path = dir.path().to_path_buf();
    path.push("testdb.sql3");

    let db = rusqlite::Connection::open(&path).unwrap();

    // Enabling either of these and then running a transaction will create the journal/wal files,
    // so that we don't have to enable opening files in our db thread after initialization.
    db.pragma_update(None, "locking_mode", "exclusive").unwrap();
    db.pragma_update(None, "journal_mode", "wal").unwrap();

    db.execute("CREATE TABLE messages ( msg TEXT NOT NULL );", []).unwrap();
    let mut get_rows = db.prepare("SELECT msg FROM messages;").unwrap();
    let mut insert_row = db.prepare("INSERT INTO messages VALUES (?)").unwrap();

    // after opening file, set extrasafe context
    SafetyContext::new()
        .enable(SystemIO::nothing()
            .allow_read()
            .allow_write()
            .allow_metadata()
            .allow_ioctl()
            .allow_close()).unwrap()
        .enable(Threads::nothing()
            .allow_sleep().yes_really()).unwrap()
        .apply_to_current_thread()
        .unwrap();

    println!("database opened at {:?}", &path);

    loop {
        if queue.is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(55));
            continue;
        }

        // note if there were multiple db threads this unwrap would be bad due to TOCTOU but here
        // it's fine because this thread is the only one that pops from the queue.
        let msg = queue.pop().unwrap();

        match msg {
            DBMsg::List(send) => {
                let messages: Vec<String> = get_rows
                    .query_map([], |row| row.get(0)).unwrap()
                    .map(Result::unwrap)
                    .collect();

                send.send(messages).unwrap();
            }
            DBMsg::Write(s) => {
                insert_row.execute([s]).unwrap();
            }
        }
    }
}

fn run_client_write(msg: &str) {
    // set up runtime
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build().unwrap();

    // Set up extrasafe context
    SafetyContext::new()
        .enable(Networking::nothing()
            .allow_start_tcp_clients()).unwrap()
        .apply_to_current_thread()
        .unwrap();
    println!("about to make request with msg {}", msg);

    // clone to move into async block
    let msg = msg.to_string();

    runtime.block_on(async {
        let client = reqwest::Client::new();

        let res = client
            .post("http://127.0.0.1:5575/write")
            .body(msg)
            .send()
            .await;
        assert!(
            res.is_ok(),
            "Error writing to server db: {:?}",
            res.unwrap_err()
        );

        let text = res.unwrap().text().await.unwrap();
        assert_eq!(text, "ok");
    });
}

fn run_client_read() {
    // set up runtime
    let runtime = tokio::runtime::Builder::new_current_thread()
        .worker_threads(1)
        .enable_all()
        .build().unwrap();

    let client = reqwest::Client::new();

    // enable extrasafe context
    let ctx = SafetyContext::new()
        .enable(Networking::nothing()
            // Necessary for DNS
            .allow_start_udp_servers().yes_really()
            .allow_start_tcp_clients()
            ).unwrap()
        // For some reason only if we make two requests with a client does it use multiple threads,
        // so we only need them in the reader thread rather than the writer.
        .enable(Threads::nothing()
            .allow_create()).unwrap();

    #[cfg(feature = "landlock")]
    let ctx = ctx.enable(
            SystemIO::nothing()
                .allow_dns_files()
                .allow_ssl_files()
        ).unwrap();
    #[cfg(not(feature = "landlock"))]
    let ctx = ctx.enable(
            SystemIO::nothing()
                .allow_open_readonly()
                .allow_read()
                .allow_metadata()
                .allow_close(),
        ).unwrap();

    ctx.apply_to_current_thread()
        .unwrap();

    // make request
    runtime.block_on(async {
        // Show that we can resolve dns and do ssl. Data returned isn't checked or used anywhere,
        // we just get it.
        let resp = client.get("https://example.org").send().await.unwrap();
        let res = resp.text().await;
        assert!(
            res.is_ok(),
            "failed getting example.org response: {:?}",
            res.unwrap_err()
        );
        let text = res.unwrap();
        println!("first 10 bytes of response from example.org {}", &text[..10]);

        let res = client.get("http://127.0.0.1:5575/read").send().await;
        assert!(
            res.is_ok(),
            "Error reading from server db: {:?}",
            res.unwrap_err()
        );

        let text = res.unwrap().text().await.unwrap();
        assert_eq!(text, "hello\nextrasafe");
        println!("got response: {}", text);
    });
}

fn main() {
    //  -- Spawn server
    let _server_thread = std::thread::Builder::new()
        .name("server".into())
        .spawn(run_server).unwrap();

    // give server time to start up
    std::thread::sleep(std::time::Duration::from_millis(100));

    // -- write "hello" to db
    let client1_thread = std::thread::Builder::new()
        .name("client1".into())
        .spawn(|| run_client_write("hello")).unwrap();

    let res1 = client1_thread.join();
    assert!(res1.is_ok(), "client1 failed: {:?}", res1.unwrap_err());

    // -- write "extrasafe" to db
    let client2_thread = std::thread::Builder::new()
        .name("client2".into())
        .spawn(|| run_client_write("extrasafe")).unwrap();

    let res2 = client2_thread.join();
    assert!(res2.is_ok(), "client2 failed: {:?}", res2.unwrap_err());

    // -- read back, check messages are there in order
    let client3_thread = std::thread::Builder::new()
        .name("client3".into())
        .spawn(run_client_read).unwrap();
    let res3 = client3_thread.join();
    assert!(res3.is_ok(), "client3 failed: {:?}", res3.unwrap_err());
}

// This test fails on musl because the local libsqlite3.so is not compiled with musl, and linking a
// glibc so into a musl program causes segfaults
#[cfg(target_env = "gnu")]
#[test]
fn run_main() {
    main()
}
