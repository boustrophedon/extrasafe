#![allow(clippy::unused_io_amount)]

//! A fully functioning example of a web server, an on-disk database, and an http client, with
//! subprocesses communicating via a unix socket.
//!
//! We start a web server thread, which in turn "opens a connection" to a database server, which is
//! just sqlite running in another thread. The server has a /read and a /write endpoint. The write
//! endpoint writes a message to the db, and the read endpoint returns all the messages in the db.
//!
//! We run two clients that write to the database, then have a third client read back the messages
//! from it. Additionally, the read client also makes a request to a real https server to
//! demonstrate DNS and HTTPS support.

use extrasafe::builtins::{danger_zone::Threads, Networking, SystemIO};
use extrasafe::SafetyContext;

use std::io::prelude::*;

use warp::Filter;

use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;

use std::sync::{Arc, Mutex};

/// This is essentially the wire format for our DB connection
enum DBMsg {
    // Send a list of all the messages in the db over the channel.
    List,
    // Write a message to the db.
    Write(String),
}

type DbConn = Arc<Mutex<UnixStream>>;

fn run_subprocess(cmd: &[&str]) -> std::process::Child {
    let exe_path = std::env::current_exe().unwrap();

    let args: Vec<_> = ["run_main", "--", "--sub"].iter().chain(cmd.iter()).collect();

    std::process::Command::new(exe_path.to_str().unwrap())
        .arg0(format!("{}-subprocess", cmd[0]))
        .args(&args)
        .spawn()
        .map_err(|e| format!("subcommand `{}` failed to start: {:?}", cmd.join(" "), e))
        .unwrap()
}

fn with_db(
    db: DbConn,
) -> impl Filter<Extract = (DbConn,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || db.clone())
}

fn run_webserver(db_socket_path: &str) {
    // we open the socket ahead of time and share it among all webserver http threads (just like
    // with a real db connection we could have a pool of them instead of a single one)

    println!("webserver thread connecting to db unix socket");
    let socket = UnixStream::connect(db_socket_path).expect("failed to connect to db socket");
    let db_socket: DbConn = Arc::new(Mutex::new(socket));

    // set up runtime
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:5576").unwrap();

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
        .and(with_db(db_socket.clone()))
        .map(|param: bytes::Bytes, db_conn: DbConn| {
            println!("webserver got write request");
            let mut conn = db_conn.lock().unwrap();

            let s = std::str::from_utf8(&param).unwrap();
            conn.write_all(format!("write {}", s).as_bytes())
                .expect("failed to send write message to db");

            "ok"
        })
        .or(warp::path("read")
            .and(warp::get())
            .and(with_db(db_socket))
            .map(|db_conn: DbConn| {
                println!("webserver got read request");
                let mut conn = db_conn.lock().unwrap();

                println!("sending list command to db");
                conn.write_all("list".as_bytes())
                    .expect("failed to send read message to db");

                println!("waiting for response from db");
                let mut buf: [u8; 100] = [0; 100];
                conn.read(&mut buf)
                    .expect("failed to read response from db");
                println!("got response from db");

                let messages = String::from_utf8(buf.to_vec())
                    .unwrap()
                    .trim_end_matches('\0')
                    .to_string();

                messages
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

fn run_db(socket_path: &str) {
    // open socket connection to listen to requests on
    let socket = UnixListener::bind(socket_path).unwrap();

    // open sqlite database
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

    // after opening connection socket and db file, set extrasafe context
    SafetyContext::new()
        .enable(Networking::nothing()
            .allow_connect()
            .yes_really()
            .allow_running_unix_servers()
        ).unwrap()
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

    println!("db server waiting to accept connection");
    // We only ever expect one connection from our webserver, so we wait for it and then loop
    let conn = socket.accept();
    if let Err(err) = conn {
        panic!("Error accepting db connection: {:?}", err);
    }

    let (mut conn, _) = conn.unwrap();
    println!("db server got connection on unix socket");

    loop {
        println!("db server waiting for unix socket message");
        let mut buf: [u8; 100] = [0; 100];
        conn.read(&mut buf)
            .expect("failed reading request to db server");

        let buf = String::from_utf8(buf.to_vec())
            .unwrap()
            .trim_end_matches('\0')
            .to_string();

        println!("db got unix socket message: '{}'", buf);

        let msg: DBMsg;
        if buf == "list" {
            msg = DBMsg::List;
        }
        else if buf.starts_with("write") {
            msg = DBMsg::Write(buf[6..].to_string());
        }
        else {
            panic!("unknown message recieved in db: {}", buf);
        }

        match msg {
            DBMsg::List => {
                let messages: Vec<String> = get_rows
                    .query_map([], |row| row.get(0)).unwrap()
                    .map(Result::unwrap)
                    .collect();

                conn.write_all(messages.join("\n").as_bytes())
                    .expect("failed writing response from db server");
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
        .build()
        .unwrap();

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
            .post("http://127.0.0.1:5576/write")
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
        .build()
        .unwrap();

    // Open client before extrasafe context so that it can read ssl certificates and dns stuff
    let client = reqwest::Client::new();

    // enable extrasafe context
    SafetyContext::new()
        .enable(Networking::nothing()
            // Necessary for DNS
            .allow_start_udp_servers().yes_really()
            .allow_start_tcp_clients()).unwrap()
        // For some reason only if we make two requests with a client does it use multiple threads,
        // so we only need them in the reader thread rather than the writer.
        .enable(Threads::nothing()
            .allow_create()).unwrap()
        // Read required to get DNS info (e.g. resolv.conf) and read ssl certificates.
        // TODO: Is there a way to do this ahead of time?
        .enable(
            SystemIO::nothing()
                .allow_open_readonly()
                .allow_read()
                .allow_metadata()
                .allow_close(),
        )
        .unwrap()
        .apply_to_current_thread()
        .unwrap();

    // make request
    runtime.block_on(async {
        // Show that we can resolve dns and do ssl. Data returned isn't checked or used anywhere,
        // we just get it.
        let resp = client.get("https://example.org/").send().await.unwrap();
        let res = resp.text().await;
        assert!(
            res.is_ok(),
            "failed getting example.org response: {:?}",
            res.unwrap_err()
        );

        println!("about to make read request to webserver");
        let res = client.get("http://127.0.0.1:5576/read").send().await;
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
    let args: Vec<String> = std::env::args().collect();
    println!("main args: {:?}", args);

    if args.contains(&"--sub".into()) {
        // If args is "example_prog [possible other options] --sub subcommand subargs...", run the subcommand
        if let Some(idx) = args.iter().position(|s| s == "db") {
            run_db(&args[idx+1]);
        }
        else if let Some(idx) = args.iter().position(|s| s == "webserver") {
            run_webserver(&args[idx+1]);
        }
        else if args.contains(&"read_client".into()) {
            run_client_read();
        }
        else if let Some(idx) = args.iter().position(|s| s == "write_client") {
            run_client_write(&args[idx+1]);
        }
        return;
    }

    // otherwise, spawn db, spawn webserver as subprocesses which communicate over a unix socket.
    // then spawn write subprocesses and read subprocesses sequentially, waiting for them to exit
    // each time.

    let dir = tempfile::TempDir::new().unwrap();
    let mut path = dir.path().to_path_buf();
    path.push("db.sock");

    // -- Spawn database, spawn http server, waiting a bit for each to finish getting ready.
    let mut db_child = run_subprocess(&["db", path.to_str().unwrap()]);
    std::thread::sleep(std::time::Duration::from_millis(100));

    let mut webserver_child = run_subprocess(&["webserver", path.to_str().unwrap()]);
    std::thread::sleep(std::time::Duration::from_millis(100));

    // -- write "hello" to db
    let res1 = run_subprocess(&["write_client", "hello"]).wait();
    assert!(
        res1.is_ok(),
        "client1 failed to finish: {:?}",
        res1.unwrap_err()
    );
    let status = res1.unwrap();
    assert!(
        status.success(),
        "client1 exited unsuccessfully: {:?}",
        status
    );

    // -- write "extrasafe" to db
    let res2 = run_subprocess(&["write_client", "extrasafe"]).wait();
    assert!(
        res2.is_ok(),
        "client2 failed to finish: {:?}",
        res2.unwrap_err()
    );
    let status = res2.unwrap();
    assert!(
        status.success(),
        "client2 exited unsuccessfully: {:?}",
        status
    );

    // -- read back, check messages are there in order
    let res3 = run_subprocess(&["read_client"]).wait();
    assert!(
        res3.is_ok(),
        "client3 failed to finish: {:?}",
        res3.unwrap_err()
    );
    let status = res3.unwrap();
    assert!(
        status.success(),
        "client3 exited unsuccessfully: {:?}",
        status
    );

    db_child.kill().unwrap();
    webserver_child.kill().unwrap();
}

// TODO: this test fails with musl probably because of timing differences.
// Instead of just waiting 100 ms, actually use signalling via mpsc::sync_channel to indicate when
// server is ready. I'm not 100% sure that's the issue though.
//
// However, even if that part worked it would still fail on musl because the local libsqlite3.so is
// not compiled with musl, and linking a glibc so into a musl program causes segfaults
#[cfg(target_env = "gnu")]
#[test]
fn run_main() {
    main()
}
