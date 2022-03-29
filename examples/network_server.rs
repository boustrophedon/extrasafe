use extrasafe::{
    builtins::{danger_zone::Threads, Networking},
    SafetyContext,
};

use warp::Filter;

use std::thread;

/// Set up a warp server, enable `SafetyContext` to prevent further socket creations and bindings,
/// make and recieve a request successfully, then try to bind another server and fail.
fn main() {
    // (code follows explanation)
    //
    // What I really would like to do is something like the following, the same as with the
    // allow_fd() in SystemIO:
    //
    // ```
    // let listener = TcpListener::bind("127.0.0.1:8741").unwrap();
    // let fd = listener.as_raw_fd();
    // // then make SafetyContext here, and inside the Networking have an
    // // .allow_socket(fd)
    //
    // // then set up warp server via hyper. There might be a better way to do this?
    // // from https://docs.rs/warp/latest/warp/fn.service.html
    // let route = warp::any().map(|| "Hello world");
    // let svc = warp::service(route);
    // let make_svc = hyper::service::make_service_fn(move |_| async move {
    //     Ok::<_, Infallible>(svc)
    // });
    //
    // let server = hyper::Server::from_tcp(listener);
    // server.serve(make_svc)
    // .await?;
    // ```
    //
    //
    // However, what actually happens is that:
    //
    // - epoll setup to get an epoll fd inside tokio runtime
    // - get a socket fd with TcpListener as above
    //   - socket() returns an fd
    //   - bind() on the socket with the address/port
    //   - listen() on the socket
    // - tokio adds the socket to the epoll fd
    // - we call accept() and get a *new fd*, which our security context can't and doesn't know
    // about.
    //   - this fd represents the connection to that particular client
    // - we then add that fd to the epoll fd
    // - we recvfrom that fd
    // - we write to that fd
    //
    // (note that I don't know async IO well enough to know what precisely triggers epoll or
    // whatever to say "you can now recvfrom this fd" because in the strace i'm looking at,
    // the thread that we do recv_from doesn't have an epoll_wait. perhaps tokio does the wait on
    // one thread and then lets another one do the recv, but even then I don't actually see an
    // epoll_wait on the epoll fd that has the socket we're accepting from - there's an
    // epoll_ctl(EPOLL_CTL_ADD) with the socket but we don't epoll_wait on it)
    // to add it )
    //
    // now there are two problems here
    // 1. we can't limit recvfrom or write to the socket we originally created, because it's not
    //    the socket/fd we end up reading/writing to
    // 2. write is reused across multiple systems so if we allow write broadly, we open up access
    //    to any fds we can get our hands on.
    //
    // so we have two solutions, which are mirror images of each other:
    // - limit socket and bind, which is used by both tcp and udp to "open network connections"
    // - limit openat, which is used to "open files"
    //

    // So what we end up doing is as described in the function comment: Make the server first, then
    // enable it. This is almost the same effect as SystemIO::allow_fd() but without the conditionals
    // on recvfrom/write.

    let _server_thread = thread::spawn(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let routes = warp::any().map(|| "hello seccomp");
        let server = warp::serve(routes).run(([127, 0, 0, 1], 3030));
        runtime.block_on(server);
    });

    // TODO: build hyper server from tcpconnection and bind, then send message over mpsc to signal
    // we can enable safetycontext, rather than just waiting 50ms.
    thread::sleep(std::time::Duration::from_millis(50));
    SafetyContext::new()
        .enable(Networking::nothing()
            .allow_running_tcp_servers()
            .allow_start_tcp_clients()
        ).unwrap()
        .enable(Threads::nothing()
            .allow_create()).unwrap()
        .apply_to_all_threads()
        .unwrap();

    // create a tokio runtime in this thread
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    println!("making request to local server...");
    let res = runtime.block_on(reqwest::get("http://127.0.0.1:3030"));
    assert!(
        res.is_ok(),
        "Error getting reply from server: {:?}",
        res.unwrap_err()
    );

    let text = runtime.block_on(res.unwrap().text()).unwrap();
    assert_eq!(text, "hello seccomp");
    println!("recieved response: {}", text);

    // Now see we fail to bind a new server.
    let res = std::net::TcpListener::bind("127.0.0.1:3031");
    assert!(res.is_err(), "Incorrectly suceeded in binding to socket");
    println!("successfully failed to bind new server");

    // Blocking version (runtime above not necessary):
    //
    // println!("making request...");
    // let res = reqwest::blocking::Client::new().get("http://127.0.0.1:3030").send();
    // assert!(res.is_ok(), "Error getting reply from server: {:?}", res.unwrap_err());

    // let text = res.unwrap().text().unwrap();
    // assert_eq!(text, "hello seccomp");
    // println!("recieved response: {}", text);
}

#[test]
fn run_main() {
    main()
}
