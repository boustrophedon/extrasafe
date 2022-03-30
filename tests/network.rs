#![allow(clippy::unused_io_amount)]

use extrasafe::{
    builtins::{danger_zone::Threads, Networking},
    SafetyContext,
};

use std::io::{Read, Write};

use std::sync::mpsc::sync_channel;

use std::thread;

#[test]
/// Bind a udp socket set to recieve a message on one thread, bind another one to send it on the
/// main thread, enable seccomp, send the message and get a response. Then try to bind a new socket
/// and check that it fails.
fn test_udp() {

    // These block on send until reciever has finished recv.
    let (sender1, recv1) = sync_channel::<()>(0);

    let server_handle = thread::spawn(move || {
        let server_socket = std::net::UdpSocket::bind("127.0.0.1:30357").unwrap();

        // setup done
        sender1.send(()).unwrap();

        let mut buf = [1; 14];
        let (count, origin) = server_socket.recv_from(&mut buf).unwrap();

        assert_eq!(count, 10);
        assert_eq!(buf, "message :)\x01\x01\x01\x01".as_bytes());

        let res = server_socket.send_to("response :)".as_bytes(), origin);
        assert!(
            res.is_ok(),
            "Failed to send response from server: {:?}",
            res.unwrap_err()
        );
    });

    let _setup_done = recv1.recv().unwrap();

    let client_socket = std::net::UdpSocket::bind("127.0.0.1:30493").unwrap();
    client_socket.connect("127.0.0.1:30357").unwrap();

    // create safetycontext after server and client have been bound.
    SafetyContext::new()
        .enable(
            Networking::nothing()
                .allow_running_udp_sockets()
        ).unwrap()
        .enable(
            Threads::nothing()
                .allow_create()
        ).unwrap()
        .apply_to_current_thread()
        .unwrap();

    let res = client_socket.send("message :)".as_bytes());
    assert!(
        res.is_ok(),
        "failed to send message to udp server: {:?}",
        res.unwrap_err()
    );

    let mut buf = [2; 14];
    client_socket.recv_from(&mut buf).unwrap();
    assert_eq!(buf, "response :)\x02\x02\x02".as_bytes());

    println!("before join");
    let res = server_handle.join();
    assert!(res.is_ok(), "Error recv on server: {:?}", res.unwrap_err());

    // now try to bind again and fail
    let res = std::net::UdpSocket::bind("127.0.0.1:30358");
    assert!(res.is_err(), "Incorrectly succeeded in binding to socket");
}

#[test]
/// Bind a tcp server on one thread, connect to it with a client socket to send it on the main
/// thread, enable seccomp, send the message and get a response. Then try to bind a new socket and
/// check that it fails.
///
/// You can see an example using an actual http server in `examples/network_server.rs`
fn test_tcp() {
    // These block on send until reciever has finished recv.
    let (sender1, recv1) = sync_channel::<()>(0);

    let server_handle = thread::spawn(move || {
        let server_socket = std::net::TcpListener::bind("127.0.0.1:31357").unwrap();

        // setup done
        sender1.send(()).unwrap();

        let mut buf = [3; 14];
        let (mut incoming, _remote_addr) = server_socket.accept().unwrap();
        let count = incoming.read(&mut buf).unwrap();

        assert_eq!(count, 10);
        assert_eq!(buf, "message :)\x03\x03\x03\x03".as_bytes());

        let res = incoming.write("response :)".as_bytes());
        assert!(
            res.is_ok(),
            "Failed to send response from udp server: {:?}",
            res.unwrap_err()
        );
    });

    let _setup_done = recv1.recv().unwrap();

    let mut client_socket = std::net::TcpStream::connect("127.0.0.1:31357").unwrap();

    // create safetycontext after server and client have been bound.
    SafetyContext::new()
        .enable(Networking::nothing()
            .allow_running_tcp_clients()
        ).unwrap()
        .enable(Threads::nothing()
            .allow_create()).unwrap()
        .apply_to_current_thread()
        .unwrap();

    let res = client_socket.write("message :)".as_bytes());
    assert!(
        res.is_ok(),
        "failed to send message to tcp server: {:?}",
        res.unwrap_err()
    );

    let mut buf = [2; 14];
    client_socket.read(&mut buf).unwrap();
    assert_eq!(buf, "response :)\x02\x02\x02".as_bytes());

    println!("before join");
    let res = server_handle.join();
    assert!(
        res.is_ok(),
        "Error read from server: {:?}",
        res.unwrap_err()
    );

    // now try to bind again and fail
    let res = std::net::TcpListener::bind("127.0.0.1:31359");
    assert!(res.is_err(), "Incorrectly succeeded in binding to socket");
}
