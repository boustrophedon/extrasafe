#![cfg(feature = "isolate")]
// The capabilities function technically does not require isolates but it's easier to test with
// them vs trying to cook up some binary with file capabilities and then manually raising the
// capability only to drop it afterwards

/// Test using extrasafe's drop capabilities in conjunction with an isolate
/// In `drop_caps`, show we cannot create a raw socket after entering the isolate

// TODO: test we can't exec a file with suid root or file capabilities (because of no_new_privs)


use std::collections::HashMap;
use extrasafe::isolate::Isolate;
use extrasafe::drop_all_caps;

#[allow(unsafe_code)]
/// creates a raw socket and prints the fd
fn create_raw_socket() {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    println!("raw socket fd {fd}");
}

fn drop_caps(name: &'static str) -> Isolate {
    // create_raw_socket prints out the fd and we just check it in the output
    fn raw_socket_drop_caps() {
        // first show we can create a raw socket
        create_raw_socket();

        // drop caps
        let rc = drop_all_caps();
        assert!(rc.is_ok());

        // after dropped caps, can still make a udp socket
        let _udp_socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .expect("creating udp socket failed");
        // but we cannot make a raw socket
        create_raw_socket();

        // try dropping caps again and check it doesn't error
        let rc = drop_all_caps();
        assert!(rc.is_ok(), "{:?}", rc.unwrap_err());

        // NOTE/TODO: You can run the `caps::raise` part of the test by including caps as a dev
        // dependency in Cargo.toml but I don't think it's really worth having the entire
        // dependency just for this one test, and I didn't really want to write more capget/capset
        // wrappers just for this test. You can also put the following lines above "drop caps" to
        // check CAP_SYS_ADMIN is in the original effective set
        // ```
        // use caps::{CapSet, Capability};
        // let cur = caps::read(None, CapSet::Permitted).unwrap();
        // println!("{cur:?}");
        // let perm_admin = caps::has_cap(None, CapSet::Effective, Capability::CAP_SYS_ADMIN).unwrap();
        // assert!(perm_admin);
        // ```

        // // Try to regain CAP_SYS_ADMIN and fail
        // let res = caps::raise(None, CapSet::Effective, Capability::CAP_SYS_ADMIN);
        // assert!(res.is_err(), "{:?}", res.unwrap_err());

    }
    Isolate::new(name, raw_socket_drop_caps)
}

fn main() {
    Isolate::main_hook("drop_caps", drop_caps);

    let output = Isolate::run("drop_caps", &HashMap::new())
        .expect("running isolate failed");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let outinfo = format!("\nstdout:\n{}\nstderr:\n{}", stdout, stderr);

    assert!(output.status.success(), "{:?}\n{}", output.status, outinfo);
    // creating socket initially works
    // all other fds are cleared at the start of an isolate so it should always be fd 3
    assert!(stdout.contains("raw socket fd 3"), "{outinfo}");
    // creating socket after dropping caps fails
    assert!(stdout.contains("raw socket fd -1"), "{outinfo}");

    println!("drop_caps passed");
}
