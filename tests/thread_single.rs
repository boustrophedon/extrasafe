// Technically this test is redundant since cargo test runs multiple threads in the same process
// and we would see errors there. It's still good documentation though.
//
// TODO we should write a test showing that seccomp filters don't override filters in
// different threads as documentation.

use extrasafe::builtins::SystemIO;

use std::sync::mpsc::sync_channel;
use std::thread;

use std::fs::File;

#[test]
/// When using per-thread contexts, check that you can enabled different filters on different
/// threads. This is achieved in this test by blocking IO on one thread and not on another, and
/// checking IO can be performed in the other thread after loading the context in the first.
fn different_threads_with_different_contexts() {

    // These channels will block on send until the receiver has called recv.
    let (sender1, recv1) = sync_channel::<()>(0);
    let (sender2, recv2) = sync_channel::<()>(0);

    let seccomp_thread = thread::spawn(move || {
        extrasafe::SafetyContext::new()
            .enable(SystemIO::nothing()
                .allow_stdout()
                .allow_stderr()).unwrap()
            .apply_to_current_thread().unwrap();
        // setup_done
        sender1.send(()).unwrap();

        // don't close this thread until the other thread is done asserting. This way we can be
        // sure the thread with the filter is definitely active when the other thread runs.
        let _io_test_passed = recv2.recv().unwrap();
        println!("exit seccomp thread");
    });

    let io_thread = thread::spawn(move || {
        let _setup_done = recv1.recv().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let mut path = dir.path().to_path_buf();
        path.push("can_open.txt");

        let res = File::create(&path);
        assert!(
            res.is_ok(),
            "Failed to open file even though there's no seccomp filter loaded in this thread."
        );

        // io_test_passed
        sender2.send(()).unwrap();
        println!("exit io thread");
    });

    let seccomp_res = seccomp_thread.join();
    assert!(
        seccomp_res.is_ok(),
        "seccomp thread failed: {:?}",
        seccomp_res.unwrap_err()
    );
    let io_res = io_thread.join();
    assert!(
        io_res.is_ok(),
        "io thread failed: {:?}",
        io_res.unwrap_err()
    );
}
