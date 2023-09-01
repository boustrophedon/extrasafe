use extrasafe::builtins::SystemIO;

use std::sync::mpsc::sync_channel;
use std::thread;

use std::fs::File;

#[test]
/// Test TSYNC behavior by enabling on one thread and failing IO on another.
fn sync_thread_contexts() {
    let dir = tempfile::tempdir().unwrap();

    // These channels will block on send until the receiver has called recv.
    let (sender1, recv1) = sync_channel::<()>(0);
    let (sender2, recv2) = sync_channel::<()>(0);

    let seccomp_thread = thread::spawn(move || {
        extrasafe::SafetyContext::new()
            .enable(SystemIO::nothing().allow_stdout().allow_stderr())
            .unwrap()
            .apply_to_all_threads()
            .unwrap();
        // setup_done
        sender1.send(()).unwrap();

        // don't close this thread until the other thread is done asserting. This way we can be
        // sure the thread that loaded the filter is definitely active when the other thread runs.
        let _io_test_passed = recv2.recv().unwrap();
        println!("exit seccomp thread");
    });

    let io_thread = thread::spawn(move || {
        let _setup_done = recv1.recv().unwrap();

        let mut path = dir.path().to_path_buf();
        path.push("can_open.txt");

        let res = File::create(&path);
        assert!(
            res.is_err(),
            "Incorrectly succeeded in opening file after seccomp was loaded on other thread"
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
