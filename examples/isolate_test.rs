#![cfg(feature = "isolate")]
/// Tests for isolate have to go in examples because tests in the tests/ directory get compiled as
/// test binaries and have their main fn overridden

// TODO: check unix domain sockets work as expected with isolated network namespace

use std::io::prelude::*;
use std::os::unix::net::{UnixStream, UnixListener};
use std::path::PathBuf;
use std::fs::File;

use std::collections::HashMap;
use extrasafe::isolate::Isolate;

fn check_isolate_output(isolate_name: &'static str, data: &[&str], envs: &HashMap<String, String>) {
    let output = Isolate::run(isolate_name, envs).expect("running isolate failed");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let outinfo = format!("\nstdout:\n{}\nstderr:\n{}", stdout, stderr);

    assert!(output.status.success(), "{:?}\n{}", output.status, outinfo);
    for s in data {
        assert!(stdout.contains(s), "{}", outinfo);
    }

    // check tmp dir is cleaned up
    for path in std::fs::read_dir("/tmp").unwrap().flatten() {
        let path = path.path();
        // NOTE: this might fail if you ran a test and it failed in a way the temp dir couldn't
        // be cleaned up (e.g. the strace segfault thing)
        assert!(!path.starts_with(isolate_name), "tmp dir still exists: {:?}", path.display());
    }

    println!("{} passed", isolate_name);
}

fn check_isolate_output_fail(isolate_name: &'static str, data: &[&str], envs: &HashMap<String, String>) {
    let output = Isolate::run(isolate_name, envs).expect("running isolate failed");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let outinfo = format!("\nstdout:\n{}\nstderr:\n{}", stdout, stderr);

    assert!(!output.status.success(), "isolate incorrently exited successfully: {:?}", output.status);
    for s in data {
        assert!(stderr.contains(s), "{}", outinfo);
    }
    println!("{} passed", isolate_name);
}


/// Test that running an isolate that assert(false) prints it to stderr and has a nonzero exit
/// code.
fn test_isolate_fail() {
    check_isolate_output_fail("isolate_fail", &["wild panic",], &HashMap::new());
}

/// Test that printing hello in the isolate is captured in the parent
fn test_isolate_hello() {
    check_isolate_output("isolate_hello", &["hello",], &HashMap::new());
}

/// Test that the isolate's uid is 0
fn test_isolate_uid() {
    check_isolate_output("isolate_uid", &["uid: 0",], &HashMap::new());
}

/// Test that we can mount a new proc and the mountinfo is correct
fn test_check_mountinfo() {
    let output = Isolate::run("check_mountinfo", &HashMap::new()).expect("running isolate failed");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    assert!(stdout.contains("/ / "), "missing root mount");
    assert!(!stdout.contains("/tmp"), "tmp from parent namespace visible");
    assert!(!stdout.contains("/proc_orig"), "proc from parent namespace visible");
    assert!(stderr.is_empty(), "stderr: {}", stderr);
    println!("check_mountinfo passed");
}

/// Test that we can bindmount a unix socket in a tempdir into the isolate and send a message from
/// the child to the parent.
fn test_unix_socket() {
    let tempdir = tempfile::tempdir().unwrap();
    let path = tempdir.path().join("parent.sock");
    let envs = vec![("ISOLATE_SOCKET_PATH".to_string(), path.display().to_string())].into_iter().collect();
    let handle = std::thread::spawn(move || {
        let output = Isolate::run("isolate_unix_socket", &envs).expect("running isolate failed");
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        assert!(output.status.success(), "{:?}\nstdout {}\nstderr {}", output.status, stdout, stderr);
    });

    let mut conn = UnixListener::bind(path).unwrap().incoming()
        .next()
        .unwrap()
        .unwrap();
    let mut resp = String::new();
    conn.read_to_string(&mut resp).unwrap();

    assert_eq!(resp, "hello from isolate");
    // make sure isolate runner thread exited successfully (although if it didn't we wouldn't
    // actually get here presumably because we'd be stuck at the unix socket's accept)
    let res = handle.join();
    assert!(res.is_ok(), "{:?}", res.unwrap_err());
    println!("isolate_unix_socket passed");
}

/// Test we can bindmount multiple directories at once
fn test_multiple_binds() {
    let tempdir1 = tempfile::tempdir().unwrap();
    let tempdir2 = tempfile::tempdir().unwrap();
    let path1 = tempdir1.path();
    let path2 = tempdir2.path();
    let envs = vec![
        ("ISOLATE_DIR_1".to_string(), path1.display().to_string()),
        ("ISOLATE_DIR_2".to_string(), path2.display().to_string()),
    ].into_iter().collect();

    // run isolate
    let output = Isolate::run("isolate_multiple_binds", &envs).expect("running isolate failed");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(output.status.success(), "{:?}\nstdout {}\nstderr {}", output.status, stdout, stderr);

    // read back values written inside isolate
    let f1 = std::fs::read_to_string(path1.join("hello")).unwrap();
    let f2 = std::fs::read_to_string(path2.join("hey")).unwrap();

    assert_eq!(f1, "abc");
    assert_eq!(f2, "xyz");
    println!("isolate_multiple_binds passed");
}

// TODO consolidate these into check_isolate_output/fails

/// Test tmpfs size limit parameter works
fn test_tmpfs_size_limit() {
    let output = Isolate::run("isolate_size_limit", &HashMap::new())
        .expect("running isolate failed");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // The isolate unwraps a write larger than the size limit for the tmpfs
    assert!(!output.status.success(), "{:?}\nstdout {}\nstderr {}", output.status, stdout, stderr);
    assert!(stderr.contains("large file failed"), "{:?}\nstdout {}\nstderr {}", output.status, stdout, stderr);
    assert!(stderr.contains("No space left on device"), "{:?}\nstdout {}\nstderr {}", output.status, stdout, stderr);

    println!("isolate_tmpfs_size passed");
}

/// Test making a network request succeeds if network is kept
/// Obviously, this requires that the parent namespace has a working network connection.
fn test_with_network() {
    let output = Isolate::run("isolate_with_network", &HashMap::new())
        .expect("running isolate failed");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    assert!(output.status.success(), "{:?}\nstdout {}\nstderr {}", output.status, stdout, stderr);
    println!("isolate_with_network passed");
}

/// Test making a network request does not succeed if new network namespace is created
fn test_no_network() {
    let output = Isolate::run("isolate_no_network", &HashMap::new())
        .expect("running isolate failed");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    assert!(!output.status.success(), "{:?}\nstdout {}\nstderr {}", output.status, stdout, stderr);
    assert!(stderr.contains("ConnectError"), "{:?}\nstdout {}\nstderr {}", output.status, stdout, stderr);
    println!("isolate_no_network passed");
}

/// Test we can use a standard `extrasafe::SafetyContext` inside an `Isolate`
fn test_safetycontext() {
    let output = Isolate::run("isolate_with_safetycontext", &HashMap::new())
        .expect("running isolate failed");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    assert!(output.status.success(), "{:?}\nstdout {}\nstderr {}", output.status, stdout, stderr);
    assert!(stdout.contains("we can print to stdout"), "{:?}\nstdout {}\nstderr {}", output.status, stdout, stderr);
    assert!(stderr.contains("we can print to stderr"), "{:?}\nstdout {}\nstderr {}", output.status, stdout, stderr);
    println!("isolate_with_safetycontext passed");

}

fn isolate_uid(name: &'static str) -> Isolate {
    fn uid() {
        let uid = unsafe { libc::getuid() };
        println!("uid: {}", uid);
    }
    Isolate::new(name, uid)
}

fn isolate_fail(name: &'static str) -> Isolate {
    fn fail() {
        panic!("a wild panic appears");
    }
    Isolate::new(name, fail)
}

fn isolate_hello(name: &'static str) -> Isolate {
    fn hello() {
        println!("hello");
    }
    Isolate::new(name, hello)
}

#[allow(unsafe_code)]
fn check_mountinfo() {
    use std::ffi::CString;

    // mount new proc
    std::fs::create_dir_all("/proc").unwrap();
    let proc_dircstr = CString::new("/proc").unwrap();
    let proc_cstr = CString::new("proc").unwrap();
    let rc = unsafe { libc::mount(proc_cstr.as_ptr(),
                                   proc_dircstr.as_ptr(),
                                   proc_cstr.as_ptr(),
                                   0,
                                   std::ptr::null()) };
    assert!(rc >= 0, "failed to mount new proc");

    // unmount old proc
    let orig_proc_dircstr = CString::new("/orig_proc").unwrap();
    let rc = unsafe { libc::umount2(orig_proc_dircstr.as_ptr(), libc::MNT_DETACH) };
    assert!(rc >= 0, "failed to unmount old proc");

    // read new proc mountinfo and print to be captured in test_check_mountinfo
    let s = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    println!("mountinfo:\n{}", s);
}

fn isolate_unix_socket(name: &'static str) -> Isolate {
    fn unix_hello() {
        let mut stream = UnixStream::connect("/isolate.sock").unwrap();
        stream.write_all(b"hello from isolate").unwrap();
    }
    let path = std::env::var("ISOLATE_SOCKET_PATH").unwrap();
    let path = PathBuf::from(path);
    Isolate::new(name, unix_hello)
        .add_bind_mount(path, "/isolate.sock")
}

fn isolate_multiple_binds(name: &'static str) -> Isolate {
    fn multiple_binds() {
        File::create("/path1/hello").unwrap()
            .write_all(b"abc").unwrap();
        File::create("/path2/hey").unwrap()
            .write_all(b"xyz").unwrap();
    }

    let path1 = std::env::var("ISOLATE_DIR_1").unwrap();
    let path1 = PathBuf::from(path1);
    let path2 = std::env::var("ISOLATE_DIR_2").unwrap();
    let path2 = PathBuf::from(path2);
    Isolate::new(name, multiple_binds)
        .add_bind_mount(path1, "/path1")
        .add_bind_mount(path2, "/path2")
}

fn isolate_size_limit(name: &'static str) -> Isolate {
    #[allow(clippy::cast_possible_truncation)]
    fn big_write() {
        let size = 1_500_000;
        let mut v = Vec::with_capacity(size);
        for i in 0..size {
            v.push((i % 255) as u8);
        }

        // This will fail
        File::create("/test").unwrap()
            .write_all(&v)
            .expect("writing large file failed");
    }

    Isolate::new(name, big_write)
        .set_rootfs_size(1)
}

// make an https request to example.org and check we can connect
fn network_call() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let resp = reqwest::get("https://example.org/").await;

        // will succeed in with_network and fail in no_network
        assert!(
            resp.is_ok(),
            "failed getting example.org response: {:?}",
            resp.unwrap_err()
        );
    });
}

fn isolate_with_network(name: &'static str) -> Isolate {
    Isolate::new(name, network_call)
        // ssl and dns files are all over the place.
        // If you wanted you could further restrict it via landlock or by mounting only specific
        // files and directories but it highly depends on your operating system and DNS setup. One
        // thing in particular to note is that if a file exists but it's a symlink to somewhere
        // outside the filesystem, something (e.g. openssl) might see that the file is there and
        // it can stat it, but then will try to read the file and crash.
        .add_bind_mount("/etc", "/etc")
        .add_bind_mount("/usr", "/usr")
        .add_bind_mount("/run", "/run")
        .add_bind_mount("/lib", "/lib")
        .new_network(false)
}

fn isolate_no_network(name: &'static str) -> Isolate {
    Isolate::new(name, network_call)
        .add_bind_mount("/", "/")
}

fn isolate_with_safetycontext(name: &'static str) -> Isolate {
    use extrasafe::SafetyContext;
    use extrasafe::builtins::*;
    fn use_safetycontext() {
        SafetyContext::new()
            .enable(SystemIO::nothing()
                .allow_stdout()
                .allow_stderr()
            ).unwrap()
            // can apply to all threads because we're in a separate process
            .apply_to_all_threads().unwrap();

            println!("we can print to stdout!");
            eprintln!("we can print to stderr!");

            assert!(File::create("test").is_err(), "shouldn't be able to open files");
    }

    Isolate::new(name, use_safetycontext)
}

fn main() {
    // Hooks first
    Isolate::main_hook("isolate_hello", isolate_hello);
    Isolate::main_hook("isolate_uid", isolate_uid);
    Isolate::main_hook("check_mountinfo", |s| {
        Isolate::new(s, check_mountinfo)
        .add_bind_mount("/proc", "/orig_proc")
    });
    Isolate::main_hook("isolate_size_limit", isolate_size_limit);
    Isolate::main_hook("isolate_fail", isolate_fail);
    Isolate::main_hook("isolate_unix_socket", isolate_unix_socket);
    Isolate::main_hook("isolate_multiple_binds", isolate_multiple_binds);
    Isolate::main_hook("isolate_with_network", isolate_with_network);
    Isolate::main_hook("isolate_no_network", isolate_no_network);
    Isolate::main_hook("isolate_with_safetycontext", isolate_with_safetycontext);

    let argv0 = std::env::args().next().unwrap();
    if argv0.contains("isolate_test") {
        // These tests actually launch the isolates, which then hit the hooks above after
        // re-execing
        test_isolate_hello();
        test_isolate_uid();
        test_check_mountinfo();
        test_unix_socket();
        test_multiple_binds();
        test_with_network();
        test_safetycontext();

        // TODO: for some reason these tests where the isolate panics make strace think there are
        // segfaults happening, and gets stuck continully outputting sigsegv messages even though
        // the program runs fine without strace. for now just put them at the end, but we should
        // investigate why it happens.
        // valgrind doesn't catch anything.
        test_no_network();
        test_tmpfs_size_limit();
        test_isolate_fail();
    }
    else {
        panic!("isolate didn't hit its hook: {}", argv0);
    }
}
