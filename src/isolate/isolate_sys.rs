//! Libc and syscall functions. Most of these functions do not return errors and simply panic
//! because once we're in the isolate, there's nothing to handle the error even if it were
//! propagated upwards.
//!
//! Control flow works as follows:
//! - We want to call some function `func` inside our namespace
//! - After re-executing self via Command, `Isolate::main_hook` eventually calls
//! `clone_into_namespace` with a bunch of configuration data, including which function we
//! eventually want to call
//! - `clone_into_namespace` sets up the clone syscall with the namespace parameters and the config
//! data, and calls clone with the `run_isolate` function
//! - `run_isolate` unpacks the config data and uses it to set up a new tmpfs and bindmounts inside it, then does `pivot_root` into the tmpfs.
//! - Finally, `run_isolate` calls `func` and then exits when it's done.
#![allow(unsafe_code)]
use std::path::{Path, PathBuf};
use std::fs::File;
use std::ffi::CString;
use super::IsolateError;
use std::io::Write;
use std::os::fd::FromRawFd;
use std::os::raw::c_char;

use std::collections::HashMap;

// 2MB (https://doc.rust-lang.org/std/thread/#stack-size)
// TODO: add config for this
pub const CHILD_STACK_SIZE: usize = 2_000_000;

/// Panic if the first parameter passed is negative. The provided message and the error message
/// from `std::io::Error::last_os_error()` are displayed in the panic string.
macro_rules! fail_negative {
    ($rc:expr, $message:expr) => {
        if ($rc < 0) {
            let err = std::io::Error::last_os_error();
            let msg = format!("{}: {}", $message, err);
            panic!("{}", msg);
        }
    }
}

/// Panic if the first parameter passed is a null pointer. The provided message and the error
/// message from `std::io::Error::last_os_error()` are displayed in the panic string.
macro_rules! fail_null {
    ($ptr:expr, $message:expr) => {
        if ($ptr.is_null()) {
            let err = std::io::Error::last_os_error();
            let msg = format!("{}: {}", $message, err);
            panic!("{}", msg);
        }
    }
}

/// Check rc for negative return code and create `std::io::Error`
fn check_err(retcode: i32) -> std::io::Result<()> {
    if retcode >= 0 {
        std::io::Result::Ok(())
    }
    else {
        std::io::Result::Err(std::io::Error::last_os_error())
    }
}

#[derive(Debug)]
/// Contains the data passed from the parent process to the Isolate via `libc::clone`'s `arg`
/// pointer parameter.
pub struct IsolateConfigData {
    /// The isolate name
    pub isolate_name: &'static str,
    /// The bindmount mappings
    pub bindmounts: HashMap<PathBuf, PathBuf>,
    /// The function to call after setup
    pub func: fn() -> (),
    /// The size of the tmpfs
    pub root_fs_size: u32,
    /// The user id of the parent process
    pub parent_user: libc::uid_t,
    /// The group id of the parent process
    pub parent_group: libc::gid_t,
    /// The temporary directory in which the Isolate will live.
    // TODO: technically we don't need this if we chdir in the parent before execing
    pub tempdir: PathBuf,
}

impl IsolateConfigData {
    pub fn new(isolate_name: &'static str, bindmounts: HashMap<PathBuf, PathBuf>, func: fn() -> (), root_fs_size: u32, tempdir: PathBuf) -> IsolateConfigData {
        let parent_user = unsafe { libc::geteuid() };
        let parent_group = unsafe { libc::getegid() };
        IsolateConfigData {
            isolate_name,
            bindmounts,
            func,
            root_fs_size,
            parent_user,
            parent_group,
            tempdir
        }
    }
}

/// Map the parent id to root in the new namespace. In the future it might be useful to allow other
/// users but root is used as a hint to the end-user that they have `CAP_SYS_ADMIN` in the
/// Isolate's namespace.
fn map_user_to_root(parent_user: libc::uid_t, parent_group: libc::gid_t) {
    std::fs::write("/proc/self/uid_map", format!("0 {parent_user} 1\n"))
        .expect("failed to map child id");
    std::fs::write("/proc/self/setgroups", "deny\n")
        .expect("failed to enable child group mapping");
    std::fs::write("/proc/self/gid_map", format!("0 {parent_group} 1\n"))
        .expect("failed to map child gid");
}

/// This is the "new main" function after the clone call.
extern "C" fn run_isolate(data: *mut libc::c_void) -> i32 {
    // This is valid because all virtual memory except the stack is cloned when we call the clone
    // syscall. All heap pointers are still valid, they just point to a new copy of the data.
    let dataptr: *mut IsolateConfigData = data.cast::<IsolateConfigData>();
    let config_data = unsafe { Box::from_raw(dataptr) };
    
    let isolate_name_cstr = CString::new(config_data.isolate_name)
        .expect("please don't put null bytes in your isolate name");
    let cstr_ptr = isolate_name_cstr.as_ptr();
    let rc = unsafe { libc::prctl(libc::PR_SET_NAME, cstr_ptr) };
    fail_negative!(rc, "prctl set process name failed");

    map_user_to_root(config_data.parent_user, config_data.parent_group);

    mount_tmpfs(&config_data.tempdir, config_data.root_fs_size);
    for (src, dst) in config_data.bindmounts {
        do_bindmount(&config_data.tempdir, &src, &dst);
    }
    do_pivot_root(&config_data.tempdir);
    //// TODO: if config_data.drop_caps, drop capabilities
    close_fds();
    (config_data.func)();
    std::process::exit(0);
}

/// Make a tempdir in /tmp in which to mount our private tmpfs where the isolate will eventually
/// live
pub fn make_tempdir(isolate_name: &str) -> PathBuf {
    assert!(isolate_name.is_ascii(), "tmpdir template name must be ascii");

    let template_str = format!("/tmp/{}.XXXXXX\0", isolate_name);
    let mut dir_buf: Vec<u8> = template_str.clone().into_bytes();

    let dir_ptr: *mut c_char = dir_buf.as_mut_ptr().cast::<c_char>();
    let ret = unsafe { libc::mkdtemp(dir_ptr) };
    fail_null!(ret, "failed to create temporary directory after clone");

    // remove null byte
    let _ = dir_buf.pop();
    let dir = String::from_utf8(dir_buf)
        .expect("mkdtemp template string should always be utf8");
    
    PathBuf::from(dir)
}

/// Mount a private tmpfs inside the created tempdir
fn mount_tmpfs(tempdir: &Path, max_size: u32) {
    let tmp_dircstr = CString::new(tempdir.as_os_str().as_encoded_bytes()).unwrap();
    let tmp_cstr = CString::new("tmpfs").unwrap();
    let options = CString::new(format!("size={}m", max_size)).unwrap();
    let options_ptr: *const libc::c_void = options.as_ptr().cast::<libc::c_void>();
    let rc = unsafe { libc::mount(tmp_cstr.as_ptr(),
                                   tmp_dircstr.as_ptr(),
                                   tmp_cstr.as_ptr(),
                                   0,
                                   options_ptr) };
    fail_negative!(rc, "failed to mount tmpfs after clone");

    // make sure the mount is private
    let empty_cstr = CString::new("").unwrap();
    let rc = unsafe { libc::mount(empty_cstr.as_ptr(),
                                   tmp_dircstr.as_ptr(),
                                   empty_cstr.as_ptr(),
                                   libc::MS_REC | libc::MS_PRIVATE,
                                   std::ptr::null()) };
    fail_negative!(rc, "failed to make tmpfs private after mounting");
}

/// Set up a bindmount inside the new root
fn do_bindmount(root: &Path, src: &Path, dst: &Path) {
    let dst = if dst.is_absolute() { dst.strip_prefix("/").unwrap() } else { dst };
    let dst = root.join(dst);

    // if directory, create all directories
    // else if file, socket, etc., create all parent directories and make empty file to bindmount
    // on to.
    if src.is_dir() {
        std::fs::create_dir_all(&dst)
            .unwrap_or_else(|_| panic!("failed to create dst directory (or parent directories) when bindmounting {}", dst.display()));
    }
    else {
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|_| panic!("failed to create parent directories when bindmounting {}", dst.display()));
        }
        drop(File::create(&dst)
            .unwrap_or_else(|_| panic!("failed to create empty file when bindmounting {}", dst.display())));
    }

    let src_dircstr = CString::new(src.as_os_str().as_encoded_bytes()).unwrap();
    let dst_dircstr = CString::new(dst.as_os_str().as_encoded_bytes()).unwrap();
    let bind_cstr = CString::new("bind").unwrap();
    let rc = unsafe { libc::mount(src_dircstr.as_ptr(),
                                   dst_dircstr.as_ptr(),
                                   bind_cstr.as_ptr(),
                                   libc::MS_REC | libc::MS_BIND,
                                   std::ptr::null()) };
    fail_negative!(rc, format!("failed to bindmount. do you have permissions for the src directory? dst must also exist! (it should be an empty file or directory)\nsrc: {:?}, dst: {:?}", src, dst));
}

/// `pivot_root(".", ".")` is explicitly documented in the manpage:
/// <https://man7.org/linux/man-pages/man2/pivot_root.2.html>
fn do_pivot_root(tmpfs: &Path) {
    // change directory to new root
    std::env::set_current_dir(tmpfs)
        .unwrap_or_else(|_| panic!("failed to chdir to {}", tmpfs.display()));

    // `pivot_root(".", ".")`
    let curdir_cstr = CString::new(".").unwrap();
    let curdir_ptr = curdir_cstr.as_ptr();
    let rc = unsafe { libc::syscall(libc::SYS_pivot_root, curdir_ptr, curdir_ptr) };
    fail_negative!(rc, format!("failed to pivot_root . . into {}", tmpfs.display()));

    // now unmount old / with MNT_DETACH
    let rc = unsafe { libc::umount2(curdir_ptr, libc::MNT_DETACH) };
    fail_negative!(rc, "failed to unmount old /");
}

pub fn create_memfd_from_self_exe() -> Result<File, IsolateError> {
    // Per the memfd_open manpage, multiple memfds can have the same name without issue.
    let memfd_name = CString::new("isolate_memfd").unwrap();

    let exe_data = std::fs::read("/proc/self/exe")
        .map_err(IsolateError::MemFd)?;
    let exe_bytes = &exe_data;
    let fsize = exe_bytes.len() as u64;
    let memfd = unsafe { libc::memfd_create(memfd_name.as_ptr(), 0) };
    check_err(memfd)
        .map_err(IsolateError::MemFd)?;
    let mut memfd_file = unsafe { std::fs::File::from_raw_fd(memfd) };
    memfd_file.set_len(fsize).expect("ftruncate on memfd");
    let _count = memfd_file.write(exe_bytes).expect("write exe data to memfd after sizing");

    Ok(memfd_file)
}

pub fn clone_into_namespace(stack: &mut [u8],
        config_data: IsolateConfigData,
        new_network: bool) ->
        (libc::pid_t, libc::id_t) {
    let flags = libc::CLONE_NEWNS | libc::CLONE_NEWUSER | libc::CLONE_NEWPID | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS  | libc::CLONE_PIDFD;
    let flags = if new_network {
        flags | libc::CLONE_NEWNET
    } else { flags };

    let mut pidfd: libc::pid_t = 0; 
    // the argument used for pidfd is defined as an i32/pid_t but waitid takes a u32/id_t so we
    // convert on return
    let pidfd_ref: *mut libc::pid_t = &mut pidfd;

    //let stack_ptr = unsafe { std::mem::transmute::<*mut u8, *mut libc::c_void>(stack.as_mut_ptr().wrapping_add(CHILD_STACK_SIZE)) };
    // The stack grows down, so we need to provide clone a pointer to the end of our stack data
    // vec.
    let stack_ptr: *mut libc::c_void = stack.as_mut_ptr().wrapping_add(CHILD_STACK_SIZE).cast::<libc::c_void>();

    let fnptr = run_isolate;
    let data = Box::new(config_data);
    let data_ptr: *mut libc::c_void = Box::into_raw(data).cast::<libc::c_void>();
    
    let pid = unsafe { libc::clone(fnptr, stack_ptr, flags, data_ptr, pidfd_ref) };
    (pid, pidfd.try_into().unwrap())
}

pub fn wait_for_child(pidfd: libc::id_t) -> i32 {
    let mut child_status: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let rc = unsafe {libc::waitid(libc::P_PIDFD, pidfd, &mut child_status, libc::__WALL | libc::WEXITED) };
    fail_negative!(rc, "waitid failed");
    unsafe { child_status.si_status() }
}

/// Close all fds >= 3, leaving stdin, stdout, stderr alone
fn close_fds() {
    let flags: i32 = libc::CLOSE_RANGE_UNSHARE.try_into().unwrap();
    let rc = unsafe { libc::syscall(libc::SYS_close_range, 3, u32::MAX, flags) };
    fail_negative!(rc, "failed to close fds > 3 after pivot_root");
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    #[test]
    #[should_panic(expected = "catch me abc")]
    fn test_fail_negative() {
        // we definitely shouldn't have 9k+ fds open so this should always fail
        let rc = unsafe { libc::close(9999) };
        fail_negative!(rc, "catch me abc");
    }

    #[test]
    #[should_panic(expected = "catch me xyz")]
    fn test_fail_null() {
        let path = CString::new("/nonexistant123").unwrap();
        let r = CString::new("r").unwrap();
        let f = unsafe { libc::fopen(path.as_ptr(), r.as_ptr()) };
        fail_null!(f, "catch me xyz");
    }
}
