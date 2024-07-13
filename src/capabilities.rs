// pid should typically always be 0 for the current process
#[repr(C)]
struct __user_cap_header_struct {
    version: u32,
    pid: i32,
}

// data is defined like this because you pass a 1 element array with v1 caps and a 2 element array
// with v2+ caps (to make 64 bits per field). it's easier to just pack all the data in one struct
// rather than constructing an array of two structs and pass a pointer to them.
//
// Honestly, I could have just defined this as [u32; 6] but just in case it's necessary at some
// point to keep specific caps it seemed better to have it like this now.
#[repr(C)]
struct __user_cap_data_struct {
    effective0: u32,
    permitted0: u32,
    inheritable0: u32,
    effective1: u32,
    permitted1: u32,
    inheritable1: u32,
}

// TODO: we could use prctl PR_CAPBSET_DROP/PR_CAP_AMBIENT to drop from the bounding/ambient set as
// well, but since we're using no_new_privs it doesn't seem worth it. Also note that no_new_privs
// makes securebits obsolete for the most part.

#[allow(unsafe_code)]
/// Drops all [linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html) and
/// sets [the no_new_privs
/// bit](https://man7.org/linux/man-pages/man2/PR_SET_NO_NEW_PRIVS.2const.html) so that they cannot
/// be regained via exec.
///
/// # Errors
/// The resulting error type does not distinguish between prctl errors and capset errors.
pub fn drop_all_caps() -> std::io::Result<()> {
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Magic number from <linux/capability.h>
    const CAPABILITY_VERSION_3: u32 = 0x20080522;
    let header = __user_cap_header_struct {
        version: CAPABILITY_VERSION_3,
        pid: 0, // current process
    };

    let data = __user_cap_data_struct {
        effective0: 0,
        permitted0: 0,
        inheritable0: 0,
        effective1: 0,
        permitted1: 0,
        inheritable1: 0,
    };

    let rc = unsafe { libc::syscall(libc::SYS_capset, &header, &data ) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

