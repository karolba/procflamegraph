use crate::sys_linux::fd::read_to_maybe_uninit;
use crate::sys_linux::macros::eintr_repeat;
use nix::errno::Errno;
use nix::fcntl::{open, OFlag};
use nix::sys::stat::{stat, FileStat, Mode};
use nix::unistd::Pid;
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};


struct ReadOptions {
    initial_buffer_size: u32,
    expand_buffer_by: u32,
    expand_buffer_on_partial_read: u32,
}
// Like standard fs::read but restarts on EINTR (which we need enabled for waitpid cancellation)
// a small optimisation: returns the OwnedFd that close()s
// since the latency to PTRACE_CONT is what matters the most to us, letting our tracees continue
// This really could be a better designed api though, maybe take a closure and close() after the closure?
fn read(path: &CStr, read_options: ReadOptions) -> Result<(Vec<u8>, OwnedFd), Errno> {
    let fd: OwnedFd = eintr_repeat!(open(path, OFlag::O_RDONLY | OFlag::O_CLOEXEC, Mode::empty()))?;

    // small initial buffer for possibly small files
    let mut data: Vec<u8> = Vec::with_capacity(read_options.initial_buffer_size as usize);

    loop {
        match eintr_repeat!(read_to_maybe_uninit(fd.as_fd(), data.spare_capacity_mut())) {
            Ok(0) => break,
            Ok(num) => {
                unsafe { data.set_len(data.len() + num) }
                let read_was_exact = num == data.capacity();
                data.reserve(if read_was_exact { read_options.expand_buffer_by } else { read_options.expand_buffer_on_partial_read } as usize);
            }
            Err(err) => Err(err)?,
        };
    }

    data.shrink_to_fit();
    Ok((data, fd))
}

pub(crate) fn process_cmdline(pid: Pid) -> Result<(Vec<u8>, OwnedFd), Errno> {
    const PATH_SIZE: usize = c"/proc/-2147483648/cmdline".to_bytes_with_nul().len();
    let mut path: [MaybeUninit<u8>; PATH_SIZE] = [const { MaybeUninit::uninit() }; PATH_SIZE];

    let size: usize = unsafe {
        // The easiest way to fill up a c_char array on the stack in rust
        libc::snprintf(
            path.as_mut_ptr() as *mut libc::c_char,
            PATH_SIZE,
            c"/proc/%d/cmdline".as_ptr(),
            pid.as_raw() as libc::c_int,
        )
    } as usize + 1; // +1 for the null terminator

    let path = unsafe { path[..size].assume_init_ref() };
    let path = unsafe { CStr::from_bytes_with_nul_unchecked(path) };

    read(path, ReadOptions {
        initial_buffer_size: 128,
        expand_buffer_by: 2048,
        expand_buffer_on_partial_read: 16,
    })
}

pub(crate) fn process_environ(pid: Pid) -> Result<(Vec<u8>, OwnedFd), Errno> {
    const PATH_SIZE: usize = c"/proc/-2147483648/environ".to_bytes_with_nul().len();
    let mut path: [MaybeUninit<u8>; PATH_SIZE] = [const { MaybeUninit::uninit() }; PATH_SIZE];

    let size: usize = unsafe {
        // The easiest way to fill up a c_char array on the stack in rust
        libc::snprintf(
            path.as_mut_ptr() as *mut libc::c_char,
            PATH_SIZE,
            c"/proc/%d/environ".as_ptr(),
            pid.as_raw() as libc::c_int,
        )
    } as usize + 1; // +1 for the null terminator

    let path = unsafe { path[..size].assume_init_ref() };
    let path = unsafe { CStr::from_bytes_with_nul_unchecked(path) };

    read(path, ReadOptions {
        initial_buffer_size: 2048,
        expand_buffer_by: 4096,
        expand_buffer_on_partial_read: 32,
    })
}

pub(crate) fn process_stat(pid: Pid) -> Result<(Vec<u8>, OwnedFd), Errno> {
    const PATH_SIZE: usize = c"/proc/-2147483648/stat".to_bytes_with_nul().len();
    let mut path: [MaybeUninit<u8>; PATH_SIZE] = [const { MaybeUninit::uninit() }; PATH_SIZE];

    let size: usize = unsafe {
        // The easiest way to fill up a c_char array on the stack in rust
        libc::snprintf(
            path.as_mut_ptr() as *mut libc::c_char,
            PATH_SIZE,
            c"/proc/%d/stat".as_ptr(),
            pid.as_raw() as libc::c_int,
        )
    } as usize + 1; // +1 for the null terminator

    let path = unsafe { path[..size].assume_init_ref() };
    let path = unsafe { CStr::from_bytes_with_nul_unchecked(path) };

    read(path, ReadOptions {
        initial_buffer_size: 512,
        expand_buffer_by: 512,
        expand_buffer_on_partial_read: 16,
    })
}


pub(crate) fn process_is_fd_a_pipe(process: Pid, child_fd: i32) -> bool {
    const PATH_SIZE: usize = c"/proc/-2147483648/fd/-2147483648".to_bytes_with_nul().len();
    let mut path: [MaybeUninit<libc::c_char>; PATH_SIZE] = [const { MaybeUninit::uninit() }; PATH_SIZE];

    let size: usize = unsafe {
        // The easiest way to fill up a c_char array on the stack in rust
        libc::snprintf(
            path.as_mut_ptr() as *mut libc::c_char,
            PATH_SIZE,
            c"/proc/%d/fd/%d".as_ptr(),
            process.as_raw() as libc::c_int,
            child_fd as libc::c_int,
        )
    } as usize + 1;

    let path: &[libc::c_char] = unsafe { path[..size].assume_init_ref() };

    // libc::c_char can be either signed or unsigned, this is the cleanest way to do a literal c_char string I think
    const EXPECTED_PREFIX: [libc::c_char; 5] = [
        'p' as libc::c_char,
        'i' as libc::c_char,
        'p' as libc::c_char,
        'e' as libc::c_char,
        ':' as libc::c_char,
    ];
    let mut prefix: [libc::c_char; EXPECTED_PREFIX.len()] = Default::default();

    let res = eintr_repeat!(Errno::result(unsafe {
        libc::readlink(path.as_ptr(), prefix.as_mut_ptr(), prefix.len())
    }));
    match res {
        Err(_) => false,
        Ok(len) => EXPECTED_PREFIX == &prefix[..len as usize]
    }
}


pub(crate) fn stat_process_exe(pid: Pid) -> nix::Result<FileStat> {
    const PATH_SIZE: usize = c"/proc/-2147483648/exe".to_bytes_with_nul().len();
    let mut path: [MaybeUninit<u8>; PATH_SIZE] = [const { MaybeUninit::uninit() }; PATH_SIZE];

    let size: usize = unsafe {
        // The easiest way to fill up a c_char array on the stack in rust
        libc::snprintf(
            path.as_mut_ptr() as *mut libc::c_char,
            PATH_SIZE,
            c"/proc/%d/exe".as_ptr(),
            pid.as_raw() as libc::c_int,
        )
    } as usize + 1; // +1 for the null terminator

    let path = unsafe { path[..size].assume_init_ref() };
    let path = unsafe { CStr::from_bytes_with_nul_unchecked(path) };

    stat(path)
}

