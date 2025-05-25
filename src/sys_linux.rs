use std::cmp;
use std::ffi::{c_void, CStr};
use std::fmt::Debug;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::{LazyLock, OnceLock};
use libc::{AT_FDCWD, O_CLOEXEC, O_DIRECTORY, O_PATH};
use nix::errno::Errno;
use nix::fcntl::{open, AtFlags};
use nix::sys::epoll::{Epoll, EpollEvent};
use nix::sys::signal::SigSet;
use nix::sys::stat::{fstatat, stat, FileStat, Mode};
use nix::sys::utsname::uname;
use nix::sys::wait::{WaitPidFlag, WaitStatus};
use nix::sys::wait::WaitStatus::StillAlive;
use nix::unistd::Pid;
use nix::fcntl::OFlag;
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicBool, Ordering};
use crate::errors::error_out;


macro_rules! eintr_repeat {
    ($e:expr) => {
        loop {
            break match $e {
                Err(nix::errno::Errno::EINTR) => continue,
                result => result,
            }
        }
    }
}
pub(crate) use eintr_repeat;
//
// // Use a RawFd instead of an OwnedFd cause I don't actually care about closing the procfs-referring
// // file descriptor - it will close itself when the program exits
// static PROCFS: LazyLock<RawFd> = LazyLock::new(|| {
//     eintr_repeat!(Errno::result(unsafe {
//         libc::openat(AT_FDCWD, c"/proc".as_ptr(), O_PATH | O_DIRECTORY | O_CLOEXEC, 0)
//     })).unwrap_or_else(|err| error_out!("Can't access /proc: {}", err))
// });
//


// epoll_pwait (missing from the nix crate) to ignore lots of EINTRs
pub(crate) fn epoll_wait(epoll: &Epoll, events: &mut [EpollEvent]) -> usize {
    const NO_TIMEOUT: libc::c_int = -1;

    let ignore_all_signals = SigSet::all();
    eintr_repeat!(Errno::result(unsafe { libc::epoll_pwait(
        epoll.0.as_raw_fd(),
        events.as_mut_ptr().cast(),
        events.len() as libc::c_int,
        NO_TIMEOUT,
        ignore_all_signals.as_ref(),
    ) }))
        .map(|r| r as usize)
        .unwrap_or_else(|err| error_out!("Couldn't epoll_wait: {}", err))
}

pub(crate) fn kernel_major_minor() -> Option<(u32, u32)> {
    let uname = uname().ok()?;
    let release = uname.release().to_string_lossy();

    let major_length = release.find(|c| c == '.')?;
    let minor_length = release[major_length+1..].find(|c| c == '.')?;

    let major = str::parse::<u32>(&release[0..major_length]).ok()?;
    let minor = str::parse::<u32>(&release[major_length+1..major_length+1+minor_length]).ok()?;

    Some((major, minor))
}

// missing from both libc and the nix crate
pub(crate) fn pidfd_open(pid: libc::pid_t, flags: libc::c_uint) -> Result<OwnedFd, Errno> {
    Errno::result(unsafe {
        libc::syscall(libc::SYS_pidfd_open, pid, flags)
    }).map(|fd| unsafe {
        OwnedFd::from_raw_fd(fd as RawFd)
    })
}

// missing from both libc and the nix crate
pub(crate) fn pidfd_getfd(pidfd: BorrowedFd, targetfd: libc::c_int, flags: libc::c_uint) -> Result<OwnedFd, Errno> {
    Errno::result(unsafe {
        libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd() as libc::c_int, targetfd, flags)
    }).map(|fd| unsafe {
        OwnedFd::from_raw_fd(fd as RawFd)
    })
}

// a version of wait that also fetches rusage, missing from the nix crate
pub(crate) fn wait4(pid: Option<Pid>, options: Option<WaitPidFlag>, rusage: &mut libc::rusage) -> Result<WaitStatus, Errno> {
    let mut status: i32 = 0;

    let pid_arg = pid.unwrap_or_else(|| Pid::from_raw(-1)).as_raw();
    let option_bits = match options {
        Some(bits) => bits.bits(),
        None => 0,
    };

    let res = Errno::result(unsafe {
        libc::wait4(
            pid_arg,
            &mut status as *mut libc::c_int,
            option_bits,
            rusage
        )
    })?;

    match res {
        0 => Ok(StillAlive),
        res => WaitStatus::from_raw(Pid::from_raw(res), status),
    }
}

pub(crate) fn is_fd_a_pipe(process: Pid, child_fd: i32) -> bool {
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

pub(crate) fn read_to_maybe_uninit(fd: BorrowedFd, buf: &mut [MaybeUninit<u8>]) -> Result<usize, Errno> {
    let fd = fd.as_raw_fd();
    let len = buf.len() as libc::size_t;
    let buf = buf.as_mut_ptr() as *mut c_void;
    Errno::result(unsafe {
        libc::read(fd, buf, len)
    }).map(|r| r as usize)
}



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

// // same as open_read_restart_on_eintr_delay_close but don't delay closing
// fn read_restart_on_eintr(dirfd: BorrowedFd, path: &Path) -> Result<Vec<u8>, std::io::Error> {
//     match read(path) {
//         Ok((vec, _fd)) => Ok(vec),
//         Err(err) => Err(err),
//     }
// }

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

fn close_range(first: RawFd, last: RawFd, flags: Option<libc::c_int>) -> nix::Result<()> {
    Errno::result(unsafe {
        libc::syscall(
            libc::SYS_close_range,
            first as libc::c_uint,
            last as libc::c_uint,
            flags.unwrap_or(0) as libc::c_int
        )
    })?;
    Ok(())
}

static CLOSE_RANGE_SYSCALL_EXISTS: AtomicBool = AtomicBool::new(true);

// Try to close two file descriptions using just one syscall if possible
// falling back to closing them sequentially if not
pub(crate) fn close_two(fd1: OwnedFd, fd2: OwnedFd) {
    if !CLOSE_RANGE_SYSCALL_EXISTS.load(Ordering::Relaxed) {
        return
    }

    let distance_between_fds = (fd1.as_raw_fd() - fd2.as_raw_fd()).abs();
    if distance_between_fds != 1 {
        return
    }

    let (first, second) = if fd1.as_raw_fd() < fd2.as_raw_fd() { (fd1, fd2) } else { (fd2, fd1) };

    match close_range(first.as_raw_fd(), second.as_raw_fd(), None) {
        Ok(()) => {
            std::mem::forget(first);
            std::mem::forget(second);
        }
        Err(Errno::ENOSYS) => {
            CLOSE_RANGE_SYSCALL_EXISTS.store(false, Ordering::Relaxed);
        }
        Err(_) => {}
    }
}