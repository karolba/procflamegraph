use std::ffi::c_void;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::Path;
use libc::c_int;
use nix::errno::Errno;
use nix::sys::wait::{WaitPidFlag, WaitStatus};
use nix::sys::wait::WaitStatus::StillAlive;
use nix::unistd::Pid;

fn read_to_maybe_uninit(fd: BorrowedFd, buf: &mut [std::mem::MaybeUninit<u8>]) -> nix::Result<usize> {
    use std::os::fd::AsRawFd;
    let fd = fd.as_raw_fd();
    let len = buf.len() as libc::size_t;
    let buf = buf.as_mut_ptr() as *mut c_void;
    Errno::result(unsafe { libc::read(fd, buf, len) }).map(|r| r as usize)
}

// Like standard fs::read but restarts on EINTR (which we need enabled for waitpid cancellation)
// an alternative would be to unblock SIGINT and SIGTERM only when waitpid is called, but that
// would generate about twice as many syscalls
//
// a small optimisation: returns the OwnedFd that close()s the /proc/*/cmdline fd
// since the latency to PTRACE_CONT is what matters the most to us, letting our tracees continue
// This really could be a better designed api though, maybe take a closure and close() after the closure?
pub(crate) fn read_restart_on_eintr_delay_close(dirfd: BorrowedFd, path: &Path) -> Result<(Vec<u8>, OwnedFd), std::io::Error> {
    use nix::fcntl::OFlag;
    use std::os::fd::AsFd;

    let fd: OwnedFd = loop {
        match nix::fcntl::openat(dirfd, path, OFlag::O_RDONLY | OFlag::O_CLOEXEC, nix::sys::stat::Mode::empty()) {
            Ok(fd) => break fd,
            Err(Errno::EINTR) => (),
            Err(err) => Err(err)?,
        };
    };

    // small initial buffer for small files
    let mut data: Vec<u8> = Vec::with_capacity(64);

    loop {
        match read_to_maybe_uninit(fd.as_fd(), data.spare_capacity_mut()) {
            Ok(0) => break,
            Ok(num) => {
                let read_was_exact = num == data.capacity();
                unsafe { data.set_len(data.len() + num) }
                data.reserve(if read_was_exact { 2048 } else { 16 });
            }
            Err(Errno::EINTR) => (),
            Err(err) => Err(err)?,
        };
    }

    data.shrink_to_fit();
    Ok((data, fd))
}

// same as read_restart_on_eintr_delay_close but don't delay closing
pub(crate) fn read_restart_on_eintr(dirfd: BorrowedFd, path: &Path) -> Result<Vec<u8>, std::io::Error> {
    match read_restart_on_eintr_delay_close(dirfd, path) {
        Ok((vec, _fd)) => Ok(vec),
        Err(err) => Err(err),
    }
}

pub(crate) fn wait4<P: Into<Option<Pid>>>(
    pid: P,
    options: Option<WaitPidFlag>,
    rusage: &mut libc::rusage
) -> nix::Result<WaitStatus> {
    let mut status: i32 = 0;

    let pid_arg = pid.into().unwrap_or_else(|| Pid::from_raw(-1)).as_raw();
    let option_bits = match options {
        Some(bits) => bits.bits(),
        None => 0,
    };

    let res = Errno::result(unsafe {
        libc::wait4(
            pid_arg,
            &mut status as *mut c_int,
            option_bits,
            rusage
        )
    })?;

    match res {
        0 => Ok(StillAlive),
        res => WaitStatus::from_raw(Pid::from_raw(res), status),
    }
}
