// Basic operations on file descriptors missing from the nix crate or libc

use crate::errors::error_out;
use nix::errno::Errno;
use std::{ffi::c_void,
          mem::MaybeUninit,
          os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
          sync::atomic::{AtomicBool, Ordering}};

pub(crate) fn read_to_maybe_uninit(fd: BorrowedFd, buf: &mut [MaybeUninit<u8>]) -> Result<usize, Errno> {
    let fd = fd.as_raw_fd();
    let len = buf.len() as libc::size_t;
    let buf = buf.as_mut_ptr() as *mut c_void;
    Errno::result(unsafe { libc::read(fd, buf, len) }).map(|r| r as usize)
}

// missing from both libc and the nix crate
pub(crate) fn pidfd_open(pid: libc::pid_t, flags: libc::c_uint) -> Result<OwnedFd, Errno> {
    Errno::result(unsafe { libc::syscall(libc::SYS_pidfd_open, pid, flags) }).map(|fd| unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

// missing from both libc and the nix crate
pub(crate) fn pidfd_getfd(pidfd: BorrowedFd, targetfd: libc::c_int, flags: libc::c_uint) -> Result<OwnedFd, Errno> {
    Errno::result(unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd() as libc::c_int, targetfd, flags) })
        .map(|fd| unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

fn close_range(first: RawFd, last: RawFd, flags: Option<libc::c_int>) -> nix::Result<()> {
    Errno::result(unsafe { libc::syscall(libc::SYS_close_range, first as libc::c_uint, last as libc::c_uint, flags.unwrap_or(0) as libc::c_int) })?;
    Ok(())
}

static CLOSE_RANGE_SYSCALL_EXISTS: AtomicBool = AtomicBool::new(true);

// Try to close two file descriptions using just one syscall if possible
// falling back to closing them sequentially if not
pub(crate) fn close_two(fd1: OwnedFd, fd2: OwnedFd) {
    if !CLOSE_RANGE_SYSCALL_EXISTS.load(Ordering::Relaxed) {
        return;
    }

    let distance_between_fds = (fd1.as_raw_fd() - fd2.as_raw_fd()).abs();
    if distance_between_fds != 1 {
        return;
    }

    let (first, second) = if fd1.as_raw_fd() < fd2.as_raw_fd() {
        (fd1, fd2)
    } else {
        (fd2, fd1)
    };

    match close_range(first.as_raw_fd(), second.as_raw_fd(), None) {
        Err(Errno::ENOSYS) => {
            CLOSE_RANGE_SYSCALL_EXISTS.store(false, Ordering::Relaxed);
        }
        Err(Errno::EBADF) => {
            error_out!("Couldn't close file descriptors {} and {}: EBADF", first.as_raw_fd(), second.as_raw_fd());
        }
        Ok(()) | Err(_) => {
            // we have to assume all other errors mean the fds are already closed
            std::mem::forget(first);
            std::mem::forget(second);
        }
    }
}
