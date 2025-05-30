use std::os::fd::AsRawFd;
use nix::errno::Errno;
use nix::sys::epoll::{Epoll, EpollEvent};
use nix::sys::signal::SigSet;
use crate::errors::error_out;
use crate::sys_linux::macros::eintr_repeat;

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
