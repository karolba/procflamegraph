use nix::errno::Errno;
use nix::sys::wait::{WaitPidFlag, WaitStatus};
use nix::sys::wait::WaitStatus::StillAlive;
use nix::unistd::Pid;

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
