use crate::{TERMINATION_SIGNAL_CAUGHT, coroutines::CoroutineState, take_over_process, tracee::Tracee, unixutils, args};
use WaitResult::{GotTerminationSignal, Result, WaitpidErr};
use nix::{
    fcntl::AtFlags,
    sys::{ptrace, signal, stat::fstatat, wait::WaitStatus, signal::Signal},
};
use std::{
    collections::HashMap,
    os::fd::{AsRawFd, BorrowedFd},
    path::PathBuf,
    sync::atomic::Ordering,
};
use std::mem::MaybeUninit;

#[derive(Debug)]
pub(crate) enum Event {
    NewChild { parent: nix::unistd::Pid, child: nix::unistd::Pid },
    Exec { rusage: libc::rusage, pid: nix::unistd::Pid, _former_thread_id: nix::unistd::Pid, args: Vec<u8> },
    NormalExit { rusage: libc::rusage, pid: nix::unistd::Pid, exit_code: i64 },
    KilledBySignal { rusage: libc::rusage, pid: nix::unistd::Pid, signal: Signal, generated_core_dump: bool },
}

fn setup_ptrace_for_child(child: nix::unistd::Pid) {
    // todo: if this fails, then either:
    // - the process has received a SIGSTOP already but it wasn't from us  => don't care about this?
    //   there should be a second sigstop invoked from raise() anyway
    // - the process is dead already (e.g. from a SIGKILL)
    //   alsoo shouldn't care I think? or hmm we might not get the notification then
    // shouldn't be a hard crash in either situation
    // - if it's dead then mark it as dead
    ptrace::setoptions(
        child,
        ptrace::Options::PTRACE_O_TRACESYSGOOD
        | ptrace::Options::PTRACE_O_TRACEEXEC
        | ptrace::Options::PTRACE_O_TRACEFORK
        | ptrace::Options::PTRACE_O_TRACEVFORK // do we care about vfork vs vforkdone?
        | ptrace::Options::PTRACE_O_TRACECLONE, // can be useful to track which PIDs are threads of a process
    )
    .ok(); // TODO: ignoring errors (if process hasn't stopped because of us), but is that right?
    // if this fails then continue the process and buffer the signal (...)
}

enum WaitResult {
    Result(WaitStatus),
    WaitpidErr(nix::errno::Errno),
    GotTerminationSignal(),
}

fn waitpid_or_signal(rusage: &mut libc::rusage) -> WaitResult {
    loop {
        if TERMINATION_SIGNAL_CAUGHT.swap(false, Ordering::SeqCst) {
            return GotTerminationSignal();
        }
        /*
         * there is technically a rare race right here, if SIGTERM is received after the above compare and before
         * waitpid is called waitpid won't return with an EINTR immediately.
         *
         * Fixing this would require calling sigprocmask before and after wait4, which would make the program
         * use nearly twice as many syscalls for tracing.
         *
         * the consequence of the race shouldn't be too bad though, we'll just know we're signalled a little bit
         * later (when waitpid receives anything else) - so it's best to keep it
         */

        // use __WALL to wait for all child threads, not only thread group leaders ("processes")
        match unixutils::wait4(None, Some(nix::sys::wait::WaitPidFlag::__WALL), rusage) {
            Ok(result) => return Result(result),
            Err(nix::errno::Errno::EINTR) => {}
            Err(err) => return WaitpidErr(err),
        }
    }
}

fn is_special_secure_exe_screwed(pid: nix::unistd::Pid, procfs_fd: BorrowedFd) -> bool {
    if args().test_always_detach {
        return true
    }

    let proc_dir = PathBuf::from(pid.to_string());

    // todo: - file capabilities
    //       - check the linux kernel source code - what else can enable AT_SECURE?
    //
    //         (or disable PTRACE_MODE_FSCREDS?? although that should be a separate thing??)

    // fstatat can't fail with EINTR so it doesn't have to be restarted
    match fstatat(Some(procfs_fd.as_raw_fd()), &proc_dir.join("exe"), AtFlags::empty()) {
        Ok(res) => {
            // todo - check gid (only if execute bit is set, mandatory file locking)
            //      - check if we aren't the same user/group (so no secure mode anyway)
            (res.st_mode & libc::S_ISUID) != 0
        }
        Err(_) => false, // ignore for now
    }
}

pub(crate) fn waitpid_loop(_first_child: nix::unistd::Pid, procfs_fd: BorrowedFd) -> Vec<Event> {
    use libc::{PTRACE_EVENT_CLONE, PTRACE_EVENT_EXEC, PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK};
    use nix::{
        sys::signal::Signal::{SIGKILL, SIGSTOP, SIGTRAP},
        sys::wait::WaitStatus::{Stopped, PtraceEvent, PtraceSyscall, Exited, Signaled},
        errno::Errno::ECHILD
    };

    // In this function, many syscalls can be interrupted by EINTR due to how signal handlers are set up
    // Make sure that's handled gracefully.

    let cont = ptrace::cont;
    // let cont = ptrace::syscall;

    let mut events: Vec<Event> = vec![];

    let mut pids_to_kill: Vec<nix::unistd::Pid> = vec![];

    // uses an unnamed type: HashMap<nix::unistd::Pid, {running-coroutine}>
    let mut take_over_process_coroutinies: HashMap<nix::unistd::Pid, _> = HashMap::new();

    // rusage in libc doesn't derive Default, this is probably the cleanest way to handle it
    // also, maybe it would be better to just return rusage from waitpid_or_signal though
    let mut rusage: libc::rusage = unsafe { MaybeUninit::<libc::rusage>::zeroed().assume_init() };

    // todo: handle signal-delivery-stop, "Signal injection and suppression" in the manual
    loop {
        match waitpid_or_signal(&mut rusage) {
            GotTerminationSignal() => {
                // todo: this is for easier killing everything when debugging
                pids_to_kill.iter().for_each(|pid| {
                    signal::kill(pid.clone(), SIGKILL).ok();
                })
            }
            Result(Stopped(child, SIGSTOP)) => {
                setup_ptrace_for_child(child);

                if let Err(_) = cont(child, None) {
                    // todo: buffer the signal or something?
                    signal::kill(child, signal::SIGCONT).ok(); // ignore any errors
                }
            }
            Result(PtraceEvent(child, SIGTRAP, PTRACE_EVENT_EXEC)) => {
                let former_thread_id = ptrace::getevent(child).unwrap_or(-1);

                let child_proc_dir = PathBuf::from(child.to_string());

                // keep the _fd to close it at the end of the function, just after cont
                // (to get to cont faster)
                let (cmdline, _fd) = match unixutils::read_restart_on_eintr_delay_close(Some(procfs_fd), &child_proc_dir.join("cmdline")) {
                    Ok((cmdline, fd)) => (cmdline, Some(fd)),
                    Err(_) => (vec![b'?'], None), // ignore errors - process could have just died.
                };

                if is_special_secure_exe_screwed(child, procfs_fd) {
                    // stop at the next syscall. We'll hijack the process and set it up to reexec and detach
                    ptrace::syscall(child, None).ok();
                } else {
                    cont(child, None).ok(); // ignore errors - the child could have died
                }

                events.push(Event::Exec {
                    rusage,
                    _former_thread_id: nix::unistd::Pid::from_raw(former_thread_id as libc::pid_t),
                    pid: child,
                    args: cmdline,
                });
            }

            Result(PtraceSyscall(child)) => {
                let coroutine = take_over_process_coroutinies
                    .entry(child)
                    .or_insert_with(|| take_over_process::take_over_process_syscall(Tracee::from(child), procfs_fd));
                let _ = match coroutine.next() {
                    Some(CoroutineState::Complete(true)) => ptrace::detach(child, None),
                    Some(CoroutineState::Complete(false)) => cont(child, None),
                    // There's still syscalls to inject:
                    Some(CoroutineState::Yielded(())) => ptrace::syscall(child, None),
                    None => cont(child, None),
                };
            }

            Result(PtraceEvent(child, SIGTRAP, PTRACE_EVENT_CLONE | PTRACE_EVENT_FORK | PTRACE_EVENT_VFORK)) => {
                let new_thread_id = ptrace::getevent(child);
                cont(child, None).ok(); // ignore errors - the child could have died

                // Ignore getevent failing - the child was most likely SIGKILLed
                if let Ok(thread_id) = new_thread_id {
                    pids_to_kill.push(nix::unistd::Pid::from_raw(thread_id as libc::pid_t));

                    events.push(Event::NewChild {
                        child: nix::unistd::Pid::from_raw(thread_id as libc::pid_t),
                        parent: child,
                    });
                }
            }
            // a process exited normally
            Result(Exited(pid, exit_code)) => {
                events.push(Event::NormalExit {
                    rusage,
                    pid,
                    exit_code: exit_code as i64,
                });
            }
            // a process exited by being killed by a signal
            Result(Signaled(pid, signal, generated_core_dump)) => {
                events.push(Event::KilledBySignal {
                    rusage,
                    pid,
                    signal,
                    generated_core_dump,
                });
            }

            Result(Stopped(child, signal)) => {
                // println!("our child ({child}) stopped because of {signal:?}, continuing with ptrace");
                // todo: could this fail if ptrace_setoptions hasn't been called yet?
                cont(child, Some(signal)).unwrap();
            }

            Result(result) => {
                println!("waitpid() unhandled result: {result:?}");
            }
            WaitpidErr(ECHILD) => {
                // println!("waitpid(): no longer have any children, nice");
                break;
            }
            WaitpidErr(e) => {
                println!("waitpid() unhandled error: {e:?}");
                break;
            }
        }
    }
    events
}
