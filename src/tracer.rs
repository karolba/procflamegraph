use crate::{TERMINATION_SIGNAL_CAUGHT, args,
            coroutines::CoroutineState,
            errors::log_warn,
            output_peeker::OutputPeeker,
            sys_linux::{proc::{process_cmdline, process_is_fd_a_pipe, stat_process_exe},
                        ptrace::Tracee,
                        wait::wait4},
            take_over_process::{self, TakeOverActions}};
use WaitResult::{GotTerminationSignal, Result, WaitpidErr};
use libc::{PTRACE_EVENT_CLONE, PTRACE_EVENT_EXEC, PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK};
use nix::{errno::Errno::ECHILD,
          sys::{ptrace, signal,
                signal::{Signal,
                         Signal::{SIGSTOP, SIGTRAP}},
                wait::{WaitStatus,
                       WaitStatus::{Exited, PtraceEvent, PtraceSyscall, Signaled, Stopped}}},
          unistd::Pid};
use std::{collections::HashMap, sync::atomic::Ordering};

#[derive(Debug)]
pub(crate) enum Event {
    NewChild {
        parent: nix::unistd::Pid,
        child:  nix::unistd::Pid,
    },
    Exec {
        rusage: libc::rusage,
        pid:    nix::unistd::Pid,
        args:   Vec<u8>,
    },
    NormalExit {
        rusage:    libc::rusage,
        pid:       nix::unistd::Pid,
        exit_code: i64,
    },
    KilledBySignal {
        rusage:              libc::rusage,
        pid:                 nix::unistd::Pid,
        signal:              Signal,
        generated_core_dump: bool,
    },
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
                       | ptrace::Options::PTRACE_O_TRACECLONE // not tracing threads makes us miss some processes
                       | ptrace::Options::PTRACE_O_TRACEFORK
                       | ptrace::Options::PTRACE_O_TRACEVFORK // do we care about vfork vs vforkdone?
                       | ptrace::Options::PTRACE_O_TRACEEXEC,
    )
    .ok();
    // TODO: ignoring errors (if process hasn't stopped because of us), but is that right?
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
        match wait4(None, Some(nix::sys::wait::WaitPidFlag::__WALL), rusage) {
            Ok(result) => return Result(result),
            Err(nix::errno::Errno::EINTR) => {}
            Err(err) => return WaitpidErr(err),
        }
    }
}

fn is_special_secure_exe_screwed(pid: nix::unistd::Pid) -> bool {
    if args().test_always_detach {
        return true;
    }

    // todo: - file capabilities
    //       - check the linux kernel source code - what else can enable AT_SECURE?
    //
    //         (or disable PTRACE_MODE_FSCREDS?? although that should be a separate thing??)

    // fstatat can't fail with EINTR so it doesn't have to be restarted
    match stat_process_exe(pid) {
        Ok(res) => {
            // todo - check gid (only if execute bit is set, mandatory file locking)
            //      - check if we aren't the same user/group (so no secure mode anyway)
            (res.st_mode & libc::S_ISUID) != 0
        }
        Err(_) => false, // ignore for now
    }
}

pub(crate) fn waitpid_loop(_first_child: nix::unistd::Pid, output_peeker: &OutputPeeker) -> Vec<Event> {
    // In this function, many syscalls can be interrupted by EINTR due to how signal handlers are set up
    // Make sure that's handled gracefully.

    let cont = ptrace::cont;
    // let cont = ptrace::syscall;

    let mut events: Vec<Event> = vec![];

    // uses an unnamed type: HashMap<nix::unistd::Pid, {running-coroutine}>
    let mut take_over_process_coroutines: HashMap<Pid, _> = HashMap::new();

    // rusage in libc doesn't derive Default, this is probably the cleanest way to handle it
    let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };

    // todo: handle signal-delivery-stop, "Signal injection and suppression" in the manual
    loop {
        match waitpid_or_signal(&mut rusage) {
            GotTerminationSignal() => {
                // todo: this is for easier killing everything when debugging
                //pids_to_kill.iter().for_each(|pid| {
                //   signal::kill(pid.clone(), SIGKILL).ok();
                //})
                println!("Got a termination signal, todo handle it")
            }
            Result(Stopped(child, SIGSTOP)) => {
                setup_ptrace_for_child(child);

                if let Err(_) = cont(child, None) {
                    // todo: buffer the signal or something?
                    signal::kill(child, signal::SIGCONT).ok(); // ignore any errors
                }
            }
            Result(PtraceEvent(child, SIGTRAP, PTRACE_EVENT_EXEC)) => {
                // `child` is the PID of the main thread in the process group that does an exec.
                // ptrace::getevent(child) can be used to get the PID of the thread that really
                // invoked execve

                // execing invalidates anything we were doing in take_over_process
                take_over_process_coroutines.remove(&child);

                // keep the _fd to close it at the end of the block, after ptrace::cont or
                // ptrace::syscall (to get to resuming the process execution just a tiny bit faster)
                let (cmdline, _fd) = match process_cmdline(child) {
                    Ok((cmdline, fd)) => (cmdline, Some(fd)),
                    Err(_) => (vec![b'?'], None), // ignore errors - the process could have just died.
                };

                let take_over_actions = TakeOverActions {
                    tracee: Tracee::from(child),
                    output_peeker,
                    do_redirect_stdout: args().capture_stdout && process_is_fd_a_pipe(child, libc::STDOUT_FILENO),
                    do_redirect_stderr: args().capture_stderr && process_is_fd_a_pipe(child, libc::STDERR_FILENO),
                    do_reexec: is_special_secure_exe_screwed(child),
                };

                if take_over_actions.is_any_action_set() {
                    take_over_process_coroutines.insert(child, take_over_actions.take_over_step());

                    // stop at the next syscall. We'll hijack the process and set it up for shenanigans
                    ptrace::syscall(child, None).ok();
                } else {
                    cont(child, None).ok(); // ignore errors - the child could have died
                }

                events.push(Event::Exec { rusage, pid: child, args: cmdline });

                output_peeker.execve_happened(child);
            }

            Result(PtraceSyscall(child)) => {
                match take_over_process_coroutines
                    .get_mut(&child)
                    .and_then(|coroutine| coroutine.next())
                {
                    Some(CoroutineState::Complete(Ok(take_over_process::TakeOverResult::ContinueExecuting()))) => {
                        // Our modifications to the process have been done. Let the child continue
                        // executing normally, without stopping on syscalls.
                        cont(child, None).ok();

                        // The coroutine is over, no longer need it
                        take_over_process_coroutines.remove(&child);
                    }

                    Some(CoroutineState::Complete(Ok(take_over_process::TakeOverResult::ReexecSetupDetach()))) => {
                        // The self-reexec setup dance is done - the process is set up for
                        // reexecuting itself, this time, without being attached to.
                        // Detach to let it continue doing so.
                        ptrace::detach(child, None).ok();

                        // The coroutine is over, no longer need it
                        take_over_process_coroutines.remove(&child);
                    }

                    Some(CoroutineState::Complete(Err(_))) => {
                        // something has failed, we cannot restart
                        //
                        // be mindful - could this also just mean the child died mid our request?
                        // TODO: log the error in verbose mode

                        cont(child, None).ok();

                        // The coroutine is over, no longer need it
                        take_over_process_coroutines.remove(&child);
                    }

                    Some(CoroutineState::Yielded(())) => {
                        // There's still syscalls we have left to inject, continue executing but
                        // stop on the next syscall exit or entry
                        ptrace::syscall(child, None).ok();
                    }

                    None => {
                        log_warn!("Received a syscall-stop for pid {} but didn't request one", child);
                    }
                };
            }

            Result(PtraceEvent(child, SIGTRAP, PTRACE_EVENT_FORK | PTRACE_EVENT_VFORK | PTRACE_EVENT_CLONE)) => {
                let new_thread_id = ptrace::getevent(child);
                cont(child, None).ok(); // ignore errors - the child could have died

                // Ignore getevent failing - the child was most likely SIGKILLed
                if let Ok(thread_id) = new_thread_id {
                    events.push(Event::NewChild {
                        child:  Pid::from_raw(thread_id as libc::pid_t),
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
                output_peeker.thread_died(pid);
                take_over_process_coroutines.remove(&pid);
            }
            // a process exited by being killed by a signal
            Result(Signaled(pid, signal, generated_core_dump)) => {
                events.push(Event::KilledBySignal {
                    rusage,
                    pid,
                    signal,
                    generated_core_dump,
                });
                output_peeker.thread_died(pid);
                take_over_process_coroutines.remove(&pid);
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
