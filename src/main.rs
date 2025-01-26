use libc::{c_int, size_t};
use nix::errno::Errno;
use nix::fcntl;
use nix::fcntl::OFlag;
use nix::libc;
use nix::sys::signal::{kill, SaFlags, SigAction, SigHandler, SigSet};
use nix::sys::stat::Mode;
use nix::sys::{ptrace, signal, wait};
use nix::unistd;
use nix::unistd::Pid;
use ptrace::Options;
use signal::Signal;
use std::collections::HashMap;
use std::env::args_os;
use std::ffi::{c_void, CString};
use std::io::Read;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use unistd::ForkResult;
use wait::{WaitPidFlag, WaitStatus};

// TODO: from ptrace(2):
// - Group-stop notifications are sent to the tracer, but not to real parent. Last confirmed on 2.6.38.6.

static TERMINATION_SIGNAL_CAUGHT: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
enum Event {
    NewChild{parent: Pid, child: Pid},
    Exec{pid: Pid, _former_thread_id: Pid, args: Vec<u8>},
    Exit{pid: Pid, exit_code: i64},
}

#[derive(Debug)]
struct Process {
    pid: Pid,
    children: Vec<Pid>,
    execvs: Vec<Vec<String>>,
    exit_code: Option<i64>,
}
impl Process {
    fn new(pid: Pid) -> Process {
        Process {
            pid: pid,
            children: vec![],
            execvs: vec![],
            exit_code: None,
        }
    }
    fn print_tree(&self, indent: usize, others: &HashMap<Pid, Process>) {
        print!("{:indent$}- ({}) ", "", self.pid);
        for execv in self.execvs.iter() {
            print!("{execv:?} -> ");
        };
        if self.execvs.len() == 0 {
            print!("-> ")
        }
        println!("{}", self.exit_code.unwrap_or(-1));

        for child in self.children.iter() {
            if let Some(child_process) = others.get(child) {
                child_process.print_tree(indent + 2, others);
            }
        }
    }
}


fn run_child() {
    ptrace::traceme().expect("ptrace_traceme failed");

    // Stop ourselves so our tracer parent can set up PTRACE_SETOPTIONS on us
    signal::raise(Signal::SIGSTOP).expect("raise(SIGSTOP) failed");

    let args : Vec<CString> = args_os()
        .skip(1)
        .map(|osstr| CString::new(osstr.as_bytes()).unwrap())
        .collect();
    unistd::execvp(args.get(0).expect("need to pass at least one arg"), &args).expect("execve failed");
}

fn setup_ptrace_for_child(child: unistd::Pid) {
    // todo: if this fails, then either:
    // - the process has received a SIGSTOP already but it wasn't from us  => don't care about this?
    //   there should be a second sigstop invoked from raise() anyway
    // - the process is dead already (e.g. from a SIGKILL)
    //   alsoo shouldn't care I think? or hmm we might not get the notification then
    // shouldn't be a hard crash in either situation
    // - if it's dead then mark it as dead
    ptrace::setoptions(child,
        Options::PTRACE_O_TRACESYSGOOD
        | Options::PTRACE_O_TRACEEXEC
        | Options::PTRACE_O_TRACEEXIT
        | Options::PTRACE_O_TRACEFORK
        | Options::PTRACE_O_TRACEVFORK // do we care about vfork vs vforkdone?
        | Options::PTRACE_O_TRACECLONE // can be useful to track which PIDs are threads of a process
    ).ok(); // TODO: ignoring errors (if process hasn't stopped because of us), but is that right?
    // if this fails then continue the process and buffer the signal (...)
}

enum WaitResult {
    Result(WaitStatus),
    WaitpidErr(Errno),
    GotTerminationSignal()
}

fn waitpid_or_signal() -> WaitResult {
    if TERMINATION_SIGNAL_CAUGHT.swap(false, Ordering::SeqCst) {
        return WaitResult::GotTerminationSignal()
    }
    // there is technically a race here, if SIGTERM is received after the above compare and before
    // waitpid is called, then waitpid won't return with an EINTR immediately
    // fixing this is kind of impossible though with how the api works
    // the consequence of the race shouldn't be too bad though, we'll just know we're signalled
    // a little bit later (when waitpid receives anything)
    loop {
        // `strace` uses __WALL, is there a reason?
        // the kernel suggests to use __WALL as well somewhere, why not then
        match wait::waitpid(None, Some(WaitPidFlag::__WALL)) {
            Ok(result) => {
                return WaitResult::Result(result)
            }
            Err(Errno::EINTR) => {
                if TERMINATION_SIGNAL_CAUGHT.swap(false, Ordering::SeqCst) {
                    return WaitResult::GotTerminationSignal()
                }
            }
            Err(err) => {
                return WaitResult::WaitpidErr(err)
            }
        }
    }
}

pub fn openat_to_ownedfd<P: ?Sized + nix::NixPath>(
    dirfd: Option<RawFd>,
    path: &P,
    oflag: OFlag,
    mode: Mode,
) -> nix::Result<OwnedFd> {
    fcntl::openat(dirfd, path, oflag, mode).map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
}

fn read_to_maybe_uninit(fd: RawFd, buf: &mut [MaybeUninit<u8>]) -> nix::Result<usize> {
    let len = buf.len() as size_t;
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
fn read_restart_on_eintr(dirfd: Option<BorrowedFd>, path: &Path) -> (Option<Vec<u8>>, Option<OwnedFd>) {
    let fd: OwnedFd = loop {
        match openat_to_ownedfd(dirfd.map(|d| d.as_raw_fd()), path, OFlag::O_RDONLY | OFlag::O_CLOEXEC, Mode::empty()) {
            Ok(fd) => break fd,
            Err(Errno::EINTR) => (),
            Err(_) => return (None, None)
        };
    };

    // small initial buffer for small command lines
    let mut data : Vec<u8> = Vec::with_capacity(64);

    loop {
        match read_to_maybe_uninit(fd.as_raw_fd(), data.spare_capacity_mut()) {
            Ok(0) => break,
            Ok(num) => {
                let read_was_exact = num == data.capacity();
                unsafe { data.set_len(data.len() + num) }
                data.reserve(if read_was_exact { 2048 } else { 16 });
            },
            Err(Errno::EINTR) => (),
            Err(_) => return (None, Some(fd))
        };
    }

    data.shrink_to_fit();
    (Some(data), Some(fd))
}

// In this function, many syscalls can be interrupted by EINTR due to how signal handlers are set up
// Make sure that's handled gracefully
fn waitpid_loop(_first_child: Pid, proc_fd: BorrowedFd) -> Vec<Event> {
    let mut events : Vec<Event> = vec![];

    // todo: handle signal-delivery-stop, "Signal injection and suppression" in the manual
    loop {
        match waitpid_or_signal() {
            WaitResult::GotTerminationSignal() => {
                // hmmm what do we do here actually
                // for sure don't exit??? at least until children exit
                // test if they also receive signals or if ptrace is weird

                // maybe it's enough to ignore sigint and sigterm ????
                eprintln!("Got a signal yeah");
            }
            WaitResult::Result(WaitStatus::Stopped(child, Signal::SIGSTOP)) => {
                // set up a new descendant
                // println!("Setting up ptrace for {child:?}");
                setup_ptrace_for_child(child);

                if let Err(_) = ptrace::cont(child, None) {
                    // todo: buffer the signal or something?
                    kill(child, signal::SIGCONT).ok(); // ignore any errors
                }
            }
            WaitResult::Result(WaitStatus::PtraceEvent(child, Signal::SIGTRAP, libc::PTRACE_EVENT_EXEC)) => {
                // todo: could those ever fail? maybe when the child suddenly dies? should handle that
                let former_thread_id = ptrace::getevent(child).unwrap_or(-1);

                let cmdline_path = PathBuf::from(child.to_string()).join("cmdline");
                let (command_line, _fd) = read_restart_on_eintr(Some(proc_fd), &cmdline_path);

                // dirty code for quick testing of suid binaries
                // let found_sudo = String::from_utf8_lossy((&command_line).clone().unwrap().as_slice()).contains("sudo");
                // if found_sudo {
                //     eprintln!("found sudo yay");
                //     ptrace::detach(child, None).expect("Could not detach?");
                // }

                events.push(Event::Exec {
                    _former_thread_id: Pid::from_raw(former_thread_id as libc::pid_t),
                    pid: child,
                    args: command_line.unwrap_or_else(|| vec![])
                });

                // if ! found_sudo {
                ptrace::cont(child, None).ok(); // ignore errors - the child could have died
                // }

            }
            WaitResult::Result(WaitStatus::PtraceEvent(child, Signal::SIGTRAP, libc::PTRACE_EVENT_CLONE
                                                                             | libc::PTRACE_EVENT_FORK
                                                                             | libc::PTRACE_EVENT_VFORK)) => {
                // Ignore getevent failing - the child was most likely SIGKILLed
                if let Ok(new_thread_id) = ptrace::getevent(child) {
                    events.push(Event::NewChild {
                        child: Pid::from_raw(new_thread_id as libc::pid_t),
                        parent: child,
                    });
                }

                ptrace::cont(child, None).ok(); // ignore errors - the child could have died
            }
            WaitResult::Result(WaitStatus::PtraceEvent(child, Signal::SIGTRAP, libc::PTRACE_EVENT_EXIT)) => {
                let exit_code = ptrace::getevent(child).unwrap_or(-1);
                events.push(Event::Exit {
                    exit_code: exit_code as i64,
                    pid: child,
                });
                ptrace::cont(child, None).ok(); // ignore errors - the child could have died
            }
            WaitResult::Result(WaitStatus::Exited(child, exit_code)) => {
                // hm which one do we trust more? this one or PTRACE_EVENT_EXIT?
                // or the one that came last?
                events.push(Event::Exit {
                    exit_code: exit_code as i64,
                    pid: child,
                });
                // println!("our child ({child}) exited with {exit_code}");
            }
            WaitResult::Result(WaitStatus::Stopped(child, signal)) => {
                // println!("our child ({child}) stopped because of {signal:?}, continuing with ptrace");
                // todo: could this fail if ptrace_setoptions hasn't been called yet?
                ptrace::cont(child, Some(signal)).unwrap();
            }
            // process was killed by a signal
            // WaitResult::Result(WaitStatus::Signaled(pid, signal, generated_core_dump)) => {
                // propagate this somewhere?
                // check what strace does
                // can trigger this by trying to trace something inside a traced process (SIGKILL)
                // println!("waitpid() unhandled result: {result:?}");
            // }
            WaitResult::Result(result) => {
                println!("waitpid() unhandled result: {result:?}");
            }
            WaitResult::WaitpidErr(Errno::ECHILD) => {
                // println!("waitpid(): no longer have any children, nice");
                break;
            }
            WaitResult::WaitpidErr(e) => {
                println!("waitpid() unhandled error: {e:?}");
                break;
            }
        }
    }
    events
}

fn run_in_fork<F : FnOnce() -> ()> (run_child: F) -> Pid {
    // safety: can really only call this function when no more than 1 thread is yet to run
    // libc::clone(cb, 0, SIGCHLD | CLONE_PTRACE, );
    match unsafe { unistd::fork() }.expect("fork() failed") {
        ForkResult::Parent { child } => child,
        ForkResult::Child => {
            run_child();
            exit(1);
        }
    }
}

fn events_to_process_tree(events: Vec<Event>) -> HashMap<Pid, Process> {
    let mut processes: HashMap<Pid, Process> = HashMap::new();

    for event in events {
        match event {
            Event::NewChild { child, parent } => {
                let parent = processes.entry(parent).or_insert_with(|| Process::new(parent));
                parent.children.push(child);
                processes.entry(child).or_insert_with(|| Process::new(child));
            }
            Event::Exit { pid, exit_code } => {
                let process = processes.entry(pid).or_insert_with(|| Process::new(pid));
                process.exit_code = Some(exit_code);
            }
            Event::Exec { pid, _former_thread_id: _, args } => {
                // todo: former_thread_id, should I do anything with it? doesn't seem like I should?
                let split = args.split(|x| *x == 0u8);
                let mut args: Vec<String> = split.map(|arg| String::from_utf8_lossy(arg).to_string()).collect();
                if let Some(last) = args.last() {
                    if last.is_empty() {
                        args.pop(); // get rid of the last entry (we split by '\0' but it's really '\0'-ended chunks)
                    }
                };
                let process = processes.entry(pid).or_insert_with(|| Process::new(pid));
                process.execvs.push(args);
            }
        }
    }

    processes
}

extern "C" fn sigaction_handler(_signal: c_int) {
    // Note: this is a signal handler - doing anything that could allocate memory or call
    // a signal-unsafe libc function is undefined behaviour
    TERMINATION_SIGNAL_CAUGHT.store(true, Ordering::SeqCst);
}

fn setup_termination_signal_handler() {
    let sigaction = SigAction::new(
        SigHandler::Handler(sigaction_handler),

        // Note: Intentionally don't specify SA_RESTART, which means many syscalls
        //       will fail with EINTR. This is intentional so waitpid() can be interrupted
        //       in waitpid_loop(), but it additionally means every other action in waitpid_loop()
        //       also has to contend with being interrupted by an EINTR.
        //       This is also why we turn off the sigaction handler immediately after waitpid_loop,
        //       to not have to deal EINTRs.
        // TODO: If we ever launch any other thread that needs to run during waitpid_loop() then
        //       pthread_setsigmask should be used so only the waitpid_loop() thread
        //       receives and is interrupted by signals without SA_RESTART
        SaFlags::empty(),

        // Signals blocked during the execution of the sigaction_handler
        signal::SIGTERM | signal::SIGINT
    );
    unsafe { signal::sigaction(signal::SIGTERM, &sigaction) }.expect("Couldn't set up a SIGTERM handler");
    unsafe { signal::sigaction(signal::SIGINT, &sigaction) }.expect("Couldn't set up a SIGINT handler");
}

fn ignore_termination_signals() {
    let ignore_sigaction = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
    unsafe { signal::sigaction(signal::SIGTERM, &ignore_sigaction) }.expect("Couldn't reset the SIGTERM handler");
    unsafe { signal::sigaction(signal::SIGINT, &ignore_sigaction) }.expect("Couldn't reset the SIGINT handler");
}

fn main() {
    // do this before setting up signal handlers to not have to worry about EINTR
    // and before run_in_fork to fail early
    let proc_dir_fd =
        openat_to_ownedfd(None, "/proc", OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC, Mode::empty())
        .expect("Don't have access to /proc");

    // safety: only fork like that at the beginning when no other threads are yet running
    let child_pid = run_in_fork(run_child);

    setup_termination_signal_handler();
    let events = waitpid_loop(child_pid, proc_dir_fd.as_fd());
    // if we've got here we'll exit shortly anyway so ignore those instead of using SigDfl
    ignore_termination_signals();

    let processes = events_to_process_tree(events);
    match processes.get(&child_pid) {
        Some(root) => root.print_tree(0, &processes),
        None => eprintln!("Our only child is not in children (??)"),
    }
}

