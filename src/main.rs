#![feature(gen_blocks)]

// has macros, needs to go first
mod errors;
mod coroutines;
use errors::error_out;

mod args;
mod ptrace_syscall_info;
mod syscall_list;
mod take_over_process;
mod tracee;
mod tracer;
mod unixutils;

use std::{
    collections::HashMap,
    ffi::{CString, OsString},
    fs::File,
    io::{BufWriter, Write},
    os::fd::AsFd,
    sync::OnceLock,
    sync::atomic::{AtomicBool, Ordering},
    time::SystemTime,
};
// use std::ffi::OsStr;
use nix::sys::signal::Signal;

static ARGS : OnceLock<args::Args> = OnceLock::new();
fn args() -> &'static args::Args {
    ARGS.get().unwrap()
}

//, SIGABRT, SIGALRM, SIGBUS, SIGCHLD, SIGCONT, SIGFPE, SIGHUP, SIGILL, SIGINT, SIGIO, SIGKILL, SIGPIPE, SIGPROF, SIGPWR, SIGQUIT, SIGSEGV, SIGSTKFLT, SIGSTOP, SIGSYS, SIGTERM, SIGTRAP, SIGTSTP, SIGTTIN, SIGTTOU, SIGURG, SIGUSR1, SIGUSR2, SIGVTALRM, SIGWINCH, SIGXCPU, SIGXFSZ};
// TODO: from ptrace(2):
// - Group-stop notifications are sent to the tracer, but not to real parent. Last confirmed on 2.6.38.6.

// TODO:
// https://amann.dev/blog/2024/ptrace_rust/
// "JVM… The JVM requires us to handle SIGSEGV here: It expects to receive a segmentation violation on
//  null dereference to update garbage collected pointers. Interesting…"
// test if that works
//
// not true?? null pointer exceptions work just fine

static TERMINATION_SIGNAL_CAUGHT: AtomicBool = AtomicBool::new(false);


#[derive(Debug)]
enum ExitReason {
    NormalExit { exit_code: i64 },
    // todo: is there a signal type in the nix crate?
    KilledBySignal { signal: Signal, generated_core_dump: bool },
}

#[derive(Debug)]
struct Process {
    pid: nix::unistd::Pid,
    children: Vec<nix::unistd::Pid>,
    execvs: Vec<Vec<String>>,
    exit: Option<ExitReason>,
    #[allow(dead_code)] start_time: Option<SystemTime>,
    #[allow(dead_code)] stop_time: Option<SystemTime>, // todo: use those?
}

impl Process {
    fn new(pid: nix::unistd::Pid) -> Process {
        Process {
            pid,
            children: vec![],
            execvs: vec![],
            exit: None,
            start_time: None,
            stop_time: None,
        }
    }

    fn print_tree(&self, indent: usize, others: &HashMap<nix::unistd::Pid, Process>, out: &mut dyn Write) -> Result<(), std::io::Error> {
        if self.execvs.is_empty() && matches!(self.exit, Some(ExitReason::NormalExit{ exit_code: 0 })) {
            // collapse worker threads that didn't contribute anything and only muddy out the output
            // todo maybe add an option to disable this behaviour (select a cool name first tho)
            for child in self.children.iter() {
                if let Some(child_process) = others.get(child) {
                    child_process.print_tree(indent, others, out)?;
                }
            }
        } else {
            write!(out, "{:indent$}- ", "")?;
            if args().display_pids {
                write!(out, "({}) ", self.pid)?;
            }
            for execv in self.execvs.iter() {
                write!(out, "{execv:?} -> ")?;
            }
            if self.execvs.len() == 0 {
                write!(out, "-> ")?;
            }
            match self.exit {
                Some(ExitReason::NormalExit { exit_code }) => writeln!(out, "{}", exit_code)?,
                Some(ExitReason::KilledBySignal { signal, generated_core_dump: true }) => writeln!(out, "killed by {} (core dumped)", signal.as_str())?,
                Some(ExitReason::KilledBySignal { signal, generated_core_dump: false }) => writeln!(out, "killed by {}", signal.as_str())?,
                None => writeln!(out, "(unknown)")?,
            };

            for child in self.children.iter() {
                if let Some(child_process) = others.get(child) {
                    child_process.print_tree(indent + 2, others, out)?;
                }
            }
        }

        Ok(())
    }
}

fn run_child(command: Vec<OsString>) -> ! {
    use std::os::unix::ffi::OsStrExt;

    nix::sys::ptrace::traceme().expect("call to ptrace(PTRACE_TRACEME) failed");

    // Stop ourselves so our tracer parent can set up PTRACE_SETOPTIONS on us
    nix::sys::signal::raise(Signal::SIGSTOP).expect("raise(SIGSTOP) failed");

    let args: Vec<CString> = command.iter().map(|osstr| CString::new(osstr.as_bytes()).unwrap()).collect();
    // todo: better errors if execve fails
    //       and return with -127 then
    nix::unistd::execvp(args.get(0).expect("need to pass at least one arg"), &args).expect("execve failed");

    unreachable!();
}

fn run_in_fork<F: FnOnce() -> ()>(run_child: F) -> nix::unistd::Pid {
    // safety: can really only call this function when no more than 1 thread is yet to run
    match unsafe { nix::unistd::fork() }.expect("fork() failed") {
        nix::unistd::ForkResult::Parent { child } => child,
        nix::unistd::ForkResult::Child => {
            run_child();
            std::process::exit(1);
        }
    }
}

fn events_to_process_tree(events: Vec<tracer::Event>) -> HashMap<nix::unistd::Pid, Process> {
    use crate::tracer::Event;

    let mut processes: HashMap<nix::unistd::Pid, Process> = HashMap::new();

    for event in events {
        match event {
            Event::NewChild { child, parent } => {
                let parent = processes.entry(parent).or_insert_with(|| Process::new(parent));
                parent.children.push(child);
                processes.entry(child).or_insert_with(|| Process::new(child));
            }
            Event::KilledBySignal { pid, signal, generated_core_dump, rusage: _rusage } => {
                let process = processes.entry(pid).or_insert_with(|| Process::new(pid));
                process.exit = Some(ExitReason::KilledBySignal{ signal, generated_core_dump });
            }
            Event::NormalExit { pid, exit_code, rusage: _rusage } => {
                let process = processes.entry(pid).or_insert_with(|| Process::new(pid));
                process.exit = Some(ExitReason::NormalExit{ exit_code });
            }
            Event::Exec { pid, args, _former_thread_id, rusage: _rusage } => {
                // todo: former_thread_id, should I do anything with it? doesn't seem like I should?
                let mut args: Vec<String> = args.split(|x| *x == 0u8).map(|arg| String::from_utf8_lossy(arg).to_string()).collect();
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

extern "C" fn sigaction_handler(_signal: libc::c_int) {
    // Note: this is a signal handler - doing anything that could allocate memory or call
    // a signal-unsafe libc function is undefined behaviour
    TERMINATION_SIGNAL_CAUGHT.store(true, Ordering::SeqCst);
}

fn setup_termination_signal_handler() {
    use nix::sys::signal;

    let sigaction = signal::SigAction::new(
        signal::SigHandler::Handler(sigaction_handler),
        // Note: Intentionally don't specify SA_RESTART, which means many syscalls
        //       will fail with EINTR. This is intentional so waitpid() can be interrupted
        //       in waitpid_loop(), but it additionally means every other action in waitpid_loop()
        //       also has to contend with being interrupted by an EINTR.
        //       This is also why we turn off the sigaction handler immediately after waitpid_loop,
        //       to not have to deal EINTRs.
        // TODO: If we ever launch any other thread that needs to run during waitpid_loop() then
        //       pthread_setsigmask should be used so only the waitpid_loop() thread
        //       receives and is interrupted by signals without SA_RESTART
        signal::SaFlags::empty(),
        // Signals blocked during the execution of the sigaction_handler
        signal::SIGTERM | signal::SIGINT,
    );

    unsafe { signal::sigaction(signal::SIGTERM, &sigaction) }.expect("Couldn't set up a SIGTERM handler");
    unsafe { signal::sigaction(signal::SIGINT, &sigaction) }.expect("Couldn't set up a SIGINT handler");
}

fn ignore_termination_signals() {
    use nix::sys::signal;

    let ignore_sigaction = signal::SigAction::new(signal::SigHandler::SigIgn, signal::SaFlags::empty(), signal::SigSet::empty());
    unsafe { signal::sigaction(signal::SIGTERM, &ignore_sigaction) }.expect("Couldn't reset the SIGTERM handler");
    unsafe { signal::sigaction(signal::SIGINT, &ignore_sigaction) }.expect("Couldn't reset the SIGINT handler");
}

fn main() -> std::process::ExitCode {
    use nix::{
        fcntl::OFlag,
        sys::stat::Mode
    };

    ARGS.set(args::parse_args()).ok();

    // do this before setting up signal handlers to not have to worry about EINTR
    // and before run_in_fork to fail early
    let proc_dir_fd =
        unixutils::openat_to_ownedfd(None, "/proc", OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC, Mode::empty())
            .unwrap_or_else(|err| error_out!("Can't access /proc: {}", err));

    // safety: can only fork like that at the beginning when no other threads are yet running
    let child_pid = run_in_fork(|| run_child(args().command.clone()));

    setup_termination_signal_handler();
    let events = tracer::waitpid_loop(child_pid, proc_dir_fd.as_fd());
    // if we've got here we'll exit shortly anyway so ignore SIGTERM and SIGINT instead of using SigDfl
    ignore_termination_signals();

    let processes = events_to_process_tree(events);
    let root = processes.get(&child_pid).expect("Our only child is not in children (??)");
    let mut output: Box<dyn Write> = match &args().output_file {
        None => Box::new(BufWriter::new(std::io::stdout())),
        Some(path) => Box::new(BufWriter::new(
            File::create(&path).unwrap_or_else(|err| error_out!("Can't open file {} for writing: {}", path.to_string_lossy(), err)),
        )),
    };

    root.print_tree(0, &processes, &mut output)
        .and_then(|_| output.flush()) // We wouldn't get to catch write errors without flushing manually
        .unwrap_or_else(|e| {
            let default_output_name = OsString::from("(stdout)");
            let filename = args().output_file.as_ref().unwrap_or(&default_output_name);
            error_out!("Couldn't write process tree to file {}: {}", filename.to_string_lossy(), e);
        });

    let exit_code = std::process::ExitCode::from(match root.exit {
        None => 1,
        Some(ExitReason::NormalExit {exit_code}) => exit_code as u8,
        Some(ExitReason::KilledBySignal {signal, ..}) => (128 + (signal as i32)) as u8
    });

    // little tiny optimisation: don't close() the handle to /proc, we are exiting anyway
    std::mem::forget(proc_dir_fd);
    // and don't spend time unmapping memory as well (this gets rid of 1 syscall)
    std::mem::forget(processes);

    exit_code
}
