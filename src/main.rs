#![feature(gen_blocks)]
#![feature(maybe_uninit_slice)]

mod args;
mod coroutines;
mod errors;
mod output_peeker;
mod sys_linux;
mod take_over_process;
mod tracer;
mod output;

use crate::{
    output::events_to_processes,
    errors::log_warn,
    output::output_process_tree,
    sys_linux::kernel_version::kernel_major_minor,
    tracer::waitpid_loop
};
use nix::{
    sys::{ptrace, signal::Signal},
    unistd::{fork, ForkResult},
};
use std::{
    ffi::CString,
    process::ExitCode,
    sync::atomic::{AtomicBool, Ordering},
    sync::OnceLock,
};

static ARGS: OnceLock<args::Args> = OnceLock::new();
pub(crate) fn args() -> &'static args::Args {
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

#[derive(Debug, Clone)]
enum ExitReason {
    NormalExit { exit_code: i64 },
    // todo: is there a signal type in the nix crate?
    KilledBySignal { signal: Signal, generated_core_dump: bool },
}


#[derive(PartialEq)]
enum ExecTracedChildOptions {
    TryToReexecOnPtracemeEPERM,
    DoNotTryToReexecOnPtracemeEPERM,
}
fn exec_traced_child(opts: ExecTracedChildOptions) -> ! {
    use std::os::unix::ffi::OsStrExt;
    let child_args: Vec<CString> = args().command.iter().map(|osstr| CString::new(osstr.as_bytes()).unwrap()).collect();

    match ptrace::traceme() {
        Err(nix::errno::Errno::EPERM) if opts == ExecTracedChildOptions::TryToReexecOnPtracemeEPERM => {
            // we might be being ptraced ourselves
            // to support running under `strace -f -b execve` let's reexec ourselves and try doing PTRACE_TRACEME again then

            let reexec_args = [
                vec![
                    CString::new(args().our_name.clone()).unwrap(),
                    c"--_reexec-ptraceme".into(),
                    c"--".into(),
                ],
                child_args.clone()
            ].concat();

            nix::unistd::execvp(c"/proc/self/exe", &reexec_args).expect("couldn't reexec myself");
            unreachable!();
        }
        result => {
            // todo: don't error out here, just maybe warn, give up, and continue without tracing
            result.expect("call to ptrace(PTRACE_TRACEME) failed");
        }
    }

    // Stop ourselves so our tracer parent can set up PTRACE_SETOPTIONS on us
    nix::sys::signal::raise(Signal::SIGSTOP).expect("raise(SIGSTOP) failed");

    // todo: better errors if execve fails
    //       and return with -127 then
    nix::unistd::execvp(child_args.get(0).expect("need to pass at least one arg"), &child_args).expect("execve failed");
    unreachable!();
}

fn run_in_fork<F: FnOnce() -> ()>(run_child: F) -> nix::unistd::Pid {
    // safety: can really only call this function when no more than 1 thread is yet to run
    // (calling fork ourselves is not thread-safe)
    match unsafe { fork() }.expect("fork() failed") {
        ForkResult::Parent { child } => child,
        ForkResult::Child => {
            run_child();
            std::process::exit(1);
        }
    }
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

fn warn_on_an_old_kernel() {
    let (major, minor) = match kernel_major_minor() {
        Some(version) => version,
        None => return, // if we couldn't get the kernel version for some reason, ignore it
    };

    // Version requirements:
    // - Linux 5.3 for PTRACE_GET_SYSCALL_INFO
    // - Linux 5.6 for pidfd_getfd
    if major < 5 || (major == 5 && minor <= 6) {
        log_warn!("The lowest required Linux version is 5.6 - you are running {}.{}", major, minor);
    }
}


fn main() -> ExitCode {
    ARGS.set(args::parse_args()).ok();

    if args().reexec_ptraceme {
        exec_traced_child(ExecTracedChildOptions::DoNotTryToReexecOnPtracemeEPERM);
    }

    warn_on_an_old_kernel();

    // safety: can only fork like that at the beginning when no other threads are yet running
    let child_pid = run_in_fork(|| exec_traced_child(ExecTracedChildOptions::TryToReexecOnPtracemeEPERM));

    // can finally create threads
    let output_peeker = output_peeker::OutputPeeker::new();

    setup_termination_signal_handler();
    let events = waitpid_loop(child_pid, &output_peeker);
    // if we've got here we'll exit shortly anyway so ignore SIGTERM and SIGINT instead of using SigDfl
    ignore_termination_signals();

    // todo: output_peeker.result() waits on all pipes to close
    //       this should probably be interruptable with SIGTERM/SIGINT
    //       maybe we could even have a default timeout if a SIGTERM/SIGINT was received before?
    let processes = events_to_processes(events, output_peeker.result());

    let root_process_exit = output_process_tree(child_pid, processes);

    ExitCode::from(match root_process_exit {
        None => 1,
        Some(ExitReason::NormalExit {exit_code}) => exit_code as u8,
        Some(ExitReason::KilledBySignal {signal, ..}) => (128 + (signal as i32)) as u8
    })
}
