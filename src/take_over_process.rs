use crate::{coroutines::{CoroutineState, co_return, co_try, co_yield, co_yield_from},
            output_peeker,
            output_peeker::OutputPeeker,
            sys_linux::{fd::{pidfd_getfd, pidfd_open},
                        proc::{process_cmdline, process_environ},
                        ptrace::{ArgvEnvpAddrs, PokeResult, Tracee},
                        ptrace_syscall_info::{SyscallEntry, SyscallExit, SyscallOp}}};
use bstr::io::BufReadExt;
use nix::{errno::Errno, sys::ptrace};
use std::{fmt,
          os::fd::{AsFd, OwnedFd}};

// todo: change this wait_* stuff for `next_syscall`
// or `do_syscall`
// it should

// Use `gen` blocks as crude coroutines

gen fn wait_for_syscall_entry(tracee: Tracee) -> CoroutineState<(), nix::Result<SyscallEntry>> {
    loop {
        match co_try!(tracee.syscall_info()).map(|syscall_info| syscall_info.op) {
            Some(SyscallOp::Entry(entry)) => co_return!(Ok(entry)),
            _ => co_yield!(()),
        }
    }
}

gen fn wait_for_syscall_exit(tracee: Tracee) -> CoroutineState<(), nix::Result<SyscallExit>> {
    loop {
        match co_try!(tracee.syscall_info()).map(|syscall_info| syscall_info.op) {
            Some(SyscallOp::Exit(exit)) => co_return!(Ok(exit)),
            _ => co_yield!(()),
        }
    }
}

gen fn do_syscall(tracee: Tracee) -> CoroutineState<(), nix::Result<SyscallExit>> {
    co_yield!(()); // continue to syscall exit
    let exit = co_try!(co_yield_from!(wait_for_syscall_exit(tracee))); // make sure we really are in a syscall exit
    co_yield!(()); // continue to syscall entry

    // the ptrace api practically guarantees syscall entry and exit always successively alternate
    // assuming that's true (other tracers seem to assume that too), we don't need to spend time
    // checking the assumption
    // co_try!(co_yield_from!(wait_for_syscall_entry(tracee)));

    co_return!(Ok(exit));
}

gen fn syscall(tracee: Tracee, base_regset: libc::user_regs_struct, syscall: SyscallEntry) -> CoroutineState<(), Result<SyscallExit, TakeOverError>> {
    co_try!(
        tracee
            .set_syscall_arg_regs(base_regset, syscall)
            .map_err(TakeOverError::InjectedSyscallSetArgsError)
    );
    co_return!(co_yield_from!(do_syscall(tracee)).map_err(TakeOverError::InjectedSyscallPtraceInfoSyscallExitError));
}

// todo: instruction length based on architecture (4 on aarch64)
// todo: is 4 always even right on aarch64? check what THUMB mode and arm32 emulation mode does
//
// todo: what even happens on x86_64 when this is wrong and the instruction pointer gets unaligned?
#[cfg(target_arch = "x86_64")]
fn roll_instruction_pointer_back_over_syscall_instruction(mut regs: libc::user_regs_struct) -> libc::user_regs_struct {
    regs.rip -= 2; /* TODO: this is probably wrong? */
    regs
}
#[cfg(target_arch = "aarch64")]
fn roll_instruction_pointer_back_over_syscall_instruction(mut regs: libc::user_regs_struct) -> libc::user_regs_struct {
    regs.pc -= 4;
    regs
}
#[cfg(target_arch = "arm")]
fn roll_instruction_pointer_back_over_syscall_instruction(mut regs: libc::user_regs_struct) -> libc::user_regs_struct {
    // ARM32 has different instruction lengths depending on mode (ARM vs Thumb)
    // SWI instruction is 4 bytes in ARM mode, 2 bytes in Thumb mode
    let cpsr = regs.uregs[16];
    let thumb_mode = (cpsr & 0x20) != 0;

    regs.uregs[15] -= if thumb_mode { 2 } else { 4 };
    regs
}

#[cfg(target_arch = "aarch64")]
fn stack_pointer(regset: &libc::user_regs_struct) -> libc::c_ulonglong {
    regset.sp
}
#[cfg(target_arch = "x86_64")]
fn stack_pointer(regset: &libc::user_regs_struct) -> libc::c_ulong {
    regset.rsp
}

#[derive(Clone, Copy)]
pub(crate) struct TakeOverActions<'a> {
    pub(crate) tracee:             Tracee,
    pub(crate) output_peeker:      &'a OutputPeeker,
    pub(crate) do_redirect_stderr: bool,
    pub(crate) do_redirect_stdout: bool,
    pub(crate) do_reexec:          bool,
}

pub(crate) enum TakeOverResult {
    ReexecSetupDetach(),
    ContinueExecuting(),
}

pub(crate) enum TakeOverError {
    WaitForFirstSyscallEntryError(Errno),
    GetInitialRegsetError(Errno),
    RestoreInitialRegsetError(Errno),
    InjectedSyscallSetArgsError(Errno),
    InjectedSyscallPtraceInfoSyscallExitError(Errno),
    CloseRangeInChildError(Errno),
    CloseInChildError(Errno),
    PidFdOpenError(Errno),
    PidFdGetFdError(Errno),
    ReadOriginalWordAtChildStackPointerError(Errno),
    ChildPipe2Error(Errno),
    ReadPipe2WordAtChildStackPointerError(Errno),
    PidFdGetFdPipe2ResultError(Errno),
    ChildDup3Error(Errno),
    RestoreOriginalValueAtChildsStackPointerError(Errno),
    ProcChildPidStatPtracePermissionCheckFailed,
    ProcChildPidStatDecodeFileFormatError,
    ProcChildPidStatCouldNotReadFile(Errno),
    ProcChildCmdlineReadError(Errno),
    ProcChildEnvironReadError(Errno),
    ChildMmapError(Errno),
    ChildDiedWhilePokingMemoryIntoIt,
    ReexecMemoryRegionPokeError(Errno),
    SetSyscallArgsForReexecError(Errno),
}

impl fmt::Display for TakeOverError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TakeOverError::WaitForFirstSyscallEntryError(errno) => write!(f, "a: {}", errno),
            TakeOverError::GetInitialRegsetError(errno) => write!(f, "a: {}", errno),
            TakeOverError::RestoreInitialRegsetError(errno) => write!(f, "a: {}", errno),
            TakeOverError::InjectedSyscallSetArgsError(errno) => write!(f, "a: {}", errno),
            TakeOverError::InjectedSyscallPtraceInfoSyscallExitError(errno) => write!(f, "a: {}", errno),
            TakeOverError::CloseRangeInChildError(errno) => write!(f, "a: {}", errno),
            TakeOverError::CloseInChildError(errno) => write!(f, "a: {}", errno),
            TakeOverError::PidFdOpenError(errno) => write!(f, "a: {}", errno),
            TakeOverError::PidFdGetFdError(errno) => write!(f, "a: {}", errno),
            TakeOverError::ReadOriginalWordAtChildStackPointerError(errno) => write!(f, "a: {}", errno),
            TakeOverError::ChildPipe2Error(errno) => write!(f, "a: {}", errno),
            TakeOverError::ReadPipe2WordAtChildStackPointerError(errno) => write!(f, "a: {}", errno),
            TakeOverError::PidFdGetFdPipe2ResultError(errno) => write!(f, "a: {}", errno),
            TakeOverError::ChildDup3Error(errno) => write!(f, "a: {}", errno),
            TakeOverError::RestoreOriginalValueAtChildsStackPointerError(errno) => write!(f, "a: {}", errno),
            TakeOverError::ProcChildPidStatPtracePermissionCheckFailed => write!(f, "a:"),
            TakeOverError::ProcChildPidStatDecodeFileFormatError => write!(f, "a:"),
            TakeOverError::ProcChildPidStatCouldNotReadFile(errno) => write!(f, "a: {}", errno),
            TakeOverError::ProcChildCmdlineReadError(errno) => write!(f, "a: {}", errno),
            TakeOverError::ProcChildEnvironReadError(errno) => write!(f, "a: {}", errno),
            TakeOverError::ChildMmapError(errno) => write!(f, "a: {}", errno),
            TakeOverError::ChildDiedWhilePokingMemoryIntoIt => write!(f, "a:"),
            TakeOverError::ReexecMemoryRegionPokeError(errno) => write!(f, "a: {}", errno),
            TakeOverError::SetSyscallArgsForReexecError(errno) => write!(f, "a: {}", errno),
        }
    }
}

struct RedirectOutputResult {
    childs_original_fd: OwnedFd,
    read_pipe:          OwnedFd,
}

impl TakeOverActions<'_> {
    pub(crate) fn is_any_action_set(&self) -> bool {
        self.do_redirect_stdout || self.do_redirect_stderr || self.do_reexec
    }

    pub(crate) gen fn take_over_step(self) -> CoroutineState<(), Result<TakeOverResult, TakeOverError>> {
        // make sure we're in syscall-entry, not syscall-exit
        // todo: the first thing a process ever does seems to be syscall-exit, not syscall-entry
        //       maybe could use that to save the needless wait (and syscalls spent) for syscall-entry?
        let original_syscall_entry: SyscallEntry =
            co_try!(co_yield_from!(wait_for_syscall_entry(self.tracee)).map_err(|errno: Errno| TakeOverError::WaitForFirstSyscallEntryError(errno)));
        let original_regset = co_try!(
            self.tracee
                .getregset()
                .map_err(TakeOverError::GetInitialRegsetError)
        );
        let redo_syscall_again_regset = roll_instruction_pointer_back_over_syscall_instruction(original_regset);

        if self.do_redirect_stdout {
            let result: RedirectOutputResult = co_try!(co_yield_from!(self.redirect_output(redo_syscall_again_regset, libc::STDOUT_FILENO)));
            self.output_peeker
                .start_peeking_child_stdout(output_peeker::StartPeekingStdout {
                    pid:             self.tracee.pid,
                    original_stdout: result.childs_original_fd,
                    pipe_from_child: result.read_pipe,
                });
        }

        if self.do_redirect_stderr {
            let result: RedirectOutputResult = co_try!(co_yield_from!(self.redirect_output(redo_syscall_again_regset, libc::STDERR_FILENO)));
            self.output_peeker
                .start_peeking_child_stderr(output_peeker::StartPeekingStderr {
                    pid:             self.tracee.pid,
                    original_stderr: result.childs_original_fd,
                    pipe_from_child: result.read_pipe,
                });
        }

        if self.do_reexec {
            co_try!(co_yield_from!(self.reexec(redo_syscall_again_regset)));
            co_return!(Ok(TakeOverResult::ReexecSetupDetach()));
        }

        co_try!(self.restore_state(original_regset, original_syscall_entry));

        co_return!(Ok(TakeOverResult::ContinueExecuting()));
    }

    fn restore_state(self, regset: libc::user_regs_struct, syscall_entry: SyscallEntry) -> Result<(), TakeOverError> {
        // TODO: ensure (statically?) we're in syscall entry, not syscall-exit (or test if this also works on syscall-exit)
        self.tracee
            .set_syscall_arg_regs(regset, syscall_entry)
            .map_err(TakeOverError::RestoreInitialRegsetError)
    }

    gen fn close_two_file_descriptors(
        self,
        base_regset: libc::user_regs_struct,
        fd1: i32,
        fd2: i32,
    ) -> CoroutineState<(), Result<(), TakeOverError>> {
        if fd1 + 1 == fd2 || fd1 - 1 == fd2
        /* todo: and on Linux 5.9 at least as a heuristic */
        {
            // todo: close on linux always cleans the file descriptor (even if we get an EINTR),
            let res: SyscallExit = co_try!(co_yield_from!(syscall(self.tracee, base_regset, SyscallEntry {
                nr:   libc::SYS_close_range as u64,
                args: [
                    i32::min(fd1, fd2) as u64, // first
                    i32::max(fd1, fd2) as u64, // last
                    0u64,                      // flags
                    0u64,                      // nothing
                    0u64,                      // nothing
                    0u64,                      // nothing
                ],
            })));
            if res.is_error == 0 {
                co_return!(Ok(()));
            }
            if res.is_error != 0 {
                let error = Errno::from_raw(-res.rval as i32);
                // try closing sequentially if close_range does not exist
                if error != Errno::ENOSYS {
                    co_return!(Err(TakeOverError::CloseRangeInChildError(error)));
                }
            }
        }

        // todo: close on linux always cleans the file descriptor (even if we get an EINTR),
        // only EBADF is a real bad error
        let res: SyscallExit = co_try!(co_yield_from!(syscall(self.tracee, base_regset, SyscallEntry {
            nr:   libc::SYS_close as u64,
            args: [
                fd1 as u64, // fd
                0u64,       // nothing
                0u64,       // nothing
                0u64,       // nothing
                0u64,       // nothing
                0u64,       // nothing
            ],
        })));
        if res.is_error != 0 {
            co_return!(Err(TakeOverError::CloseInChildError(Errno::from_raw(-res.rval as i32))));
        }

        let res: SyscallExit = co_try!(co_yield_from!(syscall(self.tracee, base_regset, SyscallEntry {
            nr:   libc::SYS_close as u64,
            args: [
                fd2 as u64, // fd
                0u64,       // nothing
                0u64,       // nothing
                0u64,       // nothing
                0u64,       // nothing
                0u64,       // nothing
            ],
        })));
        if res.is_error != 0 {
            co_return!(Err(TakeOverError::CloseInChildError(Errno::from_raw(-res.rval as i32))));
        }

        co_return!(Ok(()));
    }

    gen fn redirect_output(
        self,
        base_regset: libc::user_regs_struct,
        child_fd: libc::c_int,
    ) -> CoroutineState<(), Result<RedirectOutputResult, TakeOverError>> {
        let pidfd = co_try!(pidfd_open(self.tracee.pid.as_raw(), 0).map_err(TakeOverError::PidFdOpenError));

        let childs_original_stderr = co_try!(pidfd_getfd(pidfd.as_fd(), child_fd, 0).map_err(TakeOverError::PidFdGetFdError));

        // use the top of the stack as a temporary storage for the result of pipe2(2)
        let stack_pointer = stack_pointer(&base_regset);

        let original_sp_value = co_try!(
            ptrace::read(self.tracee.pid, stack_pointer as *mut libc::c_void).map_err(TakeOverError::ReadOriginalWordAtChildStackPointerError)
        );

        let pipe2_result: SyscallExit = co_try!(co_yield_from!(syscall(self.tracee, base_regset, SyscallEntry {
            nr:   libc::SYS_pipe2 as u64,
            args: [
                stack_pointer, // the address where fd[0] and fd[1] are gonna be placed
                0u64,          // flags
                0u64,          // nothing
                0u64,          // nothing
                0u64,          // nothing
                0u64,          // nothing
            ],
        })));
        if pipe2_result.is_error != 0 {
            co_return!(Err(TakeOverError::ChildPipe2Error(Errno::from_raw(-pipe2_result.rval as i32))));
        }

        let [pipe_read_end_in_child, pipe_write_end_in_child] = co_try!(
            ptrace::read(self.tracee.pid, stack_pointer as *mut libc::c_void)
                .map(|word: i64| unsafe { std::mem::transmute::<i64, [i32; 2]>(word) })
                .map_err(TakeOverError::ReadPipe2WordAtChildStackPointerError)
        );

        let read_pipe: OwnedFd = co_try!(pidfd_getfd(pidfd.as_fd(), pipe_read_end_in_child, 0).map_err(TakeOverError::PidFdGetFdPipe2ResultError));

        let duped: SyscallExit = co_try!(co_yield_from!(syscall(self.tracee, base_regset, SyscallEntry {
            nr:   libc::SYS_dup3 as u64,
            args: [
                pipe_write_end_in_child as u64, // oldfd
                child_fd as u64,                // newfd
                0u64,                           // flags
                0u64,                           // nothing
                0u64,                           // nothing
                0u64,                           // nothing
            ],
        })));
        if duped.is_error != 0 {
            co_return!(Err(TakeOverError::ChildDup3Error(Errno::from_raw(-duped.rval as i32))));
        }

        co_try!(co_yield_from!(self.close_two_file_descriptors(base_regset, pipe_read_end_in_child, pipe_write_end_in_child)));

        co_try!(
            ptrace::write(self.tracee.pid, stack_pointer as *mut libc::c_void, original_sp_value)
                .map_err(TakeOverError::RestoreOriginalValueAtChildsStackPointerError)
        );

        co_return!(Ok(RedirectOutputResult {
            childs_original_fd: childs_original_stderr,
            read_pipe
        }));
    }

    #[allow(clippy::manual_slice_size_calculation)] // i'm calculating it for the child
    gen fn reexec(self, base_regset: libc::user_regs_struct) -> CoroutineState<(), Result<(), TakeOverError>> {
        let addrs = match self.tracee.argv_envp_addrs() {
            Ok((
                Some(ArgvEnvpAddrs {
                    argv_start: 0,
                    argv_end: 0,
                    envp_start: 0,
                    envp_end: 0,
                }),
                _fd,
            )) => {
                // The kernel gives us a "0 0 0 0" if a ptrace permission check fails (todo specify here which one)
                // eprintln!("Warning: Could not read /proc/{}/stat: did not have permission to read argv_addr and envp_addr fields", self.tracee.pid);
                co_return!(Err(TakeOverError::ProcChildPidStatPtracePermissionCheckFailed));
            }
            Ok((Some(addrs), _fd)) => addrs,
            Ok((None, _fd)) => {
                // eprintln!("Warning: Could not read /proc/{}/stat: could not decode file format", self.tracee.pid);
                co_return!(Err(TakeOverError::ProcChildPidStatDecodeFileFormatError));
            }
            Err(e) => {
                // eprintln!("Warning: Could not read /proc/{}/stat: {}", self.tracee.pid, e);
                co_return!(Err(TakeOverError::ProcChildPidStatCouldNotReadFile(e)));
            }
        };

        let mut memory_to_inject: Vec<u64> = Vec::new(); // todo: precompute size?

        // eugh this has a very inconsistent definition but the ptrace api depends on it
        // is what ptrace(2) refers to as "machine word size" really just pointer size? so size_of::<usize>() as u64?
        let machine_word_size: u64 = 8;
        const _: () = assert!(size_of::<usize>() == 8);

        let proc_self_exe_str_offset: u64 = memory_to_inject.len() as u64 * machine_word_size;
        memory_to_inject.push(u64::from_ne_bytes(*b"/proc/se"));
        memory_to_inject.push(u64::from_ne_bytes(*b"lf/exe\0\0"));

        let argv_array_offset: u64 = memory_to_inject.len() as u64 * machine_word_size;
        // todo: we already have the cmdline (and envp?) of the process read from before
        let (argv, _fd) = co_try!(process_cmdline(self.tracee.pid).map_err(TakeOverError::ProcChildCmdlineReadError));

        let mut argv_position: u64 = 0;
        // what do you mean this can error out?? when???
        for arg in argv
            .byte_records(b'\0')
            .map(|r| r.unwrap())
        {
            memory_to_inject.push(addrs.argv_start + argv_position);
            argv_position += arg.len() as u64 + 1; // +1 for the unaccounted null terminator
        }
        memory_to_inject.push(0u64); // null pointer at the end of argv

        let envp_array_offset: u64 = memory_to_inject.len() as u64 * machine_word_size;
        // todo: should this be a read_restart_on_eintr_delay_close?
        let (envp, _fd) = co_try!(process_environ(self.tracee.pid).map_err(TakeOverError::ProcChildEnvironReadError));
        let mut envp_position: u64 = 0;
        for arg in envp
            .byte_records(b'\0')
            .map(|r| r.unwrap())
        // what do you mean this can error out?? when???
        {
            memory_to_inject.push(addrs.envp_start + envp_position);
            envp_position += arg.len() as u64 + 1; // +1 for the unaccounted null terminator
        }
        memory_to_inject.push(0u64); // null pointer at the end of envp

        // don't use what has already been read during PTRACE_EVENT_EXEC because this could have been changed by the process
        // between execution start and its first syscall we've captured to change
        // todo: ^ is that really relevant? The process can't really resize that area
        //       and even if it does add new '\0's do we wanna pass that on?

        let memory_mapping: SyscallExit = co_try!(co_yield_from!(syscall(self.tracee, base_regset, SyscallEntry {
            nr:   libc::SYS_mmap as u64,
            args: [
                0u64,                                             // addr (NULL)
                memory_to_inject.len() as u64 * 8u64,             // length
                (libc::PROT_READ | libc::PROT_WRITE) as u64,      // prot
                (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64, // flags
                (-1i64) as u64,                                   // fd
                0u64,                                             // offset
            ],
        })));
        if memory_mapping.is_error != 0 {
            co_return!(Err(TakeOverError::ChildMmapError(Errno::from_raw(-memory_mapping.rval as i32))));
        }

        match self
            .tracee
            .poke(&memory_to_inject, memory_mapping.rval as usize)
        {
            PokeResult::Ok => (),
            PokeResult::PidIsDead => co_return!(Err(TakeOverError::ChildDiedWhilePokingMemoryIntoIt)),
            PokeResult::Err(err) => co_return!(Err(TakeOverError::ReexecMemoryRegionPokeError(err))),
        }

        co_try!(
            self.tracee
                .set_syscall_arg_regs(base_regset, SyscallEntry {
                    nr:   libc::SYS_execve as u64,
                    args: [
                        memory_mapping.rval as u64 + proc_self_exe_str_offset, // "/proc/self/exe\0"
                        memory_mapping.rval as u64 + argv_array_offset,        // array pointing to values in [argv_start..argv_end]
                        memory_mapping.rval as u64 + envp_array_offset,        // array pointing to values in [envp_start..envp_end]
                        0u64,
                        0u64,
                        0u64,
                    ],
                })
                .map_err(TakeOverError::SetSyscallArgsForReexecError)
        );

        // detach.
        co_return!(Ok(()));
    }
}
