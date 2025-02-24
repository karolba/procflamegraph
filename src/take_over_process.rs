// Use `gen` blocks as crude coroutines

use std::os::fd::BorrowedFd;
use std::path::PathBuf;

use crate::coroutines::{CoroutineState, co_return, co_try, co_yield, co_yield_from};
use crate::ptrace_syscall_info::{SyscallEntry, SyscallExit, SyscallOp};
use crate::tracee::{ArgvEnvpAddrs, PokeResult, Tracee};
use crate::unixutils;

// todo: change this wait_* stuff for `next_syscall`
// or `do_syscall`
// it should

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
    co_try!(co_yield_from!(wait_for_syscall_entry(tracee))); // make sure we really are in a syscall entry
    co_return!(Ok(exit));
}

gen fn syscall(tracee: Tracee, base_regset: libc::user_regs_struct, syscall: SyscallEntry) -> CoroutineState<(), nix::Result<SyscallExit>> {
    co_try!(tracee.set_syscall_arg_regs(base_regset, syscall));
    co_return!(co_yield_from!(do_syscall(tracee)));
}


// todo: instruction length based on architecture (4 on aarch64)
// todo: is 4 always even right on aarch64? check what THUMB mode and arm32 emulation mode does
//
// todo: what even happens on x86_64 when this is wrong and the instruction pointer gets unaligned?
#[cfg(target_arch = "x86_64")]
fn roll_instruction_pointer_back_over_syscall_instruction(mut regs : libc::user_regs_struct) -> libc::user_regs_struct {
    regs.rip -= 2; /* TODO: this is probably wrong? */
    regs
}
#[cfg(target_arch = "aarch64")]
fn roll_instruction_pointer_back_over_syscall_instruction(mut regs : libc::user_regs_struct) -> libc::user_regs_struct {
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

// todo: better return type
pub(crate) gen fn take_over_process_syscall(tracee: Tracee, procfs: BorrowedFd<'_>) -> CoroutineState<(), bool> {
    use bstr::io::BufReadExt;

    let addrs = match tracee.argv_envp_addrs(procfs) {
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
            eprintln!("Warning: Could not read /proc/{}/stat: did not have permission to read argv_addr and envp_addr fields", tracee.pid);
            co_return!(false);
        }
        Ok((Some(addrs), _fd)) => addrs,
        Ok((None, _fd)) => {
            eprintln!("Warning: Could not read /proc/{}/stat: could not decode file format", tracee.pid);
            co_return!(false);
        }
        Err(e) => {
            eprintln!("Warning: Could not read /proc/{}/stat: {}", tracee.pid, e);
            co_return!(false);
        }
    };

    let _original_syscall_entry: SyscallEntry = co_yield_from!(wait_for_syscall_entry(tracee)).expect("TODO");
    let original_regset = tracee.getregset().unwrap_or_else(|_| todo!("check this error"));

    let base_regset = roll_instruction_pointer_back_over_syscall_instruction(original_regset);

    let mut memory_to_inject: Vec<u64> = Vec::new(); // todo: precompute size?

    // eugh this has a very inconsistent definition but the ptrace api depends on it
    // is what ptrace(2) refers to as "machine word size" really just pointer size? so sizeof::<usize>()?
    let machine_word_size: u64 = 8;

    let proc_self_exe_str_offset: u64 = memory_to_inject.len() as u64 * machine_word_size;
    memory_to_inject.push(u64::from_ne_bytes(*b"/proc/se"));
    memory_to_inject.push(u64::from_ne_bytes(*b"lf/exe\0\0"));

    let argv_array_offset: u64 = memory_to_inject.len() as u64 * machine_word_size;
    let path = PathBuf::from(tracee.pid.to_string()).join("cmdline");
    // todo: should this be a read_restart_on_eintr_delay_close?
    let argv = match unixutils::read_restart_on_eintr(Some(procfs), path.as_path()) {
        Err(e) => {
            eprintln!("Warning: Could not read /proc/{}/cmdline: {}", tracee.pid, e);
            co_return!(false);
        }
        Ok(argv) => argv,
    };
    let mut argv_position: u64 = 0;
    // what do you mean this can error out?? when???
    for arg in argv.byte_records(b'\0').map(|r| r.unwrap()) {
        memory_to_inject.push(addrs.argv_start + argv_position);
        argv_position += arg.len() as u64 + 1; // +1 for the unaccounted null terminator
    }
    memory_to_inject.push(0u64); // null pointer at the end of argv

    let envp_array_offset: u64 = memory_to_inject.len() as u64 * machine_word_size;
    let path = PathBuf::from(tracee.pid.to_string()).join("environ");
    // todo: should this be a read_restart_on_eintr_delay_close?
    let envp = match unixutils::read_restart_on_eintr(Some(procfs), path.as_path()) {
        Err(e) => {
            eprintln!("Warning: Could not read /proc/{}/environ: {}", tracee.pid, e);
            co_return!(false);
        }
        Ok(envp) => envp,
    };
    let mut envp_position: u64 = 0;
    // what do you mean this can error out?? when???
    for arg in envp.byte_records(b'\0').map(|r| r.unwrap()) {
        memory_to_inject.push(addrs.envp_start + envp_position);
        envp_position += arg.len() as u64 + 1; // +1 for the unaccounted null terminator
    }
    memory_to_inject.push(0u64); // null pointer at the end of envp

    // don't use what has already been read during PTRACE_EVENT_EXEC because this could have been changed by the process
    // between execution start and its first syscall we've captured to change

    let memory_mapping: SyscallExit = co_yield_from!(syscall(tracee, base_regset, SyscallEntry {
        nr: libc::SYS_mmap as u64,
        args: [
            0u64,                                             // addr (NULL)
            memory_to_inject.len() as u64 * 8u64,             // length
            (libc::PROT_READ | libc::PROT_WRITE) as u64,      // prot
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64, // flags
            (-1i64) as u64,                                   // fd
            0u64,                                             // offset
        ]
    })).expect("TODO");
    if memory_mapping.is_error != 0 {
        todo!("injected mmap in child errored out");
    }

    match tracee.poke(&memory_to_inject, memory_mapping.rval as usize) {
        PokeResult::Ok => (),
        PokeResult::PidIsDead => co_return!(false),
        PokeResult::Err(_err) => todo!("error when poking"),
    }

    // todo: checks on process_vm_writev are more strict than on ptrace::write
    // so retry with a ptrace::write calls for each machine word (4 or 8 bytes) if this somehow fails
    // See https://stackoverflow.com/questions/64322172/ptrace-allows-to-write-to-executable-program-segment-but-process-vm-writev-does
    // todo: also understand why they are stricter ... does that apply to anything else? /proc/<pid>/{environ,cmdline,exe,stat}?
    //       and if I don't care about it change memory_to_inject to Vec<u8> and get rid of the bytemuck crate

    tracee.set_syscall_arg_regs(base_regset, SyscallEntry {
        nr: libc::SYS_execve as u64,
        args: [
            memory_mapping.rval as u64 + proc_self_exe_str_offset, // "/proc/self/exe\0"
            memory_mapping.rval as u64 + argv_array_offset,        // array pointing to values in [argv_start..argv_end]
            memory_mapping.rval as u64 + envp_array_offset,        // array pointing to values in [envp_start..envp_end]
            0u64,
            0u64,
            0u64,
        ],
    }).expect("TODO");

    // detach.
    co_return!(true);
}
