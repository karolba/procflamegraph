// based on https://github.com/Mic92/vmsh/blob/dd39175f1ad8a2e3254705575d20d6c84dd98be2/src/tracer/ptrace_syscall_info.rs

use libc::c_long;
use nix::unistd::Pid;
use std::mem::MaybeUninit;
use std::mem::size_of;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
const PTRACE_GET_SYSCALL_INFO: u32 = 0x420e;

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
const PTRACE_GET_SYSCALL_INFO: i32 = 0x420e;

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
enum OpType {
    PTRACE_SYSCALL_INFO_NONE = 0,
    PTRACE_SYSCALL_INFO_ENTRY = 1,
    PTRACE_SYSCALL_INFO_EXIT = 2,
    PTRACE_SYSCALL_INFO_SECCOMP = 3,
    unknown = 4,
}

#[repr(C)]
#[derive(Copy, Clone)] // have to in order to use this in a union
struct RawEntry {
    nr: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Copy, Clone)] // have to in order to use this in a union
struct RawExit {
    rval: i64,
    is_error: u8,
}

#[repr(C)]
#[derive(Copy, Clone)] // have to in order to use this in a union
struct RawSeccomp {
    nr: u64,
    args: [u64; 6],
    ret_data: u32,
}

#[repr(C)]
union RawData {
    entry: RawEntry,
    exit: RawExit,
    seccomp: RawSeccomp,
}

/// equivalent to `ptrace_syscall_info`
#[repr(C)]
struct RawInfo {
    op: OpType,
    _pad: [u8; 3],
    arch: u32,
    instruction_pointer: u64,
    stack_pointer: u64,
    data: RawData,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct SyscallEntry {
    pub(crate) nr: u64,        /* System call number */
    pub(crate) args: [u64; 6], /* System call arguments */
}
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct SyscallExit {
    pub(crate) rval: i64, /* System call return value */

    // System call error flag;
    // Boolean: does rval contain an error value (-ERRCODE) or a nonerror return value?
    pub(crate) is_error: u8,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct SyscallSeccomp {
    pub(crate) nr: u64,        /* System call number */
    pub(crate) args: [u64; 6], /* System call arguments */
    pub(crate) ret_data: u32,  /* SECCOMP_RET_DATA portion of SECCOMP_RET_TRACE return value */
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) enum SyscallOp {
    Entry(SyscallEntry),
    Exit(SyscallExit),
    Seccomp(SyscallSeccomp),
    None,
}

/// See man ptrace (linux) for reference.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct SyscallInfo {
    pub(crate) arch: u32,                /* AUDIT_ARCH_* value; see seccomp(2) */
    pub(crate) instruction_pointer: u64, /* CPU instruction pointer */
    pub(crate) stack_pointer: u64,       /* CPU stack pointer */
    pub(crate) op: SyscallOp,
}

fn parse_raw_data(info: RawInfo) -> Option<SyscallOp> {
    match info.op {
        OpType::PTRACE_SYSCALL_INFO_NONE => Some(SyscallOp::None),
        OpType::PTRACE_SYSCALL_INFO_ENTRY => {
            let entry = unsafe { info.data.entry };
            Some(SyscallOp::Entry(SyscallEntry { nr: entry.nr, args: entry.args }))
        }
        OpType::PTRACE_SYSCALL_INFO_EXIT => {
            let exit = unsafe { info.data.exit };
            Some(SyscallOp::Exit(SyscallExit {
                rval: exit.rval,
                is_error: exit.is_error,
            }))
        }
        OpType::PTRACE_SYSCALL_INFO_SECCOMP => {
            let seccomp = unsafe { info.data.seccomp };
            Some(SyscallOp::Seccomp(SyscallSeccomp {
                nr: seccomp.nr,
                args: seccomp.args,
                ret_data: seccomp.ret_data,
            }))
        }
        _ => None,
    }
}

fn parse_raw_info(raw: RawInfo) -> Option<SyscallInfo> {
    Some(SyscallInfo {
        arch: raw.arch,
        instruction_pointer: raw.instruction_pointer,
        stack_pointer: raw.stack_pointer,
        op: parse_raw_data(raw)?,
    })
}

pub(crate) fn ptrace_get_syscall_info(pid: Pid) -> nix::Result<Option<SyscallInfo>> {
    let mut info = MaybeUninit::<RawInfo>::uninit();

    let size_or_err = unsafe { libc::ptrace(PTRACE_GET_SYSCALL_INFO, pid, size_of::<RawInfo>(), info.as_mut_ptr()) };

    if size_or_err < 0 {
        return Err(nix::errno::Errno::from_raw(-size_or_err as i32));
    }
    let need_at_least_size: c_long = (size_of::<RawInfo>() - size_of::<RawData>()) as c_long;
    if size_or_err < need_at_least_size {
        return Ok(None);
    }

    let info = unsafe { info.assume_init() };
    // todo: handle size_or_err being even more weird (more than the header, less than the data)
    Ok(parse_raw_info(info))
}
