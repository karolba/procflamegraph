use crate::sys_linux::{proc::process_stat,
                       ptrace_syscall_info::{SyscallEntry, SyscallInfo, ptrace_get_syscall_info}};
use nix::errno::Errno;
use std::os::fd::OwnedFd;

#[derive(Clone, Copy)]
pub(crate) struct Tracee {
    pub(crate) pid: nix::unistd::Pid,
}

pub(crate) struct ArgvEnvpAddrs {
    pub(crate) argv_start: u64,
    pub(crate) argv_end:   u64,
    pub(crate) envp_start: u64,
    pub(crate) envp_end:   u64,
}

pub(crate) enum PokeResult {
    Ok,
    PidIsDead,
    Err(nix::Error),
}

#[cfg(target_arch = "aarch64")]
// https://github.com/torvalds/linux/blob/05dbaf8dd8bf537d4b4eb3115ab42a5fb40ff1f5/arch/arm64/kernel/ptrace.c#L1638
const NT_ARM_SYSTEM_CALL: libc::c_long = 0x404;

impl Tracee {
    pub(crate) fn from(pid: nix::unistd::Pid) -> Tracee {
        Tracee { pid }
    }

    fn poke_writev(self, memory: &[u64], address: usize) -> nix::Result<usize> {
        let u8_slice = bytemuck::cast_slice::<u64, u8>(memory);
        let from = std::io::IoSlice::new(u8_slice);
        let to = nix::sys::uio::RemoteIoVec { base: address, len: u8_slice.len() };
        nix::sys::uio::process_vm_writev(self.pid, &[from], &[to])
    }

    fn poke_ptrace(self, memory: &[u64], address: usize) -> PokeResult {
        use nix::errno::Errno::{EINVAL, ESRCH};

        for (i, word) in memory.iter().enumerate() {
            let word_addr = address + (i * size_of::<usize>());
            match nix::sys::ptrace::write(self.pid, word_addr as *mut libc::c_void, *word as libc::c_long) {
                Ok(()) => (),
                Err(ESRCH | EINVAL) => return PokeResult::PidIsDead,
                Err(err) => return PokeResult::Err(err),
            }
        }
        PokeResult::Ok
    }

    pub(crate) fn poke(self, memory: &[u64], address: usize) -> PokeResult {
        use nix::errno::Errno::{EFAULT, EIO, ENOSYS, EPERM, ESRCH};

        match self.poke_writev(memory, address) {
            // everything is alright
            Ok(result) if result == std::mem::size_of_val(memory) => PokeResult::Ok,
            // partial write, doesn't usually happen, strace ignores and logs it
            Ok(_) => self.poke_ptrace(memory, address),
            // process_vm_writev is unavailable for us
            Err(ENOSYS | EPERM) => self.poke_ptrace(memory, address),
            // process_vm_writev is available but write failed for some reason:
            Err(EFAULT | EIO) => self.poke_ptrace(memory, address),
            // The process is dead
            Err(ESRCH) => PokeResult::PidIsDead,
            // Something else failed
            Err(another_error) => PokeResult::Err(another_error),
        }
    }

    // Copied from https://github.com/coord-e/magicpak/blob/19b8e0db28bb1eb7959e38bf2273be02ab1cdb03/src/base/trace.rs#L160-L174
    pub(crate) fn getregset(self) -> Result<libc::user_regs_struct, Errno> {
        let mut data = std::mem::MaybeUninit::<libc::user_regs_struct>::uninit();

        // ptrace can (and will) modify this iovec, has to be mut
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr() as *mut libc::c_void,
            iov_len:  size_of::<libc::user_regs_struct>(),
        };

        let res = unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGSET,
                self.pid,
                libc::NT_PRSTATUS,
                &mut iov as *mut libc::iovec, // ptrace() can modify this iovec
            )
        };
        Errno::result(res)?;

        Ok(unsafe { data.assume_init() })
    }

    fn setregset(self, mut regset: libc::user_regs_struct) -> nix::Result<()> {
        let mut iov = libc::iovec {
            iov_base: &mut regset as *mut libc::user_regs_struct as *mut libc::c_void,
            iov_len:  size_of::<libc::user_regs_struct>(),
        };

        let res = unsafe { libc::ptrace(libc::PTRACE_SETREGSET, self.pid, libc::NT_PRSTATUS, &mut iov as *mut libc::iovec) };

        Errno::result(res)?;
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn setsyscall(self, syscall: libc::c_int) -> nix::Result<()> {
        let mut iov = libc::iovec {
            iov_base: &syscall as *const libc::c_int as *mut libc::c_void,
            iov_len:  size_of::<libc::c_int>(),
        };

        let res = unsafe { libc::ptrace(libc::PTRACE_SETREGSET, self.pid, NT_ARM_SYSTEM_CALL, &mut iov as *mut libc::iovec) };

        Errno::result(res)?;
        Ok(())
    }

    pub(crate) fn argv_envp_addrs(self) -> Result<(Option<ArgvEnvpAddrs>, OwnedFd), Errno> {
        use bstr::ByteSlice;

        let (bytes, fd) = process_stat(self.pid)?;

        let after_rparen_idx: usize = match bytes.rfind_byte(b')') {
            Some(x) => x + 2,
            None => return Ok((None, fd)),
        };
        let addrs: Vec<u64> = {
            bytes[after_rparen_idx..]
                .split(|b| *b == b' ')
                .skip(45)
                .take(4)
                .map(|part: &[u8]| std::str::from_utf8(part).unwrap_or("")) // todo: don't unwrap like that
                .map(|part: &str| u64::from_str_radix(part, 10).unwrap_or(0)) // todo: don't unwrap like that, use an option
                .collect()
        };

        Ok((
            Some(ArgvEnvpAddrs {
                argv_start: addrs[0],
                argv_end:   addrs[1],
                envp_start: addrs[2],
                envp_end:   addrs[3],
            }),
            fd,
        ))
    }

    pub(crate) fn syscall_info(self) -> nix::Result<Option<SyscallInfo>> {
        ptrace_get_syscall_info(self.pid)
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn set_syscall_arg_regs(self, base_regset: libc::user_regs_struct, syscall: SyscallEntry) -> nix::Result<()> {
        let mut call_regset = base_regset;
        call_regset.rdi = syscall.args[0];
        call_regset.rsi = syscall.args[1];
        call_regset.rdx = syscall.args[2];
        call_regset.r10 = syscall.args[3];
        call_regset.r8 = syscall.args[4];
        call_regset.r9 = syscall.args[5];
        call_regset.orig_rax = syscall.nr;

        self.setregset(call_regset)?;

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn set_syscall_arg_regs(self, base_regset: libc::user_regs_struct, syscall: SyscallEntry) -> nix::Result<()> {
        let mut call_regset = base_regset;
        call_regset.regs[0] = syscall.args[0] as libc::c_ulonglong;
        call_regset.regs[1] = syscall.args[1] as libc::c_ulonglong;
        call_regset.regs[2] = syscall.args[2] as libc::c_ulonglong;
        call_regset.regs[3] = syscall.args[3] as libc::c_ulonglong;
        call_regset.regs[4] = syscall.args[4] as libc::c_ulonglong;
        call_regset.regs[5] = syscall.args[5] as libc::c_ulonglong;

        self.setregset(call_regset)?;
        self.setsyscall(syscall.nr as libc::c_int)?;

        Ok(())
    }
}
