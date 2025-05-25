use bstr::ByteVec;
use std::{
    thread,
    collections::HashMap,
    sync::{Arc, mpsc},
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    vec::Splice
};
use std::thread::JoinHandle;
use nix::{
    unistd::{fpathconf, read, write, Pid, SysconfVar},
    fcntl::{fcntl, tee, F_SETFL, OFlag, SpliceFFlags},
    errno::Errno,
    sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollOp, EpollTimeout, EpollTimeoutTryFromError},
    sys::eventfd::{EventFd, EfdFlags},
    sys::signal::SigSet
};
use crate::{errors, sys_linux};
use crate::sys_linux::eintr_repeat;
use crate::sys_linux::epoll_wait;

// https://elixir.bootlin.com/linux/v6.14.6/source/include/uapi/linux/limits.h#L14
// #define PIPE_BUF        4096	/* # bytes in atomic write to a pipe */
const PIPE_BUF: usize = 4096;

#[derive(Debug)]
pub(crate) struct NewChild {
    pub(crate) pid: Pid,
    pub(crate) original_stderr: OwnedFd,
    pub(crate) pipe_from_child: OwnedFd,
}

#[derive(Debug)]
pub(crate) struct ChildPeekResult {
    // pub(crate) data: Vec<u8>,
    pub(crate) data: String,
}

struct Child {
    pid: Pid,
    // todo: those shouldn't really be optional, let the object be destroyed and just move the vec out when closing
    original_stderr: OwnedFd,
    pipe_from_child: OwnedFd,
    captured_data: Vec<u8>
}

enum OutputPeekerMessage {
    NewChild(NewChild),
    End
}
pub(crate) struct OutputPeeker {
    sender: mpsc::Sender<OutputPeekerMessage>,
    join_handle: JoinHandle<HashMap<Pid, ChildPeekResult>>,
    sent_notif: Arc<EventFd>,
}

#[derive(Copy, Clone, Debug)]
enum EpollRegistration {
    HasMessages,
    ReadReady(Pid),
    WriteReady(Pid),
}

impl Child {
    fn new_with_epoll_registration(epoll: &Epoll, pid: Pid, original_stderr: OwnedFd, pipe_from_child: OwnedFd) -> Child {
        // todo: maybe even do this somewhere else before without a fcntl if possible?
        fcntl(&pipe_from_child, F_SETFL(OFlag::O_NONBLOCK))
            .expect("couldn't set pipe_from_child to O_NONBLOCK");
        fcntl(&original_stderr, F_SETFL(OFlag::O_NONBLOCK))
            .expect("couldn't set original_stderr to O_NONBLOCK");

        epoll.add(&pipe_from_child, EpollEvent::new(
            EpollFlags::EPOLLIN | EpollFlags::EPOLLET,
            EpollRegistration::ReadReady(pid).serialize()
        )).expect("couldn't add pipe_from_child to epoll");

        epoll.add(&original_stderr, EpollEvent::new(
            EpollFlags::EPOLLOUT | EpollFlags::EPOLLET,
            EpollRegistration::WriteReady(pid).serialize()
        )).expect("couldn't add original_stderr to epoll");

        Child {
            pid,
            original_stderr: original_stderr,
            pipe_from_child: pipe_from_child,
            captured_data: vec![],
        }
    }
    fn data_ready(&mut self) {
        loop {
            match eintr_repeat!(tee(
                self.pipe_from_child.as_fd(),
                self.original_stderr.as_fd(),
                libc::INT_MAX as usize,
                SpliceFFlags::SPLICE_F_NONBLOCK
            )) {
                Ok(0) => return, // ?? is that correct?
                Ok(mut to_read) => {
                    self.captured_data.reserve(to_read);

                    // get all data
                    while to_read > 0 {
                        let read_num = eintr_repeat!(sys_linux::read_to_maybe_uninit(
                            self.pipe_from_child.as_fd(),
                            &mut self.captured_data.spare_capacity_mut()[..to_read],
                        )).expect("this shouldn't fail");

                        assert_ne!(read_num, 0, "???");

                        to_read -= read_num;
                        unsafe { self.captured_data.set_len(self.captured_data.len() + read_num); }
                    }
                }
                Err(Errno::EAGAIN) => return,
                other => { other.expect("Couldn't tee"); }
            }
        }
    }
}

impl EpollRegistration {
    fn serialize(self) -> u64 {
        match self {
            EpollRegistration::HasMessages => u64::MAX,
            EpollRegistration::ReadReady(pid) => pid.as_raw() as u64,
            EpollRegistration::WriteReady(pid) => pid.as_raw() as u64 | (1u64 << 32),
        }
    }

    fn deserialize(data: u64) -> EpollRegistration {
        match data {
            u64::MAX => EpollRegistration::HasMessages,
            data => {
                if (data & (1u64 << 32)) == 0 {
                    EpollRegistration::ReadReady(Pid::from_raw(data as i32))
                } else {
                    EpollRegistration::WriteReady(Pid::from_raw(data as i32))
                }
            }
        }
    }
}


fn peeker_thread(receiver: mpsc::Receiver<OutputPeekerMessage>, new_child_notif: Arc<EventFd>) -> HashMap<Pid, ChildPeekResult> {
    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).expect("couldn't epoll_create");

    epoll
        .add(&new_child_notif, EpollEvent::new(EpollFlags::EPOLLIN, EpollRegistration::HasMessages.serialize()))
        .expect("couldn't epoll_ctl(epoll, EPOLL_CTL_ADD) for an eventfd");

    struct ChildEntry {
        child: Child,
        visited_for_data_ready: bool,
    }
    let mut children: HashMap<Pid, ChildEntry> = HashMap::new();
    let mut ending = false;
    let mut result: HashMap<Pid, ChildPeekResult> = HashMap::new();
    let mut events = [EpollEvent::empty(); 32];

    loop {
        if ending && children.is_empty() {
            break;
        }

        let num_events = epoll_wait(&epoll, &mut events);
        for event in events[..num_events].iter() {
            let flags = event.events();
            match EpollRegistration::deserialize(event.data()) {
                EpollRegistration::HasMessages => {
                    for _ in 0..new_child_notif.read().expect("couldn't read from an eventfd") {
                        match receiver.recv().expect("couldn't receive a NewChild from mpsc::Receiver") {
                            OutputPeekerMessage::NewChild(NewChild { pid, original_stderr, pipe_from_child }) => {
                                children.insert(pid, ChildEntry {
                                    child: Child::new_with_epoll_registration(&epoll, pid, original_stderr, pipe_from_child),
                                    visited_for_data_ready: false,
                                });
                            }
                            OutputPeekerMessage::End => {
                                ending = true;
                            }
                        }
                    }
                }
                EpollRegistration::ReadReady(pid) | EpollRegistration::WriteReady(pid) => {
                    let child_entry = children.get_mut(&pid).unwrap();

                    if flags.intersects(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT) {
                        if !child_entry.visited_for_data_ready {
                            child_entry.child.data_ready();
                            child_entry.visited_for_data_ready = true;
                        }
                    }
                }
            }
        }

        // reset them so they can be visited again in the next epoll loop
        for event in events[..num_events].iter() {
            match EpollRegistration::deserialize(event.data()) {
                EpollRegistration::HasMessages => {}
                EpollRegistration::ReadReady(pid) | EpollRegistration::WriteReady(pid) => {
                    let child = children.get_mut(&pid).unwrap();
                    child.visited_for_data_ready = false;
                }
            }
        }

        // handle closing/erroring out if everything was already read
        // todo: maybe it doesn't even need to be in its own loop?
        for event in events[..num_events].iter() {
            let flags = event.events();
            match EpollRegistration::deserialize(event.data()) {
                EpollRegistration::HasMessages => {}
                EpollRegistration::ReadReady(pid) | EpollRegistration::WriteReady(pid) => {
                    if flags.intersects(EpollFlags::EPOLLHUP | EpollFlags::EPOLLERR) {
                        match children.remove(&pid) {
                            None => { /* probably already removed it in the same iteration already */ }
                            Some(ChildEntry{child, ..}) => {
                                epoll.delete(child.pipe_from_child.as_fd())
                                    .expect("Couldn't EPOLL_CTL_DEL a pipe_from_child");

                                epoll.delete(child.original_stderr.as_fd())
                                    .expect("Couldn't EPOLL_CTL_DEL original_stderr");

                                result.insert(pid, ChildPeekResult{
                                    data: child.captured_data.into_string_lossy()
                                });

                                // try to close them in a single syscall if possible
                                sys_linux::close_two(child.pipe_from_child, child.original_stderr);
                            }
                        }
                    }
                }
            }
        }
    }

    result
}

impl OutputPeeker {
    pub(crate) fn new() -> OutputPeeker {
        let (sender, receiver) = mpsc::channel::<OutputPeekerMessage>();
        let efd = Arc::new(EventFd::from_flags(EfdFlags::EFD_CLOEXEC).expect("couldn't create an eventfd"));

        let efd_arg = Arc::clone(&efd);
        let join_handle = thread::Builder::new()
            .name("stderr-collector".to_string())
            .spawn(move || peeker_thread(receiver, efd_arg))
            .expect("failed to spawn thread");

        OutputPeeker{
            sender: sender,
            join_handle,
            sent_notif: efd,
        }
    }

    pub(crate) fn send(&self, new_child: NewChild) {
        self.sender.send(OutputPeekerMessage::NewChild(new_child)).expect("couldn't send to the OutputPeeker thread");
        self.sent_notif.write(1).expect("couldn't write to eventfd");
    }

    pub(crate) fn finish(&self) {
        self.sender.send(OutputPeekerMessage::End).expect("couldn't send to the OutputPeeker thread");
        self.sent_notif.write(1).expect("couldn't write to eventfd");
    }

    pub(crate) fn result(self) -> HashMap<Pid, ChildPeekResult> {
        self.join_handle.join().expect("couldn't join thread 'stderr-collector'")
    }
}
