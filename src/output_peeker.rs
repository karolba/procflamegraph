use crate::sys_linux::{epoll::epoll_wait,
                       fd::{close_two, read_to_maybe_uninit},
                       macros::eintr_repeat};
use EpollRegistration::{HasMessages, StderrReadReady, StderrWriteReady, StdoutReadReady, StdoutWriteReady};
use PidProcessInstanceState::{CurrentlyIntercepting, FinishedIntercepting, NotIntercepting};
use nix::{errno::Errno,
          fcntl::{F_SETFL, OFlag, SpliceFFlags, fcntl, tee},
          sys::{epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags},
                eventfd::{EfdFlags, EventFd}},
          unistd::Pid};
use std::{cell::RefCell,
          collections::HashMap,
          os::fd::{AsFd, OwnedFd},
          sync::{Arc, mpsc},
          thread,
          thread::JoinHandle};

#[derive(Debug)]
pub(crate) struct ChildPeekResult {
    pub(crate) stdout_data: Vec<Vec<u8>>,
    pub(crate) stderr_data: Vec<Vec<u8>>,
}

struct InterceptingStream {
    original_pipe:   OwnedFd,
    pipe_from_child: OwnedFd,
    captured_data:   Vec<u8>,
}

#[derive(Default)]
enum PidProcessInstanceState {
    #[default]
    NotIntercepting,
    CurrentlyIntercepting(InterceptingStream),
    FinishedIntercepting {
        captured_data: Vec<u8>,
    },
}

structstruck::strike! {
    #[derive(Default)]
    struct PidEntry {
        instances: Vec<#[derive(Default)] struct PidProcessInstance {
            stdout_state: PidProcessInstanceState,
            stderr_state: PidProcessInstanceState,
            visited_stdout_for_data_ready: bool,
            visited_stderr_for_data_ready: bool,
        }>,
        is_dead: bool,
    }
}

structstruck::strike! {
    enum OutputPeekerMessage {
        QueuedMessages(Vec<enum QueuedOutputPeekerMessage {
            ThreadExecved(Pid),
            ThreadDied(Pid),
        }>),
        StartPeekingStdout(pub(crate) struct StartPeekingStdout {
            pub(crate) pid:             Pid,
            pub(crate) original_stdout: OwnedFd,
            pub(crate) pipe_from_child: OwnedFd,
        }),
        StartPeekingStderr(pub(crate) struct StartPeekingStderr {
            pub(crate) pid:             Pid,
            pub(crate) original_stderr: OwnedFd,
            pub(crate) pipe_from_child: OwnedFd,
        }),
        End,
    }
}

pub(crate) struct OutputPeeker {
    sender:          mpsc::Sender<OutputPeekerMessage>,
    join_handle:     JoinHandle<HashMap<Pid, ChildPeekResult>>,
    sent_notif:      Arc<EventFd>,
    queued_messages: RefCell<Vec<QueuedOutputPeekerMessage>>,
}

#[derive(Copy, Clone, Debug)]
struct ThreadInstanceIndex(u32);
impl ThreadInstanceIndex {
    fn new(val: u32) -> ThreadInstanceIndex {
        if val > 0x3fff_ffffu32 {
            // so it fits in EpollRegistration
            panic!("ThreadInstanceIndex is too big"); // todo maybe just wrap around at this point
        }
        ThreadInstanceIndex(val)
    }
    fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

#[derive(Copy, Clone, Debug)]
enum EpollRegistration {
    HasMessages,
    StdoutReadReady(Pid, ThreadInstanceIndex),
    StdoutWriteReady(Pid, ThreadInstanceIndex),
    StderrReadReady(Pid, ThreadInstanceIndex),
    StderrWriteReady(Pid, ThreadInstanceIndex),
}

impl InterceptingStream {
    fn new(original_pipe: OwnedFd, pipe_from_child: OwnedFd) -> InterceptingStream {
        // todo: maybe even do this somewhere else before without a fcntl if possible?
        fcntl(&pipe_from_child, F_SETFL(OFlag::O_NONBLOCK)).expect("couldn't set pipe_from_child to O_NONBLOCK");
        fcntl(&original_pipe, F_SETFL(OFlag::O_NONBLOCK)).expect("couldn't set original_pipe to O_NONBLOCK");

        InterceptingStream {
            original_pipe,
            pipe_from_child,
            captured_data: vec![],
        }
    }

    fn register_epoll_write(&self, epoll: &Epoll, id: EpollRegistration) {
        epoll
            .add(self.pipe_from_child.as_fd(), EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLET, id.serialize()))
            .expect("couldn't add pipe_from_child to epoll");
    }

    fn register_epoll_read(&self, epoll: &Epoll, id: EpollRegistration) {
        epoll
            .add(self.original_pipe.as_fd(), EpollEvent::new(EpollFlags::EPOLLOUT | EpollFlags::EPOLLET, id.serialize()))
            .expect("couldn't add original_pipe to epoll");
    }

    fn deregister_epoll_write(&self, epoll: &Epoll) {
        epoll
            .delete(self.pipe_from_child.as_fd())
            .expect("Couldn't EPOLL_CTL_DEL pipe_from_child");
    }

    fn deregister_epoll_read(&self, epoll: &Epoll) {
        epoll
            .delete(self.original_pipe.as_fd())
            .expect("Couldn't EPOLL_CTL_DEL original_pipe");
    }

    fn data_ready(&mut self) {
        loop {
            match eintr_repeat!(tee(
                self.pipe_from_child.as_fd(),
                self.original_pipe.as_fd(),
                libc::INT_MAX as usize,
                SpliceFFlags::SPLICE_F_NONBLOCK
            )) {
                Ok(0) => return, // ?? is that correct?
                Ok(mut to_read) => {
                    self.captured_data.reserve(to_read);

                    // get all data
                    while to_read > 0 {
                        let read_num = eintr_repeat!(read_to_maybe_uninit(
                            self.pipe_from_child.as_fd(),
                            &mut self.captured_data.spare_capacity_mut()[..to_read]
                        ))
                        .expect("this shouldn't fail, todo better error message here");

                        assert_ne!(read_num, 0, "??? todo better error message");

                        to_read -= read_num;
                        unsafe {
                            self.captured_data
                                .set_len(self.captured_data.len() + read_num);
                        }
                    }
                }
                Err(Errno::EAGAIN) => return,
                other => {
                    other.expect("Couldn't tee");
                }
            }
        }
    }
}

impl PidEntry {
    fn has_pipes_open(&self) -> bool {
        // this is O(n), if that somehow ever shows up in profiles cache the first pid_process_instance that's doing CurrentlyIntercepting
        // and start searching from that next time it's called
        self.instances
            .iter()
            .rev()
            .any(|pid_process_instance| {
                matches!(pid_process_instance.stdout_state, CurrentlyIntercepting(..))
                    || matches!(pid_process_instance.stderr_state, CurrentlyIntercepting(..))
            })
    }
    fn are_we_done_with_it(&self) -> bool {
        self.is_dead && !self.has_pipes_open()
    }
    fn finalize(mut self) -> ChildPeekResult {
        ChildPeekResult {
            stdout_data: self
                .instances
                .iter_mut()
                .map(|instance| match std::mem::replace(&mut instance.stdout_state, NotIntercepting) {
                    FinishedIntercepting { captured_data } => captured_data,
                    NotIntercepting => vec![],
                    CurrentlyIntercepting(..) => {
                        panic!("Trying to finalize a stdout_PidProcessInstance that's still in a CurrentlyIntercepting state for stdout");
                    }
                })
                .collect(),
            stderr_data: self
                .instances
                .iter_mut()
                .map(|instance| match std::mem::replace(&mut instance.stderr_state, NotIntercepting) {
                    FinishedIntercepting { captured_data } => captured_data,
                    NotIntercepting => vec![],
                    CurrentlyIntercepting(..) => {
                        panic!("Trying to finalize a PidProcessInstance that's still in a CurrentlyIntercepting state for stderr");
                    }
                })
                .collect(),
        }
    }
}

// encode the EpollRegistration enum into a single u64 so that the linux epoll api can give it back to us
// todo, this is pretty tedious, is there a simple method to do it in a more readable way, like a bitfield?
impl EpollRegistration {
    /*
     * this is roughly what EpollRegistration serializes to:
     *
     * union SerializedEpollRegistration {
     *     enum { EVENTFD_MESSAGE = 0 } eventfd_message;
     *     struct {
     *         enum {
     *             STDOUT_READ_READY  = 0,
     *             STDOUT_WRITE_READY = 1,
     *             STDERR_READ_READY  = 2,
     *             STDERR_WRITE_READY = 3
     *         } : 2;
     *         uint32_t thread_instance_index : 30;
     *         uint32_t pid : 32;
     *     } data_event;
     * };
     *
     * The serialization uses the fact Pid 0 is always the kernel, and we can't (and wouldn't wanna) trace the kernel - so it's an invalid pid
     * value from the point of a tracer
     *
     * todo: assert somewhere pid != 0
     */

    fn serialize(self) -> u64 {
        match self {
            HasMessages => 0,
            StdoutReadReady(pid, ThreadInstanceIndex(index)) => (pid.as_raw() as u64) | ((index as u64) << 32),
            StdoutWriteReady(pid, ThreadInstanceIndex(index)) => (pid.as_raw() as u64) | ((index as u64) << 32) | (1u64 << 62),
            StderrReadReady(pid, ThreadInstanceIndex(index)) => (pid.as_raw() as u64) | ((index as u64) << 32) | (2u64 << 62),
            StderrWriteReady(pid, ThreadInstanceIndex(index)) => (pid.as_raw() as u64) | ((index as u64) << 32) | (3u64 << 62),
        }
    }

    fn deserialize(data: u64) -> EpollRegistration {
        if data == 0 {
            return HasMessages;
        }
        match (data & (3u64 << 62)) >> 62 {
            0 => StdoutReadReady(Pid::from_raw(data as i32), ThreadInstanceIndex::new(((data & 0x3fff_ffff_0000_0000u64) >> 32) as u32)),
            1 => StdoutWriteReady(Pid::from_raw(data as i32), ThreadInstanceIndex::new(((data & 0x3fff_ffff_0000_0000u64) >> 32) as u32)),
            2 => StderrReadReady(Pid::from_raw(data as i32), ThreadInstanceIndex::new(((data & 0x3fff_ffff_0000_0000u64) >> 32) as u32)),
            3 => StderrWriteReady(Pid::from_raw(data as i32), ThreadInstanceIndex::new(((data & 0x3fff_ffff_0000_0000u64) >> 32) as u32)),
            _ => unreachable!(),
        }
    }
}

enum Message {
    ThreadExecved(Pid),
    ThreadDied(Pid),
    StartPeekingStdout(StartPeekingStdout),
    StartPeekingStderr(StartPeekingStderr),
    End,
}
gen fn recv_messages(receiver: &mpsc::Receiver<OutputPeekerMessage>, new_child_notif: &EventFd) -> Message {
    for _ in 0..new_child_notif
        .read()
        .expect("couldn't read from an eventfd")
    {
        match receiver
            .recv()
            .expect("couldn't receive from mpsc::Receiver")
        {
            OutputPeekerMessage::QueuedMessages(messages) => {
                for queued_message in messages {
                    match queued_message {
                        QueuedOutputPeekerMessage::ThreadExecved(pid) => yield Message::ThreadExecved(pid),
                        QueuedOutputPeekerMessage::ThreadDied(pid) => yield Message::ThreadDied(pid),
                    }
                }
            }
            OutputPeekerMessage::StartPeekingStdout(start) => yield Message::StartPeekingStdout(start),
            OutputPeekerMessage::StartPeekingStderr(start) => yield Message::StartPeekingStderr(start),
            OutputPeekerMessage::End => yield Message::End,
        }
    }
}

fn peeker_thread(receiver: mpsc::Receiver<OutputPeekerMessage>, new_child_notif: Arc<EventFd>) -> HashMap<Pid, ChildPeekResult> {
    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).expect("couldn't epoll_create");

    epoll
        .add(&new_child_notif, EpollEvent::new(EpollFlags::EPOLLIN, HasMessages.serialize()))
        .expect("couldn't epoll_ctl(epoll, EPOLL_CTL_ADD) for an eventfd");

    let mut children: HashMap<Pid, PidEntry> = HashMap::new();
    let mut ending = false;
    let mut result: HashMap<Pid, ChildPeekResult> = HashMap::new();
    let mut events_buf = [EpollEvent::empty(); 32];

    while !(ending && children.is_empty()) {
        let num_events = epoll_wait(&epoll, &mut events_buf);
        let events = || {
            events_buf[..num_events]
                .iter()
                .map(|epoll_event: &EpollEvent| (EpollRegistration::deserialize(epoll_event.data()), epoll_event.events()))
        };

        for (event, flags) in events() {
            if matches!(event, HasMessages) {
                for message in recv_messages(&receiver, new_child_notif.as_ref()) {
                    match message {
                        Message::StartPeekingStdout(StartPeekingStdout {
                            pid,
                            original_stdout,
                            pipe_from_child,
                        }) => {
                            let pid_entry = children.get_mut(&pid).unwrap();
                            let instance = InterceptingStream::new(original_stdout, pipe_from_child);
                            let index = ThreadInstanceIndex::new(
                                (pid_entry.instances.len() - 1)
                                    .try_into()
                                    .unwrap(),
                            );
                            instance.register_epoll_read(&epoll, StdoutReadReady(pid, index));
                            instance.register_epoll_write(&epoll, StdoutWriteReady(pid, index));
                            // last_mut() cause it has to already exist, we must've received a ThreadExecved already
                            pid_entry
                                .instances
                                .last_mut()
                                .unwrap()
                                .stdout_state = CurrentlyIntercepting(instance);
                        }
                        Message::StartPeekingStderr(StartPeekingStderr {
                            pid,
                            original_stderr,
                            pipe_from_child,
                        }) => {
                            let pid_entry = children.get_mut(&pid).unwrap();
                            let instance = InterceptingStream::new(original_stderr, pipe_from_child);
                            let index = ThreadInstanceIndex::new(
                                (pid_entry.instances.len() - 1)
                                    .try_into()
                                    .unwrap(),
                            );
                            instance.register_epoll_read(&epoll, StderrReadReady(pid, index));
                            instance.register_epoll_write(&epoll, StderrWriteReady(pid, index));
                            // last_mut() cause it has to already exist, we must've received a ThreadExecved already
                            pid_entry
                                .instances
                                .last_mut()
                                .unwrap()
                                .stderr_state = CurrentlyIntercepting(instance);
                        }
                        Message::ThreadExecved(pid) => {
                            // either a completely new thread did its first execve, becoming alive
                            // or an already exiting one reexeced
                            children
                                .entry(pid)
                                .or_insert_with(|| PidEntry::default())
                                .instances
                                .push(PidProcessInstance::default());
                        }
                        Message::ThreadDied(pid) => {
                            if let Some(child) = children.get_mut(&pid) {
                                child.is_dead = true;
                                if child.are_we_done_with_it() {
                                    result.insert(
                                        pid,
                                        children
                                            .remove(&pid)
                                            .unwrap()
                                            .finalize(),
                                    );
                                }
                            }
                        }
                        Message::End => {
                            ending = true;
                        }
                    }
                }
            }

            if let StdoutReadReady(pid, instance_index) | StdoutWriteReady(pid, instance_index) = event
                && flags.intersects(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT)
                && let Some(pid_entry) = children.get_mut(&pid)
                && let Some(instance) = pid_entry
                    .instances
                    .get_mut(instance_index.as_usize())
            {
                match (instance.visited_stdout_for_data_ready, &mut instance.stdout_state) {
                    (true, CurrentlyIntercepting(..)) => {
                        // seen it this iteration
                    }
                    (false, CurrentlyIntercepting(intercepting)) => {
                        intercepting.data_ready();
                        instance.visited_stdout_for_data_ready = true;
                    }
                    (_, NotIntercepting) => {
                        panic!("Received EPOLLIN or EPOLLOUT on a child's stdout that wasn't being intercepted");
                    }
                    (_, FinishedIntercepting { .. }) => {
                        panic!("Received EPOLLIN or EPOLLOUT on a child's stdout that has already been finished");
                    }
                }
            }

            if let StderrReadReady(pid, instance_index) | StderrWriteReady(pid, instance_index) = event
                && flags.intersects(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT)
                && let Some(pid_entry) = children.get_mut(&pid)
                && let Some(instance) = pid_entry
                    .instances
                    .get_mut(instance_index.as_usize())
            {
                match (instance.visited_stderr_for_data_ready, &mut instance.stderr_state) {
                    (true, CurrentlyIntercepting(..)) => {
                        // seen it this iteration
                    }
                    (false, CurrentlyIntercepting(intercepting)) => {
                        intercepting.data_ready();
                        instance.visited_stderr_for_data_ready = true;
                    }
                    (_, NotIntercepting) => {
                        panic!("Received EPOLLIN or EPOLLOUT on a child's stderr that wasn't being intercepted");
                    }
                    (_, FinishedIntercepting { .. }) => {
                        panic!("Received EPOLLIN or EPOLLOUT on a child's stderr that has already been finished");
                    }
                }
            }
        }

        // reset them so they can be visited again in the next epoll loop
        for (event, flags) in events() {
            if let StdoutReadReady(pid, instance_index) | StdoutWriteReady(pid, instance_index) = event
                && flags.intersects(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT)
                && let Some(pid_entry) = children.get_mut(&pid)
                && let Some(instance) = pid_entry
                    .instances
                    .get_mut(instance_index.as_usize())
            {
                instance.visited_stdout_for_data_ready = false;
            }

            if let StderrReadReady(pid, instance_index) | StderrWriteReady(pid, instance_index) = event
                && flags.intersects(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT)
                && let Some(pid_entry) = children.get_mut(&pid)
                && let Some(instance) = pid_entry
                    .instances
                    .get_mut(instance_index.as_usize())
            {
                instance.visited_stderr_for_data_ready = false;
            }
        }

        // handle closing/erroring out only when everything was already read
        for (event, flags) in events() {
            if flags.intersects(EpollFlags::EPOLLHUP | EpollFlags::EPOLLERR)
               && let StdoutReadReady(pid, instance_index) | StdoutWriteReady(pid, instance_index) = event
               && let Some(pid_entry) = children.get_mut(&pid)
               && let Some(instance) = pid_entry.instances.get_mut(instance_index.as_usize())
               && matches!(instance.stdout_state, CurrentlyIntercepting(_)) // make sure that is really the type before replacing it
               && let CurrentlyIntercepting(intercepting) = std::mem::replace(&mut instance.stdout_state, NotIntercepting)
            {
                intercepting.deregister_epoll_read(&epoll);
                intercepting.deregister_epoll_write(&epoll);

                // try to close them in a single syscall if possible
                close_two(intercepting.pipe_from_child, intercepting.original_pipe);

                instance.stdout_state = FinishedIntercepting {
                    captured_data: intercepting.captured_data,
                };

                if pid_entry.are_we_done_with_it() {
                    result.insert(
                        pid,
                        children
                            .remove(&pid)
                            .unwrap()
                            .finalize(),
                    );
                }
            }

            if flags.intersects(EpollFlags::EPOLLHUP | EpollFlags::EPOLLERR)
               && let StderrReadReady(pid, instance_index) | StderrWriteReady(pid, instance_index) = event
               && let Some(pid_entry) = children.get_mut(&pid)
               && let Some(instance) = pid_entry.instances.get_mut(instance_index.as_usize())
               && matches!(instance.stderr_state, CurrentlyIntercepting(_)) // make sure that is really the type before replacing it
               && let CurrentlyIntercepting(intercepting) = std::mem::replace(&mut instance.stderr_state, NotIntercepting)
            {
                intercepting.deregister_epoll_read(&epoll);
                intercepting.deregister_epoll_write(&epoll);

                // try to close them in a single syscall if possible
                close_two(intercepting.pipe_from_child, intercepting.original_pipe);

                instance.stderr_state = FinishedIntercepting {
                    captured_data: intercepting.captured_data,
                };

                if pid_entry.are_we_done_with_it() {
                    result.insert(
                        pid,
                        children
                            .remove(&pid)
                            .unwrap()
                            .finalize(),
                    );
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
            .name("output-collector".to_owned())
            .spawn(|| peeker_thread(receiver, efd_arg))
            .expect("failed to spawn thread");

        OutputPeeker {
            sender,
            join_handle,
            sent_notif: efd,
            queued_messages: RefCell::new(vec![]),
        }
    }

    fn send(&self, message: OutputPeekerMessage) {
        if self.queued_messages.borrow().is_empty() {
            self.sender.send(message).unwrap();
            self.sent_notif
                .write(1)
                .expect("couldn't write to eventfd");
        } else {
            let queued_messages = OutputPeekerMessage::QueuedMessages(self.queued_messages.replace(vec![]));
            self.sender
                .send(queued_messages)
                .unwrap();
            self.sender.send(message).unwrap();
            self.sent_notif
                .write(2)
                .expect("couldn't write to eventfd");
        }
    }

    pub(crate) fn execve_happened(&self, pid: Pid) {
        // there's no hurry to inform the other thread and doing so results in 3 syscalls, so let's
        // buffer that
        self.queued_messages
            .borrow_mut()
            .push(QueuedOutputPeekerMessage::ThreadExecved(pid));
    }

    pub(crate) fn thread_died(&self, pid: Pid) {
        // there's no hurry to inform the other thread and doing so results in 3 syscalls, so let's
        // buffer that
        self.queued_messages
            .borrow_mut()
            .push(QueuedOutputPeekerMessage::ThreadDied(pid));
    }

    pub(crate) fn start_peeking_child_stderr(&self, new_child: StartPeekingStderr) {
        self.send(OutputPeekerMessage::StartPeekingStderr(new_child));
    }

    pub(crate) fn start_peeking_child_stdout(&self, new_child: StartPeekingStdout) {
        self.send(OutputPeekerMessage::StartPeekingStdout(new_child));
    }

    pub(crate) fn result(self) -> HashMap<Pid, ChildPeekResult> {
        self.send(OutputPeekerMessage::End);
        self.join_handle
            .join()
            .expect("couldn't join thread 'output-collector'")
    }
}
