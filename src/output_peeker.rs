use std::thread;
use std::collections::HashMap;
use std::sync::{Arc, mpsc};
use std::os::fd::{AsRawFd, OwnedFd};
use nix::unistd::Pid;
use nix::fcntl::{fcntl, tee, F_SETFL, OFlag, SpliceFFlags};
use nix::errno::Errno;
use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollOp, EpollTimeout, EpollTimeoutTryFromError};
use nix::sys::eventfd::{EventFd, EfdFlags};
use nix::sys::signal::SigSet;

#[derive(Debug)]
pub(crate) struct NewChild {
    pub(crate) pid: Pid,
    pub(crate) original_stderr: OwnedFd,
    pub(crate) pipe_from_child: OwnedFd,
}

struct Child {
    pid: Pid,
    original_stderr: OwnedFd,
    pipe_from_child: OwnedFd,
}

#[derive(Copy, Clone, Debug)]
enum EpollRegistration {
    NewChildNotif,
    Pid(Pid),
}

impl EpollRegistration {
    fn serialize(self) -> u64 {
        match self {
            EpollRegistration::NewChildNotif => u64::MAX,
            EpollRegistration::Pid(pid) => pid.as_raw() as u64,
        }
    }

    fn deserialize(data: u64) -> EpollRegistration {
        match data {
            u64::MAX => EpollRegistration::NewChildNotif,
            pid => EpollRegistration::Pid(Pid::from_raw(pid as i32)),
        }
    }
}

fn epoll_wait(epoll: &Epoll, events: &mut [EpollEvent]) -> usize {
    const NO_TIMEOUT: libc::c_int = -1;

    loop {
        let res = Errno::result(unsafe { libc::epoll_pwait(
            epoll.0.as_raw_fd(),
            events.as_mut_ptr().cast(),
            events.len() as libc::c_int,
            NO_TIMEOUT,
            SigSet::all().as_ref(),
        ) }).map(|r| r as usize);

        match res {
            Err(Errno::EINTR) => continue,
            ret => return ret.expect("couldn't epoll_wait"),
        }
    }
}

fn peeker_thread(receiver: mpsc::Receiver<NewChild>, new_child_notif: Arc<EventFd>) {
    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).expect("couldn't epoll_create");

    epoll
        .add(&new_child_notif, EpollEvent::new(EpollFlags::EPOLLIN, EpollRegistration::NewChildNotif.serialize()))
        .expect("couldn't epoll_ctl(epoll, EPOLL_CTL_ADD) for an eventfd");

    let mut children: HashMap<Pid, Child> = HashMap::new();
    let mut events = [EpollEvent::empty(); 32];

    loop {
        let num_events = epoll_wait(&epoll, &mut events);
        for event in events[..num_events].iter() {
            match (EpollRegistration::deserialize(event.data()), event.events()) {
                (EpollRegistration::NewChildNotif, EpollFlags::EPOLLIN) => {
                    let num_new_children = (&new_child_notif).read().expect("couldn't read from an eventfd");
                    for _ in 0..num_new_children {
                        let new_child = receiver.recv().expect("couldn't receive a NewChild from mpsc::Receiver");

                        // todo: maybe even do this somewhere else before without a fcntl if possible?
                        fcntl(&new_child.pipe_from_child, F_SETFL(OFlag::O_NONBLOCK))
                            .expect("couldn't set pipe_from_child to O_NONBLOCK");

                        epoll.add(&new_child.pipe_from_child, EpollEvent::new(EpollFlags::EPOLLIN, EpollRegistration::Pid(new_child.pid).serialize()))
                            .expect("couldn't add pipe_from_child to epoll");

                        children.insert(new_child.pid, Child {
                            pid: new_child.pid,
                            original_stderr: new_child.original_stderr,
                            pipe_from_child: new_child.pipe_from_child,
                        });
                    }
                }
                (a, b) => { dbg!(a, b); }
            }
        }
    }
}

//for new_child in receiver.try_iter() {
    // tee doesn't need it if it has SPLICE_F_NONBLOCK
    //fcntl(&val.original_stderr, F_SETFL(OFlag::O_NONBLOCK)).expect("couldn't set original_stderr to O_NONBLOCK");
    //fcntl(&val.pipe_from_child, F_SETFL(OFlag::O_NONBLOCK)).expect("couldn't set pipe_from_child to O_NONBLOCK");

    //loop {
        //let size = match tee(&val.pipe_from_child, &val.original_stderr, libc::INT_MAX as usize, SpliceFFlags::SPLICE_F_NONBLOCK) {
            //Ok(size) => size,
            //Err(Errno::EAGAIN) => continue,
            //Err(err) => Err(err).expect("todo"),
        //};
        //dbg!(size);
    //}
//}

pub(crate) struct OutputPeeker {
    sender: mpsc::Sender<NewChild>,
    sent_notif: Arc<EventFd>,
}

/*
 * TODO: wait for stderr and stdout stolen from our immiediate child to close
 * or else this is racy as hell - the child can die while the kernel still
 * has stuff in pipe buffers
 */
impl OutputPeeker {
    pub(crate) fn new() -> OutputPeeker {
        let (sender, receiver) = mpsc::channel::<NewChild>();
        let efd = Arc::new(EventFd::from_flags(EfdFlags::EFD_CLOEXEC).expect("couldn't create an eventfd"));

        let efd_arg = Arc::clone(&efd);
        thread::Builder::new()
            .name("stderr-collector".to_string())
            .spawn(move || peeker_thread(receiver, efd_arg))
            .expect("failed to spawn thread");

        OutputPeeker{
            sender: sender,
            sent_notif: efd,
        }
    }

    pub(crate) fn send(&self, new_child: NewChild) {
        self.sender.send(new_child).expect("couldn't send to the OutputPeeker thread");
        self.sent_notif.write(1).expect("couldn't write to eventfd");
    }
}
