macro_rules! eintr_repeat {
    ($e:expr) => {
        loop {
            break match $e {
                Err(nix::errno::Errno::EINTR) => continue,
                result => result,
            }
        }
    }
}
pub(crate) use eintr_repeat;
