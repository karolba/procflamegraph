// A very minimalistic coroutine library based on experimental `gen` blocks and functions

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
pub(crate) enum CoroutineState<Yield, Return> {
    Yielded(Yield),
    Complete(Return),
}

// Equivalent to python's `yield from` syntax
macro_rules! co_yield_from {
    ($e:expr) => {{
        let mut generator = $e;
        loop {
            match generator.next() {
                Some(CoroutineState::Complete(x)) => break x,
                Some(CoroutineState::Yielded(x)) => yield CoroutineState::Yielded(x),
                None => panic!("Tried to co_yield_from!() a finished coroutine"),
            }
        }
    }};
}
pub(crate) use co_yield_from;

macro_rules! co_yield {
    ($e:expr) => {
        yield CoroutineState::Yielded($e)
    };
}
pub(crate) use co_yield;

macro_rules! co_return {
    ($e:expr) => {
        return yield CoroutineState::Complete($e)
    };
}
pub(crate) use co_return;

macro_rules! co_try {
    ($e:expr) => {
        match $e {
            Result::Ok(val) => val,
            Result::Err(err) => co_return!(Result::Err(std::convert::From::from(err))),
        }
    };
}
pub(crate) use co_try;
