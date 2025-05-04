macro_rules! error_out {
    ($str:tt) => {{
        use std::io::Write;
        // Use a BufWriter to not split the error over many unneccessarily small write() syscalls
        writeln!(std::io::BufWriter::new(std::io::stderr()), concat!("{}: Error: ", $str), args().our_name).ok();
        std::process::exit(1);
    }};
    ($str:tt, $($arg:tt)*) => {{
        use std::io::Write;
        // Use a BufWriter to not split the error over many unneccessarily small write() syscalls
        writeln!(std::io::BufWriter::new(std::io::stderr()), concat!("{}: Error: ", $str), args().our_name, $($arg)*).ok();
        std::process::exit(1);
    }};
}
pub(crate) use error_out;

macro_rules! log_warn {
    ($str:tt) => {{
        use std::io::Write;
        // Use a BufWriter to not split the warning over many unneccessarily small write() syscalls
        writeln!(std::io::BufWriter::new(std::io::stderr()), concat!("{}: Warning: ", $str), args().our_name).ok();
    }};
    ($str:tt, $($arg:tt)*) => {{
        use std::io::Write;
        // Use a BufWriter to not split the warning over many unneccessarily small write() syscalls
        writeln!(std::io::BufWriter::new(std::io::stderr()), concat!("{}: Warning: ", $str), args().our_name, $($arg)*).ok();
    }};
}
pub(crate) use log_warn;
