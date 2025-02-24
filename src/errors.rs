macro_rules! error_out {
    ($str:tt, $($arg:tt)*) => {{
        let program_name = std::env::args().next().unwrap_or_else(|| "procflamegraph".to_string());
        // Use a BufWriter to not split the error over many unneccessarily small write() syscalls
        writeln!(std::io::BufWriter::new(std::io::stderr()), concat!("{}: Error: ", $str), program_name, $($arg)*).ok();
        std::process::exit(1);
    }};
}
pub(crate) use error_out;
