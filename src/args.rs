use std::ffi::OsString;
use std::io::Write;

pub(crate) struct Args {
    pub(crate) our_name: String,
    pub(crate) output_file: Option<OsString>,
    pub(crate) command: Vec<OsString>,
    pub(crate) display_pids: bool,
    pub(crate) display_times: bool,
    pub(crate) display_threads: bool,
    pub(crate) test_always_detach: bool,
    pub(crate) capture_stderr: bool,
    pub(crate) reexec_ptraceme: bool,
}

impl Args {
    fn default() -> Args {
        Args {
            our_name: String::new(),
            output_file: None,
            command: vec![],
            display_pids: false,
            display_times: false,
            display_threads: false,
            test_always_detach: false,
            capture_stderr: false,
            reexec_ptraceme: false,
        }
    }
}


fn usage(application_name: &str, err: Option<&str>) {
    // eprintln!() is not buffered at all by default
    let mut b = std::io::BufWriter::new(std::io::stderr());

    if let Some(err_text) = err {
        let _ = writeln!(b, "{application_name}: {err_text}");
        let _ = writeln!(b, "");
    }
    
    let _ = writeln!(b, "Usage: {application_name} [-pt] [-o file] [--] command [arg...]");
    let _ = writeln!(b, "       {application_name} [-h|--help]");
    let _ = writeln!(b, "Options:");
    let _ = writeln!(b, " -h      --help              - display this help message");
    let _ = writeln!(b, " -o FILE --output=FILE       - output the process tree to a file instead of stdout");
    let _ = writeln!(b, " -p      --pids              - display PIDs in the process tree");
    let _ = writeln!(b, "         --no-pids           - don't display PIDs in the process tree (default)");
    let _ = writeln!(b, " -t      --times             - display how long a process took to execute in the process tree");
    let _ = writeln!(b, "         --no-times          - don't display how long a process took to execute in the process tree (default)");
    let _ = writeln!(b, "         --show-threads      - show threads alongside processes");
    let _ = writeln!(b, "         --no-show-threads   - don't show threads alongside processes (default)");
    let _ = writeln!(b, "         --capture-stderr    - show stderr from all child processes");
    let _ = writeln!(b, "         --no-capture-stderr - don't show stderr from all child processes processes (default)");
}

fn argument_parsing_error_usage(application_name: &str, err: &str) -> ! {
    usage(application_name, Some(err));
    std::process::exit(1);
}

pub(crate) fn parse_args() -> Args {
    use lexopt::prelude::{Long, Short, Value};
    let mut args = Args::default();

    let mut parser = lexopt::Parser::from_env();
    args.our_name = parser.bin_name().unwrap_or("procflamegraph").to_string();

    while let Some(arg) = parser.next().unwrap_or_else(|err| argument_parsing_error_usage(&args.our_name, &*err.to_string())) {
        match arg {
            Short('p') | Long("pids")  => args.display_pids = true,
            Long("no-pids")            => args.display_pids = false,
            Short('t') | Long("times") => args.display_times = true,
            Long("no-times")           => args.display_times = false,
            Long("show-threads")       => args.display_threads = true,
            Long("no-show-threads")    => args.display_threads = false,
            Long("capture-stderr")     => args.capture_stderr = true,
            Long("no-capture-stderr")  => args.capture_stderr = false,
            Short('h') | Long("help") => {
                usage(&args.our_name, None);
                std::process::exit(0);
            }
            Short('o') | Long("output") => {
                args.output_file = Some(parser.value().unwrap_or_else(|err| argument_parsing_error_usage(&args.our_name, &*err.to_string())));
            }

            // hidden flags
            Long("_test-always-detach") => args.test_always_detach = true,
            Long("_reexec-ptraceme")    => args.reexec_ptraceme = true,

            Value(command) => {
                args.command = vec![command];
                parser
                    .raw_args()
                    .unwrap_or_else(|err| argument_parsing_error_usage(&args.our_name, &*err.to_string()))
                    .for_each(|arg| args.command.push(arg));
            }
            Short(x) => argument_parsing_error_usage(&args.our_name, &*format!("Unknown option \"-{x}\"")),
            Long(x) => argument_parsing_error_usage(&args.our_name, &*format!("Unknown option \"--{x}\"")),
        }
    }

    if args.command.is_empty() {
        usage(&args.our_name, None);
        std::process::exit(1);
    }

    args
}
