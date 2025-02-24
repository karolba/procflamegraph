use std::ffi::OsString;
use std::io::Write;

#[derive(Default)]
pub(crate) struct Args {
    pub(crate) output_file: Option<OsString>,
    pub(crate) command: Vec<OsString>,
    pub(crate) display_pids: bool,
    pub(crate) display_times: bool,
}

fn usage(application_name: &str) {
    // eprintln!() is not buffered at all by default
    let mut b = std::io::BufWriter::new(std::io::stderr());

    let _ = writeln!(b, "Usage: {application_name} [-pt] [-o file] [--] command [arg...]");
    let _ = writeln!(b, "       {application_name} [-h|--help]");
    let _ = writeln!(b, "Options:");
    let _ = writeln!(b, " -h      --help        - display this help message");
    let _ = writeln!(b, " -o FILE --output=FILE - output the process tree to a file instead of stdout");
    let _ = writeln!(b, " -p      --pids        - display PIDs in the process tree");
    let _ = writeln!(b, "         --no-pids     - don't display PIDs in the process tree (default)");
    let _ = writeln!(b, " -t      --times       - display how long a process took to execute in the process tree");
    let _ = writeln!(b, "         --no-times    - don't display how long a process took to execute in the process tree (default)");
}

fn argument_parsing_error_usage(application_name: &str, err: &str) -> ! {
    eprintln!("{application_name}: {err}\n");
    usage(application_name);
    std::process::exit(1);
}

pub(crate) fn parse_args() -> Args {
    use lexopt::prelude::{Long, Short, Value};
    let mut args = Args::default();

    let mut parser = lexopt::Parser::from_env();
    let name: String = parser.bin_name().unwrap_or("procflamegraph").to_string();

    while let Some(arg) = parser.next().unwrap_or_else(|err| argument_parsing_error_usage(&name, &*err.to_string())) {
        match arg {
            Short('p') | Long("pids") => args.display_pids = true,
                      Long("no-pids") => args.display_pids = false,
            Short('t') | Long("times") => args.display_times = true,
                      Long("no-times") => args.display_times = false,
            Short('h') | Long("help") => {
                usage(&name);
                std::process::exit(0);
            }
            Short('o') | Long("output") => {
                args.output_file = Some(parser.value().unwrap_or_else(|err| argument_parsing_error_usage(&name, &*err.to_string())));
            }
            Value(command) => {
                args.command = vec![command];
                parser
                    .raw_args()
                    .unwrap_or_else(|err| argument_parsing_error_usage(&name, &*err.to_string()))
                    .for_each(|arg| args.command.push(arg));
            }
            Short(x) => argument_parsing_error_usage(&name, &*format!("Unknown option \"-{x}\"")),
            Long(x) => argument_parsing_error_usage(&name, &*format!("Unknown option \"--{x}\"")),
        }
    }

    if args.command.is_empty() {
        usage(&name);
        std::process::exit(1);
    }

    args
}
