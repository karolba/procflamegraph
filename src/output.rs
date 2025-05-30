use crate::errors::error_out;
use crate::output_peeker::ChildPeekResult;
use crate::tracer::Event;
use crate::{args, ExitReason};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{stdout, BufWriter, Write};
use std::time::SystemTime;

#[derive(Debug)]
struct Process {
    pid: Pid,
    children: Vec<Pid>,
    execvs: Vec<Vec<String>>,
    exit: Option<ExitReason>,
    #[allow(dead_code)] start_time: Option<SystemTime>,
    #[allow(dead_code)] stop_time: Option<SystemTime>, // todo: use those?
}

impl Process {
    fn new(pid: Pid) -> Process {
        Process {
            pid,
            children: vec![],
            execvs: vec![],
            exit: None,
            start_time: None,
            stop_time: None,
        }
    }

    fn print_human_readable_tree(&self, indent: usize, others: &HashMap<Pid, Process>, out: &mut dyn Write) -> Result<(), std::io::Error> {
        if !args().display_threads && self.execvs.is_empty() && matches!(self.exit, Some(ExitReason::NormalExit{ exit_code: 0 })) {
            // collapse worker threads that didn't contribute anything and only muddy out the output
            // todo: could it make sense to collapse non-0-exit-code threads too
            for child in self.children.iter() {
                if let Some(child_process) = others.get(child) {
                    child_process.print_human_readable_tree(indent, others, out)?;
                }
            }
        } else {
            write!(out, "{:indent$}- ", "")?;
            if args().display_pids {
                write!(out, "({}) ", self.pid)?;
            }
            for execv in self.execvs.iter() {
                write!(out, "{execv:?} -> ")?;
            }
            if self.execvs.len() == 0 {
                write!(out, "-> ")?;
            }
            match self.exit {
                Some(ExitReason::NormalExit { exit_code }) => writeln!(out, "{}", exit_code)?,
                Some(ExitReason::KilledBySignal { signal, generated_core_dump: true }) => writeln!(out, "killed by {} (core dumped)", signal.as_str())?,
                Some(ExitReason::KilledBySignal { signal, generated_core_dump: false }) => writeln!(out, "killed by {}", signal.as_str())?,
                None => writeln!(out, "(unknown)")?,
            };

            for child in self.children.iter() {
                if let Some(child_process) = others.get(child) {
                    child_process.print_human_readable_tree(indent + 2, others, out)?;
                }
            }
        }

        Ok(())
    }

    // fn print_json_tree(&self, others: &HashMap<Pid, Process>, out: &mut dyn Write) -> Result<(), std::io::Error> {
    //
    // }
}

fn events_to_process_tree(events: Vec<Event>) -> HashMap<Pid, Process> {
    use crate::tracer::Event;

    let mut processes: HashMap<Pid, Process> = HashMap::new();

    for event in events {
        match event {
            Event::NewChild { child, parent } => {
                let parent = processes.entry(parent).or_insert_with(|| Process::new(parent));
                parent.children.push(child);
                processes.entry(child).or_insert_with(|| Process::new(child));
            }
            Event::KilledBySignal { pid, signal, generated_core_dump, rusage: _rusage } => {
                let process = processes.entry(pid).or_insert_with(|| Process::new(pid));
                process.exit = Some(ExitReason::KilledBySignal{ signal, generated_core_dump });
            }
            Event::NormalExit { pid, exit_code, rusage: _rusage } => {
                let process = processes.entry(pid).or_insert_with(|| Process::new(pid));
                process.exit = Some(ExitReason::NormalExit{ exit_code });
            }
            Event::Exec { pid, args, _former_thread_id, rusage: _rusage } => {
                // todo: former_thread_id, should I do anything with it? doesn't seem like I should?
                let mut args: Vec<String> = args.split(|x| *x == 0u8).map(|arg| String::from_utf8_lossy(arg).to_string()).collect();
                if let Some(last) = args.last() {
                    if last.is_empty() {
                        args.pop(); // get rid of the last entry (we split by '\0' but it's really '\0'-ended chunks)
                    }
                };
                let process = processes.entry(pid).or_insert_with(|| Process::new(pid));
                process.execvs.push(args);
            }
        }
    }

    processes
}

pub(crate) fn output_process_tree(events: Vec<Event>, root_child_pid: Pid, captured_output: HashMap<Pid, ChildPeekResult>) -> Option<ExitReason> {
    let processes = events_to_process_tree(events);

    let root = processes.get(&root_child_pid).expect("Our only child is not in children (??)");

    let mut output: Box<dyn Write> = match &args().output_file {
        None => Box::new(BufWriter::new(stdout())),
        Some(path) => Box::new(BufWriter::new(
            File::create(&path).unwrap_or_else(|err| error_out!("Can't open file {} for writing: {}", path.to_string_lossy(), err)),
        )),
    };

    if args().json_output {

    } else {
        root.print_human_readable_tree(0, &processes, &mut output)
            .and_then(|_| output.flush()) // We wouldn't get to catch write errors without flushing manually
            .unwrap_or_else(|e| {
                let default_output_name = OsString::from("(stdout)");
                let filename = args().output_file.as_ref().unwrap_or(&default_output_name);
                error_out!("Couldn't write the process tree to file {}: {}", filename.to_string_lossy(), e);
            });
    }

    let root_process_exit = root.exit.clone();

    // a little tiny optimisation, saves a syscall on average (we're exiting anyway, no need to munmap)
    std::mem::forget(processes);
    std::mem::forget(captured_output);

    root_process_exit
}