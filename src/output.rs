use crate::{ExitReason, args, errors::error_out, output_peeker::ChildPeekResult, tracer::Event};
use nix::unistd::Pid;
use std::{borrow::Cow,
          collections::HashMap,
          error::Error,
          fs::File,
          io::{BufWriter, Write, stdout},
          time::SystemTime};
use struson::writer::{JsonStreamWriter,
                      simple::{ObjectWriter, SimpleJsonWriter, ValueWriter}};

// todo: is there a builtin for this?
macro_rules! yield_from {
    ($e:expr) => {{
        let mut generator = $e;
        loop {
            match generator.next() {
                Some(x) => yield x,
                None => break,
            }
        }
    }};
}

#[derive(Debug)]
pub(crate) struct Process {
    pid:                Pid,
    children:           Vec<Pid>,
    execvs:             Vec<Vec<String>>,
    exit:               Option<ExitReason>,
    child_peek_results: Option<ChildPeekResult>,
    #[allow(dead_code)]
    start_time:         Option<SystemTime>,
    #[allow(dead_code)]
    stop_time:          Option<SystemTime>, // todo: use those? or rusage
}

type JsonObjectWriter<'a, 'b> = ObjectWriter<'a, JsonStreamWriter<&'b mut Box<dyn Write>>>;

impl Process {
    fn new(pid: Pid) -> Process {
        Process {
            pid,
            children: vec![],
            execvs: vec![],
            exit: None,
            child_peek_results: None,
            start_time: None,
            stop_time: None,
        }
    }

    gen fn flattened_children<'a>(&self, others: &'a HashMap<Pid, Process>) -> &'a Process {
        for child in &self.children {
            if let Some(child) = others.get(child) {
                if child.execvs.is_empty() {
                    // "error[E0733]: recursion in a gen fn requires boxing", so put it in a box then
                    yield_from!(Box::new(child.flattened_children(others)));
                } else {
                    yield child;
                }
            }
        }
    }

    fn write_human_readable_tree(&self, indent: usize, others: &HashMap<Pid, Process>, out: &mut dyn Write) -> Result<(), std::io::Error> {
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

        for child in self.flattened_children(others) {
            child.write_human_readable_tree(indent + 2, others, out)?;
        }

        Ok(())
    }

    fn write_json(&self, others: &HashMap<Pid, Process>, j: &mut JsonObjectWriter) -> Result<(), Box<dyn Error>> {
        if args().display_pids {
            j.write_number_member("pid", self.pid.as_raw())?;
        }

        if !self.execvs.is_empty() {
            j.write_array_member("execves", |j| {
                for (i, execve) in self.execvs.iter().enumerate() {
                    j.write_object(|j| {
                        j.write_array_member("argv", |j| {
                            for arg in execve.iter() {
                                j.write_string(arg.as_str())?;
                            }
                            Ok(())
                        })?;

                        if let Some(child_peek_result) = &self.child_peek_results {
                            let ChildPeekResult { stdout_data, stderr_data } = child_peek_result;

                            if let Some(instance_result) = stdout_data.get(i)
                                && !instance_result.is_empty()
                            {
                                j.write_string_member_with_writer("capturedStdout", |mut w| {
                                    w.write_all(instance_result.as_slice())?;
                                    Ok(())
                                })?;
                            }
                            if let Some(instance_result) = stderr_data.get(i)
                                && !instance_result.is_empty()
                            {
                                j.write_string_member_with_writer("capturedStderr", |mut w| {
                                    w.write_all(instance_result.as_slice())?;
                                    Ok(())
                                })?;
                            }
                        }
                        Ok(())
                    })?;
                }
                Ok(())
            })?;
        }

        match self.exit {
            None => j.write_string_member("exit", "unknown")?,
            Some(ExitReason::NormalExit { exit_code }) => j.write_object_member("exit", |j| {
                j.write_number_member("code", exit_code)?;
                Ok(())
            })?,
            Some(ExitReason::KilledBySignal { signal, generated_core_dump: false }) => j.write_object_member("exit", |j| {
                j.write_string_member("killedBySignal", signal.as_str())?;
                Ok(())
            })?,
            Some(ExitReason::KilledBySignal { signal, generated_core_dump: true }) => j.write_object_member("exit", |j| {
                j.write_string_member("killedBySignal", signal.as_str())?;
                j.write_bool_member("generatedCoreDump", true)?;
                Ok(())
            })?,
        };

        let mut children = self.flattened_children(others);
        if let Some(first_child) = children.next() {
            j.write_array_member("children", |j| {
                j.write_object(|j| first_child.write_json(others, j))?;

                for child in children {
                    j.write_object(|j| {
                        child.write_json(others, j)?;
                        Ok(())
                    })?;
                }
                Ok(())
            })?;
        }

        Ok(())
    }
}

pub(crate) fn events_to_processes(events: Vec<Event>, mut captured_output: HashMap<Pid, ChildPeekResult>) -> HashMap<Pid, Process> {
    use crate::tracer::Event;

    let mut processes: HashMap<Pid, Process> = HashMap::new();

    let mut new_process = |pid: Pid| -> Process {
        let mut process = Process::new(pid);
        process.child_peek_results = captured_output.remove(&pid);
        process
    };

    for event in events {
        match event {
            Event::NewChild { child, parent } => {
                processes
                    .entry(parent)
                    .or_insert_with(|| new_process(parent))
                    .children
                    .push(child);
                processes
                    .entry(child)
                    .or_insert_with(|| new_process(child));
            }
            Event::KilledBySignal {
                pid,
                signal,
                generated_core_dump,
                rusage: _rusage,
            } => {
                let proc = processes
                    .entry(pid)
                    .or_insert_with(|| new_process(pid));
                proc.exit = Some(ExitReason::KilledBySignal { signal, generated_core_dump });
            }
            Event::NormalExit { pid, exit_code, rusage: _rusage } => {
                let proc = processes
                    .entry(pid)
                    .or_insert_with(|| new_process(pid));
                proc.exit = Some(ExitReason::NormalExit { exit_code });
            }
            Event::Exec { pid, args, rusage: _rusage } => {
                let mut args: Vec<String> = args
                    .split(|x| *x == 0u8)
                    .map(|arg| String::from_utf8_lossy(arg).to_string())
                    .collect();
                if let Some(last) = args.last()
                    && last.is_empty()
                {
                    args.pop(); // get rid of the last entry (we split by '\0' but it's really '\0'-ended chunks)
                };
                processes
                    .entry(pid)
                    .or_insert_with(|| new_process(pid))
                    .execvs
                    .push(args);
            }
        }
    }

    processes
}

fn have_to_write<E: Into<Box<dyn Error>>>(result: Result<(), E>) {
    if let Err(error) = result {
        let filename = args()
            .output_file
            .as_ref()
            .map(|filename| filename.to_string_lossy())
            .unwrap_or_else(|| Cow::Borrowed("(stdout)"));
        error_out!("Couldn't write the process tree to file {}: {}", filename, error.into());
    }
}

pub(crate) fn output_process_tree(root_child_pid: Pid, processes: HashMap<Pid, Process>) -> Option<ExitReason> {
    let root = processes
        .get(&root_child_pid)
        .expect("Our only child is not in children (??)");

    let mut output: Box<dyn Write> = match &args().output_file {
        None => Box::new(BufWriter::new(stdout())),
        Some(path) => Box::new(BufWriter::new(
            File::create(&path).unwrap_or_else(|err| error_out!("Can't open file {} for writing: {}", path.to_string_lossy(), err)),
        )),
    };

    if args().json_output {
        let writer = SimpleJsonWriter::new(&mut output);
        have_to_write(writer.write_object(|object_writer| root.write_json(&processes, object_writer)));
        have_to_write(output.write(b"\n").map(drop)); // todo: this is after a flush, somehow inhibit the first one
    } else {
        have_to_write(root.write_human_readable_tree(0, &processes, &mut output));
    }

    // flush so we handle errors we'd otherwise ignore at closing
    have_to_write(output.flush());

    let root_process_exit = root.exit.clone();

    // a little tiny optimisation, saves a syscall on average on musl's allocator (we're exiting anyway, no need to munmap)
    std::mem::forget(processes);

    root_process_exit
}
