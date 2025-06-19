use crate::{ExitReason, args, errors::error_out, output_peeker::ChildPeekResult, tracer::Event};
use nix::{sys::time::{TimeSpec, TimeVal},
          unistd::Pid};
use std::{borrow::Cow,
          collections::HashMap,
          error::Error,
          fs::File,
          io::{BufWriter, Write, stdout},
          iter::zip};
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
struct Rusage {
    utime: TimeVal,
    stime: TimeVal,
}

#[derive(Debug)]
struct Execve {
    cmdline:         Vec<String>,
    started_at:      TimeSpec,
    captured_stdout: Option<Vec<u8>>,
    captured_stderr: Option<Vec<u8>>,
    rusage_at_end:   Option<Rusage>,
}

#[derive(Debug)]
pub(crate) struct Process {
    pid:       Pid,
    children:  Vec<Pid>,
    execvs:    Vec<Execve>,
    exit:      Option<ExitReason>,
    exit_time: Option<TimeSpec>,
}

type JsonObjectWriter<'a, 'b> = ObjectWriter<'a, JsonStreamWriter<&'b mut Box<dyn Write>>>;

impl Process {
    fn new(pid: Pid) -> Process {
        Process {
            pid,
            children: vec![],
            execvs: vec![],
            exit: None,
            exit_time: None,
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
                for execve in self.execvs.iter() {
                    j.write_object(|j| {
                        j.write_array_member("argv", |j| {
                            for arg in execve.cmdline.iter() {
                                j.write_string(arg.as_str())?;
                            }
                            Ok(())
                        })?;

                        j.write_object_member("started_at", |j| {
                            j.write_string_member("sec", &execve.started_at.tv_sec().to_string())?;
                            j.write_string_member("nsec", &execve.started_at.tv_nsec().to_string())?;
                            Ok(())
                        })?;

                        if let Some(rusage_at_end) = &execve.rusage_at_end {
                            j.write_object_member("rusage", |j| {
                                j.write_object_member("utime", |j| {
                                    j.write_string_member("sec", &rusage_at_end.utime.tv_sec().to_string())?;
                                    j.write_string_member("usec", &rusage_at_end.utime.tv_usec().to_string())?;
                                    Ok(())
                                })?;
                                j.write_object_member("stime", |j| {
                                    j.write_string_member("sec", &rusage_at_end.stime.tv_sec().to_string())?;
                                    j.write_string_member("usec", &rusage_at_end.stime.tv_usec().to_string())?;
                                    Ok(())
                                })?;
                                Ok(())
                            })?;
                        }

                        if let Some(captured_stdout) = &execve.captured_stdout {
                            j.write_string_member_with_writer("capturedStdout", |mut w| {
                                w.write_all(captured_stdout.as_slice())?;
                                Ok(())
                            })?;
                        }

                        if let Some(captured_stderr) = &execve.captured_stderr {
                            j.write_string_member_with_writer("capturedStderr", |mut w| {
                                w.write_all(captured_stderr.as_slice())?;
                                Ok(())
                            })?;
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

        if let Some(exit_time) = self.exit_time {
            j.write_object_member("exited_at", |j| {
                j.write_string_member("sec", &exit_time.tv_sec().to_string())?;
                j.write_string_member("nsec", &exit_time.tv_nsec().to_string())?;
                Ok(())
            })?;
        }

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

pub(crate) fn events_to_processes(events: Vec<Event>, captured_output: HashMap<Pid, ChildPeekResult>) -> HashMap<Pid, Process> {
    use crate::tracer::Event;

    let mut processes: HashMap<Pid, Process> = HashMap::new();

    for event in events {
        match event {
            Event::NewChild { child, parent } => {
                processes
                    .entry(parent)
                    .or_insert_with(|| Process::new(parent))
                    .children
                    .push(child);
                processes
                    .entry(child)
                    .or_insert_with(|| Process::new(child));
            }
            Event::KilledBySignal {
                pid,
                signal,
                generated_core_dump,
                time,
                ru_utime,
                ru_stime,
            } => {
                let process = processes
                    .entry(pid)
                    .or_insert_with(|| Process::new(pid));
                if let Some(last_execve) = process.execvs.last_mut() {
                    last_execve.rusage_at_end = Some(Rusage { utime: ru_utime, stime: ru_stime })
                }
                process.exit = Some(ExitReason::KilledBySignal { signal, generated_core_dump });
                process.exit_time = Some(time);
            }
            Event::NormalExit {
                pid,
                exit_code,
                time,
                ru_utime,
                ru_stime,
            } => {
                let process = processes
                    .entry(pid)
                    .or_insert_with(|| Process::new(pid));
                if let Some(last_execve) = process.execvs.last_mut() {
                    last_execve.rusage_at_end = Some(Rusage { utime: ru_utime, stime: ru_stime })
                }
                process.exit = Some(ExitReason::NormalExit { exit_code });
                process.exit_time = Some(time);
            }
            Event::Exec { pid, args, time, ru_utime, ru_stime } => {
                let process = processes
                    .entry(pid)
                    .or_insert_with(|| Process::new(pid));
                
                if let Some(last_execve) = process.execvs.last_mut() {
                    last_execve.rusage_at_end = Some(Rusage { utime: ru_utime, stime: ru_stime })
                }

                process.execvs.push(Execve {
                    cmdline:         parse_proc_cmdline(args),
                    started_at:      time,
                    captured_stdout: None,
                    captured_stderr: None,
                    rusage_at_end:   None,
                });
            }
        }
    }

    for (pid, captured_for_each_execve) in captured_output {
        let process = &mut processes.get_mut(&pid).unwrap();
        for (execve, captured_stdout_for_execve) in zip(&mut process.execvs, captured_for_each_execve.stdout_data) {
            execve.captured_stdout = Some(captured_stdout_for_execve);
        }
        for (execve, captured_stderr_for_execve) in zip(&mut process.execvs, captured_for_each_execve.stderr_data) {
            execve.captured_stderr = Some(captured_stderr_for_execve);
        }
    }

    processes
}

fn parse_proc_cmdline(args: Vec<u8>) -> Vec<String> {
    let mut args: Vec<String> = args
        .split(|x| *x == 0u8)
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect();
    if let Some(last) = args.last()
        && last.is_empty()
    {
        // get rid of the last entry (we split by '\0' but linux really gives us '\0'-ended chunks)
        // be tolerant if it's not a '\0'-ended chunk, as a process might be able to pass some garbage in
        args.pop();
    };
    args
}

fn must_write_err<E: Into<Box<dyn Error>>>(result: Result<(), E>) {
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
        must_write_err(writer.write_object(|object_writer| root.write_json(&processes, object_writer)));
        must_write_err(output.write(b"\n").map(drop)); // todo: this is after a flush, somehow inhibit the first one
    } else {
        must_write_err(root.write_human_readable_tree(0, &processes, &mut output));
    }

    // flush so we handle errors we'd otherwise ignore at closing
    must_write_err(output.flush());

    let root_process_exit = root.exit.clone();

    // a little tiny optimisation, saves a syscall on average on musl's allocator (we're exiting anyway, no need to munmap)
    std::mem::forget(processes);

    root_process_exit
}
