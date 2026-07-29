use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs::{self, OpenOptions, Permissions},
    io::{BufRead, BufReader, Read, Write},
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Stdio},
    thread::{self, JoinHandle},
};

use verisvm_core::Digest;
use verisvm_worker::{SourceMode, SourceTreeHasher};

use crate::{
    Error, Result,
    git::{CapturedOutput, SecureGit, capture, join_capture, path_display, sanitize},
    tree::TreeEntry,
};

const OPERATION: &str = "blob extraction";
const HEADER_LIMIT: usize = 256;
const SYMLINK_TARGET_LIMIT: u64 = 4_096;

pub(crate) fn materialize(git: &SecureGit, root: &Path, entries: &[TreeEntry]) -> Result<Digest> {
    prepare_directories(root, entries)?;
    let mut cat_file = CatFile::spawn(git)?;
    let mut hasher = SourceTreeHasher::new(entries.len())?;
    for entry in entries {
        cat_file.materialize_entry(root, entry, &mut hasher)?;
    }
    cat_file.finish()?;
    hasher.finish().map_err(Into::into)
}

fn prepare_directories(root: &Path, entries: &[TreeEntry]) -> Result<()> {
    let mut directories = BTreeSet::new();
    let paths = entries
        .iter()
        .map(|entry| entry.path.as_slice())
        .collect::<BTreeSet<_>>();
    for entry in entries {
        for (index, byte) in entry.path.iter().enumerate() {
            if *byte == b'/' {
                directories.insert(entry.path[..index].to_vec());
            }
        }
    }
    for directory in &directories {
        if paths.contains(directory.as_slice()) {
            return Err(Error::PathCollision(path_display(directory)));
        }
        let path = join_raw(root, directory);
        match fs::create_dir(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(Error::PathCollision(path_display(directory)));
            }
            Err(source) => {
                return Err(Error::Materialize {
                    path: path_display(directory),
                    source,
                });
            }
        }
    }
    Ok(())
}

struct CatFile {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    stderr_reader: Option<JoinHandle<std::io::Result<CapturedOutput>>>,
    finished: bool,
}

impl CatFile {
    fn spawn(git: &SecureGit) -> Result<Self> {
        let mut command = git.command();
        command
            .arg("cat-file")
            .arg("--batch")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|source| Error::GitIo {
            operation: OPERATION,
            source,
        })?;
        let stdin = child.stdin.take().ok_or_else(|| Error::InvalidGitOutput {
            operation: OPERATION,
            detail: "stdin pipe is unavailable".to_owned(),
        })?;
        let stdout = child.stdout.take().ok_or_else(|| Error::InvalidGitOutput {
            operation: OPERATION,
            detail: "stdout pipe is unavailable".to_owned(),
        })?;
        let stderr = child.stderr.take().ok_or_else(|| Error::InvalidGitOutput {
            operation: OPERATION,
            detail: "stderr pipe is unavailable".to_owned(),
        })?;
        let stderr_reader = thread::spawn(move || capture(stderr, 64 * 1_024));
        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout: BufReader::new(stdout),
            stderr_reader: Some(stderr_reader),
            finished: false,
        })
    }

    fn materialize_entry(
        &mut self,
        root: &Path,
        entry: &TreeEntry,
        hasher: &mut SourceTreeHasher,
    ) -> Result<()> {
        let stdin = self.stdin.as_mut().ok_or_else(|| Error::InvalidGitOutput {
            operation: OPERATION,
            detail: "stdin pipe closed early".to_owned(),
        })?;
        stdin
            .write_all(entry.object_id.as_bytes())
            .and_then(|()| stdin.write_all(b"\n"))
            .and_then(|()| stdin.flush())
            .map_err(|source| Error::GitIo {
                operation: OPERATION,
                source,
            })?;
        self.verify_header(entry)?;
        hasher.begin_entry(&entry.path, entry.mode, entry.size)?;
        let path = join_raw(root, &entry.path);
        match entry.mode {
            SourceMode::Regular | SourceMode::Executable => {
                let mut file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                    .map_err(|source| path_error(&entry.path, source))?;
                stream_content(&mut self.stdout, entry.size, hasher, &mut file)?;
                let mode = if entry.mode == SourceMode::Executable {
                    0o755
                } else {
                    0o644
                };
                file.set_permissions(Permissions::from_mode(mode))
                    .map_err(|source| Error::Materialize {
                        path: path_display(&entry.path),
                        source,
                    })?;
            }
            SourceMode::Symlink => {
                if entry.size > SYMLINK_TARGET_LIMIT {
                    return Err(Error::SymlinkTooLarge {
                        path: path_display(&entry.path),
                        size: entry.size,
                        limit: SYMLINK_TARGET_LIMIT,
                    });
                }
                let capacity = usize::try_from(entry.size).map_err(|_| Error::SymlinkTooLarge {
                    path: path_display(&entry.path),
                    size: entry.size,
                    limit: SYMLINK_TARGET_LIMIT,
                })?;
                let mut target = Vec::with_capacity(capacity);
                stream_content(&mut self.stdout, entry.size, hasher, &mut target)?;
                validate_symlink(&entry.path, &target)?;
                std::os::unix::fs::symlink(OsStr::from_bytes(&target), &path)
                    .map_err(|source| path_error(&entry.path, source))?;
            }
        }
        let mut delimiter = [0_u8; 1];
        self.stdout
            .read_exact(&mut delimiter)
            .map_err(|source| Error::GitIo {
                operation: OPERATION,
                source,
            })?;
        if delimiter != [b'\n'] {
            return Err(Error::InvalidGitOutput {
                operation: OPERATION,
                detail: "blob content delimiter is invalid".to_owned(),
            });
        }
        hasher.end_entry()?;
        Ok(())
    }

    fn verify_header(&mut self, entry: &TreeEntry) -> Result<()> {
        let mut header = Vec::new();
        read_line_limited(&mut self.stdout, &mut header, HEADER_LIMIT)?;
        let fields = header
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        let [object_id, kind, size] = fields.as_slice() else {
            return Err(Error::InvalidGitOutput {
                operation: OPERATION,
                detail: "blob header has an invalid shape".to_owned(),
            });
        };
        let observed_size = std::str::from_utf8(size)
            .ok()
            .and_then(|value| value.parse::<u64>().ok());
        if *object_id != entry.object_id.as_bytes()
            || *kind != b"blob"
            || observed_size != Some(entry.size)
        {
            return Err(Error::InvalidGitOutput {
                operation: OPERATION,
                detail: format!("blob identity differs for {}", path_display(&entry.path)),
            });
        }
        Ok(())
    }

    fn finish(mut self) -> Result<()> {
        self.stdin.take();
        let mut extra = [0_u8; 1];
        let extra_len = self
            .stdout
            .read(&mut extra)
            .map_err(|source| Error::GitIo {
                operation: OPERATION,
                source,
            })?;
        let status = self.child.wait().map_err(|source| Error::GitIo {
            operation: OPERATION,
            source,
        })?;
        let stderr_reader = self
            .stderr_reader
            .take()
            .ok_or_else(|| Error::InvalidGitOutput {
                operation: OPERATION,
                detail: "stderr reader is unavailable".to_owned(),
            })?;
        let stderr = join_capture(stderr_reader, OPERATION)?;
        self.finished = true;
        if extra_len != 0 {
            return Err(Error::InvalidGitOutput {
                operation: OPERATION,
                detail: "unexpected trailing blob output".to_owned(),
            });
        }
        if !status.success() {
            return Err(Error::GitFailed {
                operation: OPERATION,
                status: status
                    .code()
                    .map_or_else(|| "signal".to_owned(), |code| code.to_string()),
                stderr: sanitize(&stderr.bytes, stderr.exceeded),
            });
        }
        Ok(())
    }
}

impl Drop for CatFile {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.stdin.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(handle) = self.stderr_reader.take() {
            let _ = handle.join();
        }
    }
}

fn stream_content(
    reader: &mut impl Read,
    size: u64,
    hasher: &mut SourceTreeHasher,
    writer: &mut impl Write,
) -> Result<()> {
    let mut remaining = size;
    let mut buffer = vec![0_u8; 64 * 1_024].into_boxed_slice();
    while remaining > 0 {
        let buffer_len = u64::try_from(buffer.len()).map_err(|_| Error::InvalidGitOutput {
            operation: OPERATION,
            detail: "buffer length cannot be represented".to_owned(),
        })?;
        let limit =
            usize::try_from(remaining.min(buffer_len)).map_err(|_| Error::InvalidGitOutput {
                operation: OPERATION,
                detail: "blob size cannot be represented".to_owned(),
            })?;
        let read = reader
            .read(&mut buffer[..limit])
            .map_err(|source| Error::GitIo {
                operation: OPERATION,
                source,
            })?;
        if read == 0 {
            return Err(Error::InvalidGitOutput {
                operation: OPERATION,
                detail: "blob content ended early".to_owned(),
            });
        }
        hasher.update(&buffer[..read])?;
        writer
            .write_all(&buffer[..read])
            .map_err(|source| Error::GitIo {
                operation: OPERATION,
                source,
            })?;
        remaining -= u64::try_from(read).map_err(|_| Error::InvalidGitOutput {
            operation: OPERATION,
            detail: "blob read length cannot be represented".to_owned(),
        })?;
    }
    Ok(())
}

fn read_line_limited(reader: &mut impl BufRead, line: &mut Vec<u8>, limit: usize) -> Result<()> {
    line.clear();
    loop {
        let available = reader.fill_buf().map_err(|source| Error::GitIo {
            operation: OPERATION,
            source,
        })?;
        if available.is_empty() {
            return Err(Error::InvalidGitOutput {
                operation: OPERATION,
                detail: "blob header ended early".to_owned(),
            });
        }
        if let Some(index) = available.iter().position(|byte| *byte == b'\n') {
            if line.len().saturating_add(index) > limit {
                return Err(Error::GitOutputTooLarge {
                    operation: OPERATION,
                    limit,
                });
            }
            line.extend_from_slice(&available[..index]);
            reader.consume(index + 1);
            return Ok(());
        }
        if line.len().saturating_add(available.len()) > limit {
            return Err(Error::GitOutputTooLarge {
                operation: OPERATION,
                limit,
            });
        }
        let consumed = available.len();
        line.extend_from_slice(available);
        reader.consume(consumed);
    }
}

fn validate_symlink(path: &[u8], target: &[u8]) -> Result<()> {
    if target.is_empty() || target.starts_with(b"/") || target.contains(&0) {
        return Err(Error::UnsafeSymlink(path_display(path)));
    }
    let mut depth = path.split(|byte| *byte == b'/').count() - 1;
    for component in target.split(|byte| *byte == b'/') {
        match component {
            b"" | b"." => {}
            b".." if depth == 0 => return Err(Error::UnsafeSymlink(path_display(path))),
            b".." => depth -= 1,
            _ => depth = depth.saturating_add(1),
        }
    }
    Ok(())
}

fn join_raw(root: &Path, path: &[u8]) -> PathBuf {
    let mut joined = root.to_path_buf();
    for component in path.split(|byte| *byte == b'/') {
        joined.push(OsStr::from_bytes(component));
    }
    joined
}

fn path_error(path: &[u8], source: std::io::Error) -> Error {
    if source.kind() == std::io::ErrorKind::AlreadyExists {
        Error::PathCollision(path_display(path))
    } else {
        Error::Materialize {
            path: path_display(path),
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::validate_symlink;

    #[test]
    fn accepts_symlinks_that_stay_inside_the_tree() {
        validate_symlink(b"docs/latest", b"../README.md").expect("internal target");
    }

    #[test]
    fn rejects_symlinks_that_escape_the_tree() {
        assert!(validate_symlink(b"latest", b"../outside").is_err());
        assert!(validate_symlink(b"latest", b"/etc/passwd").is_err());
    }
}
