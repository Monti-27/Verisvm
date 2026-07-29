use std::{
    cmp::Ordering,
    io::{BufRead, BufReader},
    process::Stdio,
    thread,
};

use verisvm_worker::{ExecutionLimits, SourceMode, validate_source_path};

use crate::{
    Error, Result,
    git::{SecureGit, capture, join_capture, path_display, sanitize},
};

const OPERATION: &str = "tree inspection";
const RECORD_OVERHEAD: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TreeEntry {
    pub(crate) path: Vec<u8>,
    pub(crate) mode: SourceMode,
    pub(crate) object_id: String,
    pub(crate) size: u64,
}

#[derive(Debug)]
pub(crate) struct SourceTree {
    pub(crate) entries: Vec<TreeEntry>,
    pub(crate) source_bytes: u64,
}

pub(crate) fn read_tree(
    git: &SecureGit,
    commit: &str,
    limits: &ExecutionLimits,
) -> Result<SourceTree> {
    let mut command = git.command();
    command
        .arg("ls-tree")
        .arg("-r")
        .arg("-z")
        .arg("-l")
        .arg("--full-tree")
        .arg(commit)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|source| Error::GitIo {
        operation: OPERATION,
        source,
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
    let parsed = parse_tree(BufReader::new(stdout), limits);
    if parsed.is_err() {
        let _ = child.kill();
    }
    let status = child.wait().map_err(|source| Error::GitIo {
        operation: OPERATION,
        source,
    })?;
    let stderr = join_capture(stderr_reader, OPERATION)?;
    let entries = parsed?;
    if !status.success() {
        return Err(Error::GitFailed {
            operation: OPERATION,
            status: status
                .code()
                .map_or_else(|| "signal".to_owned(), |code| code.to_string()),
            stderr: sanitize(&stderr.bytes, stderr.exceeded),
        });
    }
    Ok(entries)
}

fn parse_tree(mut reader: impl BufRead, limits: &ExecutionLimits) -> Result<SourceTree> {
    let record_limit = limits.source_path_bytes.saturating_add(RECORD_OVERHEAD);
    let mut entries = Vec::new();
    let mut record = Vec::new();
    let mut metadata_bytes = 0_usize;
    let mut source_bytes = 0_u64;
    let mut previous_path = Vec::new();
    while read_record(&mut reader, &mut record, record_limit)? {
        metadata_bytes = metadata_bytes
            .checked_add(record.len().saturating_add(1))
            .ok_or(Error::MetadataTooLarge {
                limit: limits.source_metadata_bytes,
            })?;
        if metadata_bytes > limits.source_metadata_bytes {
            return Err(Error::MetadataTooLarge {
                limit: limits.source_metadata_bytes,
            });
        }
        if entries.len() == limits.source_files {
            return Err(Error::TooManyFiles {
                limit: limits.source_files,
            });
        }
        let entry = parse_record(&record, limits)?;
        match previous_path.as_slice().cmp(&entry.path) {
            Ordering::Less => {}
            Ordering::Equal => return Err(Error::PathCollision(path_display(&entry.path))),
            Ordering::Greater => {
                return Err(Error::InvalidGitOutput {
                    operation: OPERATION,
                    detail: "paths are not in bytewise order".to_owned(),
                });
            }
        }
        source_bytes = source_bytes
            .checked_add(entry.size)
            .ok_or(Error::SourceTooLarge {
                limit: limits.source_bytes,
            })?;
        if source_bytes > limits.source_bytes {
            return Err(Error::SourceTooLarge {
                limit: limits.source_bytes,
            });
        }
        previous_path.clone_from(&entry.path);
        entries.push(entry);
    }
    if entries.is_empty() {
        return Err(Error::EmptyTree);
    }
    Ok(SourceTree {
        entries,
        source_bytes,
    })
}

fn parse_record(record: &[u8], limits: &ExecutionLimits) -> Result<TreeEntry> {
    let separator = record
        .iter()
        .position(|byte| *byte == b'\t')
        .ok_or(Error::InvalidTreeRecord)?;
    let path = &record[separator + 1..];
    if path.len() > limits.source_path_bytes {
        return Err(Error::PathTooLong {
            limit: limits.source_path_bytes,
        });
    }
    validate_source_path(path)?;
    let fields = record[..separator]
        .split(u8::is_ascii_whitespace)
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    let [mode, kind, object_id, size] = fields.as_slice() else {
        return Err(Error::InvalidTreeRecord);
    };
    if *mode == b"160000" && *kind == b"commit" {
        return Err(Error::Submodule(path_display(path)));
    }
    let source_mode = match (*mode, *kind) {
        (b"100644", b"blob") => SourceMode::Regular,
        (b"100755", b"blob") => SourceMode::Executable,
        (b"120000", b"blob") => SourceMode::Symlink,
        _ => {
            return Err(Error::UnsupportedTreeEntry {
                mode: String::from_utf8_lossy(mode).into_owned(),
                kind: String::from_utf8_lossy(kind).into_owned(),
                path: path_display(path),
            });
        }
    };
    if !matches!(object_id.len(), 40 | 64)
        || !object_id
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Error::InvalidTreeRecord);
    }
    let size = std::str::from_utf8(size)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(Error::InvalidTreeRecord)?;
    if size > limits.source_file_bytes {
        return Err(Error::FileTooLarge {
            path: path_display(path),
            size,
            limit: limits.source_file_bytes,
        });
    }
    Ok(TreeEntry {
        path: path.to_vec(),
        mode: source_mode,
        object_id: String::from_utf8_lossy(object_id).into_owned(),
        size,
    })
}

fn read_record(reader: &mut impl BufRead, record: &mut Vec<u8>, limit: usize) -> Result<bool> {
    record.clear();
    loop {
        let available = reader.fill_buf().map_err(|source| Error::GitIo {
            operation: OPERATION,
            source,
        })?;
        if available.is_empty() {
            if record.is_empty() {
                return Ok(false);
            }
            return Err(Error::InvalidTreeRecord);
        }
        if let Some(index) = available.iter().position(|byte| *byte == 0) {
            if record.len().saturating_add(index) > limit {
                return Err(Error::GitOutputTooLarge {
                    operation: OPERATION,
                    limit,
                });
            }
            record.extend_from_slice(&available[..index]);
            reader.consume(index + 1);
            return Ok(true);
        }
        if record.len().saturating_add(available.len()) > limit {
            return Err(Error::GitOutputTooLarge {
                operation: OPERATION,
                limit,
            });
        }
        let consumed = available.len();
        record.extend_from_slice(available);
        reader.consume(consumed);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use verisvm_worker::{ExecutionLimits, SourceMode};

    use super::parse_tree;
    use crate::Error;

    #[test]
    fn parses_raw_nul_delimited_tree_entries() {
        let input = b"100644 blob 0123456789abcdef0123456789abcdef01234567       4\tCargo.toml\0\
100755 blob 1123456789abcdef0123456789abcdef01234567      10\tbin/run\0";
        let tree = parse_tree(Cursor::new(input), &ExecutionLimits::default())
            .expect("valid tree records");

        assert_eq!(tree.entries.len(), 2);
        assert_eq!(tree.entries[0].path, b"Cargo.toml");
        assert_eq!(tree.entries[1].mode, SourceMode::Executable);
        assert_eq!(tree.entries[1].size, 10);
        assert_eq!(tree.source_bytes, 14);
    }

    #[test]
    fn rejects_gitlinks() {
        let input = b"160000 commit 0123456789abcdef0123456789abcdef01234567       -\tvendor/sdk\0";
        let error = parse_tree(Cursor::new(input), &ExecutionLimits::default())
            .expect_err("gitlink must fail");

        assert!(matches!(error, Error::Submodule(_)));
    }

    #[test]
    fn rejects_source_limit_overrun() {
        let input = b"100644 blob 0123456789abcdef0123456789abcdef01234567       4\tCargo.toml\0";
        let limits = ExecutionLimits {
            source_bytes: 3,
            ..ExecutionLimits::default()
        };
        let error = parse_tree(Cursor::new(input), &limits).expect_err("tree must exceed limit");

        assert!(matches!(error, Error::SourceTooLarge { .. }));
    }

    #[test]
    fn rejects_repository_control_paths() {
        let input = b"100644 blob 0123456789abcdef0123456789abcdef01234567       4\t.git/config\0";
        let error = parse_tree(Cursor::new(input), &ExecutionLimits::default())
            .expect_err("control path must fail");

        assert!(matches!(error, Error::SourceTree(_)));
    }
}
