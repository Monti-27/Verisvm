use std::{
    ffi::OsString,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
};

use crate::{Error, Result};

const STDERR_LIMIT: usize = 64 * 1_024;

pub(crate) struct SecureGit {
    executable: PathBuf,
    git_dir: PathBuf,
    path: OsString,
}

pub(crate) struct CapturedOutput {
    pub(crate) bytes: Vec<u8>,
    pub(crate) exceeded: bool,
}

impl SecureGit {
    pub(crate) fn new(executable: &Path, git_dir: PathBuf) -> Result<Self> {
        if !executable.is_absolute() {
            return Err(Error::InvalidGitExecutable(
                "path must be absolute".to_owned(),
            ));
        }
        let executable = fs::canonicalize(executable).map_err(|error| {
            Error::InvalidGitExecutable(format!("cannot resolve path: {error}"))
        })?;
        if !executable.is_file() {
            return Err(Error::InvalidGitExecutable(
                "path does not name a file".to_owned(),
            ));
        }
        let parent = executable.parent().ok_or_else(|| {
            Error::InvalidGitExecutable("path has no parent directory".to_owned())
        })?;
        let path = std::env::join_paths([parent, Path::new("/usr/bin"), Path::new("/bin")])
            .map_err(|error| Error::InvalidGitExecutable(error.to_string()))?;
        Ok(Self {
            executable,
            git_dir,
            path,
        })
    }

    pub(crate) fn initialize(&self, object_format: &str) -> Result<()> {
        let mut command = self.base_command();
        command
            .arg("init")
            .arg("--bare")
            .arg("--quiet")
            .arg(format!("--object-format={object_format}"))
            .arg(&self.git_dir);
        Self::run(command, "repository initialization", 1_024)?;
        Ok(())
    }

    pub(crate) fn fetch(&self, repository: &str, commit: &str) -> Result<()> {
        let mut command = self.command();
        command
            .arg("fetch")
            .arg("--quiet")
            .arg("--no-tags")
            .arg("--no-write-fetch-head")
            .arg("--no-recurse-submodules")
            .arg("--depth=1")
            .arg("--")
            .arg(repository)
            .arg(commit);
        Self::run(command, "fetch", 1_024)?;
        Ok(())
    }

    pub(crate) fn verify_commit(&self, commit: &str) -> Result<()> {
        let mut type_command = self.command();
        type_command.arg("cat-file").arg("-t").arg(commit);
        let object_type = Self::run(type_command, "commit type inspection", 64)?;
        if object_type != b"commit\n" {
            return Err(Error::InvalidGitOutput {
                operation: "commit type inspection",
                detail: "requested object is not a commit".to_owned(),
            });
        }

        let mut resolve_command = self.command();
        resolve_command
            .arg("rev-parse")
            .arg("--verify")
            .arg("--end-of-options")
            .arg(commit);
        let resolved = Self::run(resolve_command, "commit resolution", 129)?;
        let resolved = resolved.strip_suffix(b"\n").unwrap_or(&resolved);
        if !resolved.eq_ignore_ascii_case(commit.as_bytes()) {
            return Err(Error::CommitMismatch);
        }
        Ok(())
    }

    pub(crate) fn command(&self) -> Command {
        let mut command = self.base_command();
        command.arg("--git-dir").arg(&self.git_dir);
        command
    }

    fn base_command(&self) -> Command {
        let mut command = Command::new(&self.executable);
        command
            .env_clear()
            .env("PATH", &self.path)
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", "/bin/false")
            .env("SSH_ASKPASS", "/bin/false")
            .env("GCM_INTERACTIVE", "never")
            .env("GIT_LFS_SKIP_SMUDGE", "1")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_PROTOCOL_FROM_USER", "0")
            .arg("--no-pager")
            .arg("-c")
            .arg("protocol.allow=never")
            .arg("-c")
            .arg("protocol.https.allow=always")
            .arg("-c")
            .arg("credential.helper=")
            .arg("-c")
            .arg("credential.interactive=false")
            .arg("-c")
            .arg("core.askPass=/bin/false")
            .arg("-c")
            .arg("core.hooksPath=/dev/null")
            .arg("-c")
            .arg("core.fsmonitor=false")
            .arg("-c")
            .arg("fetch.recurseSubmodules=false")
            .arg("-c")
            .arg("fetch.fsckObjects=true")
            .arg("-c")
            .arg("transfer.fsckObjects=true")
            .arg("-c")
            .arg("fetch.writeCommitGraph=false")
            .arg("-c")
            .arg("http.followRedirects=false")
            .arg("-c")
            .arg("filter.lfs.smudge=")
            .arg("-c")
            .arg("filter.lfs.process=")
            .arg("-c")
            .arg("filter.lfs.required=false");
        command
    }

    fn run(mut command: Command, operation: &'static str, limit: usize) -> Result<Vec<u8>> {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|source| Error::GitIo { operation, source })?;
        let stdout = child.stdout.take().ok_or_else(|| Error::InvalidGitOutput {
            operation,
            detail: "stdout pipe is unavailable".to_owned(),
        })?;
        let stderr = child.stderr.take().ok_or_else(|| Error::InvalidGitOutput {
            operation,
            detail: "stderr pipe is unavailable".to_owned(),
        })?;
        let stdout_reader = thread::spawn(move || capture(stdout, limit));
        let stderr_reader = thread::spawn(move || capture(stderr, STDERR_LIMIT));
        let status = child
            .wait()
            .map_err(|source| Error::GitIo { operation, source })?;
        let stdout = join_capture(stdout_reader, operation)?;
        let stderr = join_capture(stderr_reader, operation)?;
        if stdout.exceeded {
            return Err(Error::GitOutputTooLarge { operation, limit });
        }
        if !status.success() {
            return Err(Error::GitFailed {
                operation,
                status: status
                    .code()
                    .map_or_else(|| "signal".to_owned(), |code| code.to_string()),
                stderr: sanitize(&stderr.bytes, stderr.exceeded),
            });
        }
        Ok(stdout.bytes)
    }
}

pub(crate) fn capture(mut reader: impl Read, limit: usize) -> io::Result<CapturedOutput> {
    let mut bytes = Vec::with_capacity(limit.min(8 * 1_024));
    let mut buffer = [0_u8; 8 * 1_024];
    let mut exceeded = false;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let available = limit.saturating_sub(bytes.len());
        let retained = read.min(available);
        bytes.extend_from_slice(&buffer[..retained]);
        exceeded |= retained < read;
    }
    Ok(CapturedOutput { bytes, exceeded })
}

pub(crate) fn join_capture(
    handle: thread::JoinHandle<io::Result<CapturedOutput>>,
    operation: &'static str,
) -> Result<CapturedOutput> {
    handle
        .join()
        .map_err(|_| Error::InvalidGitOutput {
            operation,
            detail: "output reader stopped unexpectedly".to_owned(),
        })?
        .map_err(|source| Error::GitIo { operation, source })
}

pub(crate) fn sanitize(bytes: &[u8], truncated: bool) -> String {
    let mut output = String::with_capacity(bytes.len());
    for character in String::from_utf8_lossy(bytes).chars() {
        if character == '\n' || character == '\t' || !character.is_control() {
            output.push(character);
        } else {
            output.push('?');
        }
    }
    let output = output.trim().to_owned();
    if truncated {
        format!("{output} [truncated]")
    } else if output.is_empty() {
        "no diagnostic output".to_owned()
    } else {
        output
    }
}

pub(crate) fn path_display(path: &[u8]) -> String {
    path.iter()
        .flat_map(|byte| std::ascii::escape_default(*byte))
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use tempfile::Builder;

    use super::SecureGit;
    use crate::Error;

    #[test]
    fn initializes_a_fresh_object_database() {
        let workspace = Builder::new()
            .prefix("verisvm-git-")
            .tempdir()
            .expect("Git workspace");
        let git_dir = workspace.path().join("objects.git");
        let git = SecureGit::new(&find_git(), git_dir.clone()).expect("secure Git");

        git.initialize("sha1").expect("initialized object database");

        assert!(git_dir.join("HEAD").is_file());
        assert!(git_dir.join("objects").is_dir());
    }

    #[test]
    fn rejects_the_file_transport() {
        let workspace = Builder::new()
            .prefix("verisvm-git-")
            .tempdir()
            .expect("Git workspace");
        let git =
            SecureGit::new(&find_git(), workspace.path().join("objects.git")).expect("secure Git");
        git.initialize("sha1").expect("initialized object database");

        let error = git
            .fetch(
                "file:///tmp/verisvm-forbidden-repository",
                "0123456789abcdef0123456789abcdef01234567",
            )
            .expect_err("file transport must fail");

        assert!(matches!(&error, Error::GitFailed { .. }), "{error:?}");
        assert!(error.to_string().contains("transport 'file' not allowed"));
    }

    fn find_git() -> PathBuf {
        let path = std::env::var_os("PATH").unwrap_or_default();
        std::env::split_paths(&path)
            .map(|directory| directory.join("git"))
            .find(|candidate| candidate.is_file())
            .and_then(|candidate| fs::canonicalize(candidate).ok())
            .expect("Git executable")
    }
}
