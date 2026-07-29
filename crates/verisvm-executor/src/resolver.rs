use std::{fs, path::Path};

use tempfile::{Builder, TempDir};
use verisvm_core::{Digest, SourceRevision};
use verisvm_worker::{ExecutionLimits, RepositoryPolicy};

use crate::{Error, Result, git::SecureGit, materialize::materialize, tree::read_tree};

pub struct GitSourceResolver {
    git_executable: std::path::PathBuf,
    repositories: RepositoryPolicy,
}

#[derive(Debug)]
pub struct ResolvedSource {
    _workspace: TempDir,
    source_directory: std::path::PathBuf,
    repository: String,
    commit: String,
    tree_digest: Digest,
    file_count: usize,
    source_bytes: u64,
}

impl GitSourceResolver {
    pub fn new(
        git_executable: impl Into<std::path::PathBuf>,
        repositories: RepositoryPolicy,
    ) -> Result<Self> {
        let git_executable = git_executable.into();
        if !git_executable.is_absolute() {
            return Err(Error::InvalidGitExecutable(
                "path must be absolute".to_owned(),
            ));
        }
        let git_executable = fs::canonicalize(git_executable).map_err(|error| {
            Error::InvalidGitExecutable(format!("cannot resolve path: {error}"))
        })?;
        if !git_executable.is_file() {
            return Err(Error::InvalidGitExecutable(
                "path does not name a file".to_owned(),
            ));
        }
        Ok(Self {
            git_executable,
            repositories,
        })
    }

    pub fn resolve(
        &self,
        source: &SourceRevision,
        limits: &ExecutionLimits,
    ) -> Result<ResolvedSource> {
        self.repositories
            .validate(&source.repository)
            .map_err(Error::InvalidRepository)?;
        limits.validate().map_err(Error::InvalidLimits)?;
        validate_commit(&source.commit)?;
        let workspace = Builder::new()
            .prefix("verisvm-source-")
            .tempdir()
            .map_err(Error::Workspace)?;
        let git_dir = workspace.path().join("objects.git");
        let git = SecureGit::new(&self.git_executable, git_dir)?;
        let object_format = if source.commit.len() == 40 {
            "sha1"
        } else {
            "sha256"
        };
        git.initialize(object_format)?;
        git.fetch(&source.repository, &source.commit)?;
        Self::resolve_prepared(workspace, source, limits, &git)
    }

    fn resolve_prepared(
        workspace: TempDir,
        source: &SourceRevision,
        limits: &ExecutionLimits,
        git: &SecureGit,
    ) -> Result<ResolvedSource> {
        git.verify_commit(&source.commit)?;
        let tree = read_tree(git, &source.commit, limits)?;
        let source_path = workspace.path().join("source");
        fs::create_dir(&source_path).map_err(Error::Workspace)?;
        let tree_digest = materialize(git, &source_path, &tree.entries)?;
        if tree_digest != source.tree_digest {
            return Err(Error::SourceDigestMismatch {
                expected: source.tree_digest,
                observed: tree_digest,
            });
        }
        Ok(ResolvedSource {
            _workspace: workspace,
            source_directory: source_path,
            repository: source.repository.clone(),
            commit: source.commit.clone(),
            tree_digest,
            file_count: tree.entries.len(),
            source_bytes: tree.source_bytes,
        })
    }
}

impl ResolvedSource {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.source_directory
    }

    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    #[must_use]
    pub fn commit(&self) -> &str {
        &self.commit
    }

    #[must_use]
    pub const fn tree_digest(&self) -> Digest {
        self.tree_digest
    }

    #[must_use]
    pub const fn file_count(&self) -> usize {
        self.file_count
    }

    #[must_use]
    pub const fn source_bytes(&self) -> u64 {
        self.source_bytes
    }
}

fn validate_commit(commit: &str) -> Result<()> {
    if !matches!(commit.len(), 40 | 64)
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Error::InvalidCommit);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::{Path, PathBuf},
        process::Command,
    };

    use tempfile::{Builder, TempDir};
    use verisvm_core::{Digest, SourceRevision};
    use verisvm_worker::{
        ExecutionLimits, RepositoryPolicy, SourceMode, SourceTreeEntry, hash_source_tree,
    };

    use super::GitSourceResolver;
    use crate::{Error, git::SecureGit};

    #[test]
    fn resolves_and_materializes_committed_objects() {
        let fixture = Fixture::new();
        let expected = hash_source_tree(&[
            SourceTreeEntry {
                path: b"Cargo.toml",
                mode: SourceMode::Regular,
                content: b"[package]\nname = \"fixture\"\n",
            },
            SourceTreeEntry {
                path: b"README.md",
                mode: SourceMode::Regular,
                content: b"fixture\n",
            },
            SourceTreeEntry {
                path: b"bin/run",
                mode: SourceMode::Executable,
                content: b"run\n",
            },
            SourceTreeEntry {
                path: b"docs/latest",
                mode: SourceMode::Symlink,
                content: b"../README.md",
            },
        ])
        .expect("valid source tree");
        let source = SourceRevision {
            repository: "https://github.com/example/fixture".to_owned(),
            commit: fixture.commit.clone(),
            tree_digest: expected,
        };
        let resolved = fixture.resolve(&source, &ExecutionLimits::default());

        assert_eq!(resolved.tree_digest(), expected);
        assert_eq!(resolved.file_count(), 4);
        assert_eq!(
            fs::read(resolved.path().join("Cargo.toml")).expect("materialized file"),
            b"[package]\nname = \"fixture\"\n"
        );
        assert_eq!(
            fs::read_link(resolved.path().join("docs/latest")).expect("materialized symlink"),
            Path::new("../README.md")
        );
        let executable = fs::metadata(resolved.path().join("bin/run"))
            .expect("executable metadata")
            .permissions()
            .mode();
        assert_ne!(executable & 0o111, 0);
    }

    #[test]
    fn rejects_digest_mismatch_before_returning_a_workspace() {
        let fixture = Fixture::new();
        let source = SourceRevision {
            repository: "https://github.com/example/fixture".to_owned(),
            commit: fixture.commit.clone(),
            tree_digest: Digest::new([99; 32]),
        };
        let error = fixture
            .try_resolve(&source, &ExecutionLimits::default())
            .expect_err("digest mismatch must fail");

        assert!(
            matches!(error, Error::SourceDigestMismatch { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn rejects_total_source_limit_before_materialization() {
        let fixture = Fixture::new();
        let source = SourceRevision {
            repository: "https://github.com/example/fixture".to_owned(),
            commit: fixture.commit.clone(),
            tree_digest: Digest::new([0; 32]),
        };
        let limits = ExecutionLimits {
            source_bytes: 8,
            source_file_bytes: 1_024,
            ..ExecutionLimits::default()
        };
        let error = fixture
            .try_resolve(&source, &limits)
            .expect_err("source limit must fail");

        assert!(matches!(error, Error::SourceTooLarge { .. }));
    }

    #[test]
    fn rejects_symlinks_that_escape_the_source_tree() {
        let fixture = Fixture::with_symlink("../../outside");
        let source = SourceRevision {
            repository: "https://github.com/example/fixture".to_owned(),
            commit: fixture.commit.clone(),
            tree_digest: Digest::new([0; 32]),
        };
        let error = fixture
            .try_resolve(&source, &ExecutionLimits::default())
            .expect_err("escaping symlink must fail");

        assert!(matches!(error, Error::UnsafeSymlink(_)), "{error:?}");
    }

    #[test]
    #[ignore = "requires network access"]
    fn fetches_an_exact_https_commit() {
        let resolver = GitSourceResolver::new(find_git(), RepositoryPolicy::github_only())
            .expect("source resolver");
        let mut source = SourceRevision {
            repository: "https://github.com/octocat/Hello-World.git".to_owned(),
            commit: "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d".to_owned(),
            tree_digest: Digest::new([0; 32]),
        };
        let error = resolver
            .resolve(&source, &ExecutionLimits::default())
            .expect_err("placeholder digest must fail");
        source.tree_digest = match error {
            Error::SourceDigestMismatch { observed, .. } => observed,
            other => panic!("unexpected source resolution error: {other:?}"),
        };
        let checkout = resolver
            .resolve(&source, &ExecutionLimits::default())
            .expect("exact source resolution");

        assert_eq!(checkout.commit(), source.commit);
        assert_eq!(checkout.tree_digest(), source.tree_digest);
    }

    struct Fixture {
        git: PathBuf,
        repository: TempDir,
        commit: String,
    }

    impl Fixture {
        fn new() -> Self {
            Self::with_symlink("../README.md")
        }

        fn with_symlink(target: &str) -> Self {
            let git = find_git();
            let repository = Builder::new()
                .prefix("verisvm-fixture-")
                .tempdir()
                .expect("fixture repository");
            run(&git, repository.path(), ["init", "--quiet"]);
            run(
                &git,
                repository.path(),
                ["config", "user.email", "test@example.com"],
            );
            run(
                &git,
                repository.path(),
                ["config", "user.name", "VeriSVM Test"],
            );
            fs::create_dir_all(repository.path().join("bin")).expect("bin directory");
            fs::create_dir_all(repository.path().join("docs")).expect("docs directory");
            fs::write(
                repository.path().join("Cargo.toml"),
                b"[package]\nname = \"fixture\"\n",
            )
            .expect("manifest");
            fs::write(repository.path().join("README.md"), b"fixture\n").expect("readme");
            fs::write(repository.path().join("bin/run"), b"run\n").expect("executable");
            let mut permissions = fs::metadata(repository.path().join("bin/run"))
                .expect("executable metadata")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(repository.path().join("bin/run"), permissions)
                .expect("executable mode");
            symlink(target, repository.path().join("docs/latest")).expect("symlink");
            run(&git, repository.path(), ["add", "--all"]);
            run(
                &git,
                repository.path(),
                ["commit", "--quiet", "-m", "fixture"],
            );
            let commit = output(&git, repository.path(), ["rev-parse", "HEAD"]);
            Self {
                git,
                repository,
                commit,
            }
        }

        fn resolve(
            &self,
            source: &SourceRevision,
            limits: &ExecutionLimits,
        ) -> super::ResolvedSource {
            self.try_resolve(source, limits).expect("resolved source")
        }

        fn try_resolve(
            &self,
            source: &SourceRevision,
            limits: &ExecutionLimits,
        ) -> crate::Result<super::ResolvedSource> {
            let workspace = Builder::new()
                .prefix("verisvm-resolved-")
                .tempdir()
                .expect("resolved workspace");
            let git_dir = workspace.path().join("objects.git");
            let source_path = self.repository.path().to_string_lossy().into_owned();
            let git_dir_path = git_dir.to_string_lossy().into_owned();
            run(
                &self.git,
                workspace.path(),
                ["clone", "--quiet", "--bare", &source_path, &git_dir_path],
            );
            let secure_git = SecureGit::new(&self.git, git_dir)?;
            GitSourceResolver::resolve_prepared(workspace, source, limits, &secure_git)
        }
    }

    fn find_git() -> PathBuf {
        let path = std::env::var_os("PATH").unwrap_or_default();
        std::env::split_paths(&path)
            .map(|directory| directory.join("git"))
            .find(|candidate| candidate.is_file())
            .and_then(|candidate| fs::canonicalize(candidate).ok())
            .expect("Git executable")
    }

    fn run<const N: usize>(git: &Path, directory: &Path, arguments: [&str; N]) {
        let status = Command::new(git)
            .current_dir(directory)
            .args(arguments)
            .status()
            .expect("Git command");
        assert!(status.success());
    }

    fn output<const N: usize>(git: &Path, directory: &Path, arguments: [&str; N]) -> String {
        let output = Command::new(git)
            .current_dir(directory)
            .args(arguments)
            .output()
            .expect("Git command");
        assert!(output.status.success());
        String::from_utf8(output.stdout)
            .expect("UTF-8 Git output")
            .trim()
            .to_owned()
    }
}
