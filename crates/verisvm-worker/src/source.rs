use std::cmp::Ordering;

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use verisvm_core::Digest;

const SOURCE_TREE_DOMAIN: &[u8] = b"VERISVM-SOURCE-TREE-V1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceMode {
    Regular,
    Executable,
    Symlink,
}

impl SourceMode {
    const fn tag(self) -> u8 {
        match self {
            Self::Regular => 0,
            Self::Executable => 1,
            Self::Symlink => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceTreeEntry<'a> {
    pub path: &'a [u8],
    pub mode: SourceMode,
    pub content: &'a [u8],
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SourceTreeError {
    #[error("source tree is empty")]
    Empty,
    #[error("source tree path is invalid")]
    InvalidPath,
    #[error("source tree contains a duplicate path")]
    DuplicatePath,
    #[error("source tree paths are not in bytewise order")]
    OutOfOrderPath,
    #[error("source tree entry content is incomplete")]
    IncompleteEntry,
    #[error("source tree entry content exceeds its declared length")]
    ContentLengthExceeded,
    #[error("source tree entry count differs from its declared count")]
    EntryCountMismatch,
    #[error("source tree length cannot be represented")]
    LengthOverflow,
}

pub struct SourceTreeHasher {
    hasher: Sha256,
    expected_entries: u64,
    processed_entries: u64,
    previous_path: Vec<u8>,
    remaining_content: Option<u64>,
}

impl SourceTreeHasher {
    pub fn new(expected_entries: usize) -> Result<Self, SourceTreeError> {
        if expected_entries == 0 {
            return Err(SourceTreeError::Empty);
        }
        let expected_entries =
            u64::try_from(expected_entries).map_err(|_| SourceTreeError::LengthOverflow)?;
        let mut hasher = Sha256::new();
        hasher.update(SOURCE_TREE_DOMAIN);
        hasher.update(expected_entries.to_be_bytes());
        Ok(Self {
            hasher,
            expected_entries,
            processed_entries: 0,
            previous_path: Vec::new(),
            remaining_content: None,
        })
    }

    pub fn begin_entry(
        &mut self,
        path: &[u8],
        mode: SourceMode,
        content_len: u64,
    ) -> Result<(), SourceTreeError> {
        if self.remaining_content.is_some() {
            return Err(SourceTreeError::IncompleteEntry);
        }
        if self.processed_entries == self.expected_entries {
            return Err(SourceTreeError::EntryCountMismatch);
        }
        validate_source_path(path)?;
        match self.previous_path.as_slice().cmp(path) {
            Ordering::Equal => return Err(SourceTreeError::DuplicatePath),
            Ordering::Greater => return Err(SourceTreeError::OutOfOrderPath),
            Ordering::Less => {}
        }
        self.hasher.update([mode.tag()]);
        self.hasher.update(
            u64::try_from(path.len())
                .map_err(|_| SourceTreeError::LengthOverflow)?
                .to_be_bytes(),
        );
        self.hasher.update(path);
        self.hasher.update(content_len.to_be_bytes());
        self.previous_path.clear();
        self.previous_path.extend_from_slice(path);
        self.remaining_content = Some(content_len);
        Ok(())
    }

    pub fn update(&mut self, content: &[u8]) -> Result<(), SourceTreeError> {
        let remaining = self
            .remaining_content
            .as_mut()
            .ok_or(SourceTreeError::IncompleteEntry)?;
        let content_len =
            u64::try_from(content.len()).map_err(|_| SourceTreeError::LengthOverflow)?;
        if content_len > *remaining {
            return Err(SourceTreeError::ContentLengthExceeded);
        }
        self.hasher.update(content);
        *remaining -= content_len;
        Ok(())
    }

    pub fn end_entry(&mut self) -> Result<(), SourceTreeError> {
        match self.remaining_content {
            Some(0) => {
                self.remaining_content = None;
                self.processed_entries += 1;
                Ok(())
            }
            Some(_) | None => Err(SourceTreeError::IncompleteEntry),
        }
    }

    pub fn finish(self) -> Result<Digest, SourceTreeError> {
        if self.remaining_content.is_some() {
            return Err(SourceTreeError::IncompleteEntry);
        }
        if self.processed_entries != self.expected_entries {
            return Err(SourceTreeError::EntryCountMismatch);
        }
        Ok(Digest::new(self.hasher.finalize().into()))
    }
}

pub fn hash_source_tree(entries: &[SourceTreeEntry<'_>]) -> Result<Digest, SourceTreeError> {
    let mut sorted = entries.to_vec();
    sorted.sort_unstable_by(|left, right| left.path.cmp(right.path));
    let mut hasher = SourceTreeHasher::new(sorted.len())?;
    for entry in sorted {
        let content_len =
            u64::try_from(entry.content.len()).map_err(|_| SourceTreeError::LengthOverflow)?;
        hasher.begin_entry(entry.path, entry.mode, content_len)?;
        hasher.update(entry.content)?;
        hasher.end_entry()?;
    }
    hasher.finish()
}

pub fn validate_source_path(path: &[u8]) -> Result<(), SourceTreeError> {
    if path.is_empty()
        || path.starts_with(b"/")
        || path.ends_with(b"/")
        || path.contains(&0)
        || path.split(|byte| *byte == b'/').any(|part| {
            part.is_empty() || matches!(part, b"." | b"..") || part.eq_ignore_ascii_case(b".git")
        })
    {
        return Err(SourceTreeError::InvalidPath);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{SourceMode, SourceTreeEntry, SourceTreeError, SourceTreeHasher, hash_source_tree};

    #[test]
    fn tree_hash_is_independent_of_entry_order() {
        let first = SourceTreeEntry {
            path: b"Cargo.toml",
            mode: SourceMode::Regular,
            content: b"package",
        };
        let second = SourceTreeEntry {
            path: b"src/lib.rs",
            mode: SourceMode::Regular,
            content: b"pub fn run() {}",
        };

        assert_eq!(
            hash_source_tree(&[first, second]).expect("valid tree"),
            hash_source_tree(&[second, first]).expect("valid tree")
        );
    }

    #[test]
    fn tree_hash_commits_to_mode_path_and_content() {
        let base = SourceTreeEntry {
            path: b"bin/run",
            mode: SourceMode::Regular,
            content: b"run",
        };
        let executable = SourceTreeEntry {
            mode: SourceMode::Executable,
            ..base
        };
        let renamed = SourceTreeEntry {
            path: b"bin/start",
            ..base
        };
        let changed = SourceTreeEntry {
            content: b"start",
            ..base
        };
        let digest = hash_source_tree(&[base]).expect("valid tree");

        assert_ne!(digest, hash_source_tree(&[executable]).expect("valid tree"));
        assert_ne!(digest, hash_source_tree(&[renamed]).expect("valid tree"));
        assert_ne!(digest, hash_source_tree(&[changed]).expect("valid tree"));
    }

    #[test]
    fn tree_hash_rejects_ambiguous_paths() {
        let entry = SourceTreeEntry {
            path: b"src/../secret",
            mode: SourceMode::Regular,
            content: b"secret",
        };

        assert_eq!(
            hash_source_tree(&[entry]),
            Err(SourceTreeError::InvalidPath)
        );
    }

    #[test]
    fn streaming_hash_matches_in_memory_hash() {
        let entries = [
            SourceTreeEntry {
                path: b"Cargo.toml",
                mode: SourceMode::Regular,
                content: b"package",
            },
            SourceTreeEntry {
                path: b"src/lib.rs",
                mode: SourceMode::Executable,
                content: b"pub fn run() {}",
            },
        ];
        let mut hasher = SourceTreeHasher::new(entries.len()).expect("valid entry count");
        for entry in entries {
            hasher
                .begin_entry(
                    entry.path,
                    entry.mode,
                    u64::try_from(entry.content.len()).expect("content length fits"),
                )
                .expect("valid entry");
            for chunk in entry.content.chunks(3) {
                hasher.update(chunk).expect("valid content");
            }
            hasher.end_entry().expect("complete entry");
        }

        assert_eq!(
            hasher.finish().expect("complete tree"),
            hash_source_tree(&entries).expect("valid tree")
        );
    }

    #[test]
    fn streaming_hash_rejects_out_of_order_entries() {
        let mut hasher = SourceTreeHasher::new(2).expect("valid entry count");
        hasher
            .begin_entry(b"src/lib.rs", SourceMode::Regular, 0)
            .expect("valid first entry");
        hasher.end_entry().expect("complete first entry");

        assert_eq!(
            hasher.begin_entry(b"Cargo.toml", SourceMode::Regular, 0),
            Err(SourceTreeError::OutOfOrderPath)
        );
    }

    #[test]
    fn streaming_hash_rejects_incomplete_content() {
        let mut hasher = SourceTreeHasher::new(1).expect("valid entry count");
        hasher
            .begin_entry(b"Cargo.toml", SourceMode::Regular, 8)
            .expect("valid entry");
        hasher.update(b"short").expect("bounded content");

        assert_eq!(hasher.end_entry(), Err(SourceTreeError::IncompleteEntry));
    }
}
