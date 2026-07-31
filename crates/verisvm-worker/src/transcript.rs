use sha2::{Digest as _, Sha256};
use thiserror::Error;
use verisvm_core::Digest;

const TRANSCRIPT_DOMAIN: &[u8] = b"VERISVM-TRANSCRIPT-V1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Termination {
    Exited(i32),
    Signaled(i32),
    TimedOut,
}

impl Termination {
    #[must_use]
    pub const fn succeeded(self) -> bool {
        matches!(self, Self::Exited(0))
    }

    const fn encoded(self) -> (u8, i32) {
        match self {
            Self::Exited(code) => (0, code),
            Self::Signaled(signal) => (1, signal),
            Self::TimedOut => (2, 0),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranscriptStream {
    Stdout,
    Stderr,
    System,
}

impl TranscriptStream {
    const fn tag(self) -> u8 {
        match self {
            Self::Stdout => 0,
            Self::Stderr => 1,
            Self::System => 2,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranscriptEntry {
    pub sequence: u64,
    pub stream: TranscriptStream,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transcript {
    termination: Termination,
    entries: Vec<TranscriptEntry>,
    byte_len: usize,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum TranscriptError {
    #[error("transcript entries must have contiguous sequence numbers starting at zero")]
    InvalidSequence,
    #[error("transcript byte length overflow")]
    LengthOverflow,
}

impl Transcript {
    pub fn new(
        termination: Termination,
        entries: Vec<TranscriptEntry>,
    ) -> Result<Self, TranscriptError> {
        let mut byte_len = 0_usize;
        for (index, entry) in entries.iter().enumerate() {
            if entry.sequence != u64::try_from(index).expect("entry index fits u64") {
                return Err(TranscriptError::InvalidSequence);
            }
            byte_len = byte_len
                .checked_add(entry.data.len())
                .ok_or(TranscriptError::LengthOverflow)?;
        }
        Ok(Self {
            termination,
            entries,
            byte_len,
        })
    }

    #[must_use]
    pub const fn termination(&self) -> Termination {
        self.termination
    }

    #[must_use]
    pub const fn byte_len(&self) -> usize {
        self.byte_len
    }

    #[must_use]
    pub fn entries(&self) -> &[TranscriptEntry] {
        &self.entries
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        let mut hasher = Sha256::new();
        let (termination_tag, termination_value) = self.termination.encoded();
        hasher.update(TRANSCRIPT_DOMAIN);
        hasher.update([termination_tag]);
        hasher.update(termination_value.to_be_bytes());
        hasher.update(
            u64::try_from(self.entries.len())
                .expect("entry count fits u64")
                .to_be_bytes(),
        );
        for entry in &self.entries {
            hasher.update(entry.sequence.to_be_bytes());
            hasher.update([entry.stream.tag()]);
            hasher.update(
                u64::try_from(entry.data.len())
                    .expect("entry length fits u64")
                    .to_be_bytes(),
            );
            hasher.update(&entry.data);
        }
        Digest::new(hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::{Termination, Transcript, TranscriptEntry, TranscriptError, TranscriptStream};

    #[test]
    fn transcript_hash_commits_to_stream_order_and_status() {
        let entries = vec![
            TranscriptEntry {
                sequence: 0,
                stream: TranscriptStream::Stdout,
                data: b"build".to_vec(),
            },
            TranscriptEntry {
                sequence: 1,
                stream: TranscriptStream::Stderr,
                data: b"warning".to_vec(),
            },
        ];
        let success =
            Transcript::new(Termination::Exited(0), entries.clone()).expect("valid transcript");
        let failure = Transcript::new(Termination::Exited(1), entries).expect("valid transcript");

        assert_ne!(success.digest(), failure.digest());
    }

    #[test]
    fn transcript_rejects_missing_sequence_numbers() {
        let entries = vec![TranscriptEntry {
            sequence: 1,
            stream: TranscriptStream::System,
            data: Vec::new(),
        }];

        assert_eq!(
            Transcript::new(Termination::TimedOut, entries),
            Err(TranscriptError::InvalidSequence)
        );
    }
}
