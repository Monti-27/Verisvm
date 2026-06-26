use sha2::{Digest as _, Sha256};
use verisvm_core::{Digest, SolanaAddress};

use crate::{Error, Result};

pub const PROGRAM_DATA_HEADER_SIZE: usize = 45;
const PROGRAM_VARIANT: u32 = 2;
const PROGRAM_DATA_VARIANT: u32 = 3;

pub fn decode_program_pointer(data: &[u8]) -> Result<SolanaAddress> {
    if read_u32(data, 0)? != PROGRAM_VARIANT {
        return Err(Error::InvalidLoaderAccount(
            "expected a program account".to_owned(),
        ));
    }
    let bytes = data
        .get(4..36)
        .ok_or_else(|| Error::InvalidLoaderAccount("program account is truncated".to_owned()))?
        .try_into()
        .map_err(|_| Error::InvalidLoaderAccount("program address is truncated".to_owned()))?;
    Ok(SolanaAddress::new(bytes))
}

pub fn decode_program_data(data: &[u8]) -> Result<(u64, Option<SolanaAddress>, Digest)> {
    if data.len() < PROGRAM_DATA_HEADER_SIZE || read_u32(data, 0)? != PROGRAM_DATA_VARIANT {
        return Err(Error::InvalidLoaderAccount(
            "expected a program-data account".to_owned(),
        ));
    }

    let slot = u64::from_le_bytes(
        data[4..12]
            .try_into()
            .map_err(|_| Error::InvalidLoaderAccount("deployment slot is truncated".to_owned()))?,
    );
    let authority = match data[12] {
        0 => None,
        1 => Some(SolanaAddress::new(data[13..45].try_into().map_err(
            |_| Error::InvalidLoaderAccount("upgrade authority is truncated".to_owned()),
        )?)),
        value => {
            return Err(Error::InvalidLoaderAccount(format!(
                "invalid authority option: {value}"
            )));
        }
    };
    let executable = trim_trailing_zeroes(&data[PROGRAM_DATA_HEADER_SIZE..]);
    if executable.is_empty() {
        return Err(Error::InvalidLoaderAccount(
            "program executable is empty".to_owned(),
        ));
    }
    let executable_digest = Digest::new(Sha256::digest(executable).into());
    Ok((slot, authority, executable_digest))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| {
            Error::InvalidLoaderAccount("account discriminator is truncated".to_owned())
        })?
        .try_into()
        .map_err(|_| Error::InvalidLoaderAccount("account discriminator is invalid".to_owned()))?;
    Ok(u32::from_le_bytes(bytes))
}

fn trim_trailing_zeroes(data: &[u8]) -> &[u8] {
    let length = data
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |index| index + 1);
    &data[..length]
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};
    use verisvm_core::{Digest, SolanaAddress};

    use super::{PROGRAM_DATA_HEADER_SIZE, decode_program_data, decode_program_pointer};

    #[test]
    fn decodes_upgradeable_program_pointer() {
        let mut data = vec![0_u8; 36];
        data[..4].copy_from_slice(&2_u32.to_le_bytes());
        data[4..].copy_from_slice(&[7; 32]);

        assert_eq!(
            decode_program_pointer(&data).expect("valid program account"),
            SolanaAddress::new([7; 32])
        );
    }

    #[test]
    fn decodes_program_data_and_ignores_allocation_padding() {
        let mut data = vec![0_u8; PROGRAM_DATA_HEADER_SIZE + 6];
        data[..4].copy_from_slice(&3_u32.to_le_bytes());
        data[4..12].copy_from_slice(&400_u64.to_le_bytes());
        data[12] = 1;
        data[13..45].copy_from_slice(&[8; 32]);
        data[45..48].copy_from_slice(&[1, 2, 3]);

        let (slot, authority, digest) = decode_program_data(&data).expect("valid program data");

        assert_eq!(slot, 400);
        assert_eq!(authority, Some(SolanaAddress::new([8; 32])));
        assert_eq!(digest, Digest::new(Sha256::digest([1, 2, 3]).into()));
    }
}
