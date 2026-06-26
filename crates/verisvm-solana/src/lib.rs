mod deployment;
mod error;
mod otter;
mod rpc;

pub use deployment::{PROGRAM_DATA_HEADER_SIZE, decode_program_data, decode_program_pointer};
pub use error::{Error, Result};
pub use otter::{
    OTTER_VERIFY_PROGRAM_ID, ObservedOtterVerifyRecord, OtterVerifyRecord,
    decode_otter_verify_record,
};
pub use rpc::SolanaRpc;
