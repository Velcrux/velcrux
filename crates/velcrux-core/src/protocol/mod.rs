//! Wire protocol: encoding, decoding, message catalog.
//!
//! No I/O. No filesystem. No allocation driven by attacker-supplied lengths.
//! Every decoder is a pure function over `&[u8]` so it can be fuzzed in
//! isolation (DEVELOPMENT.md §6, SECURITY.md §1).
//!
//! Layout follows `PROTOCOL.md`:
//!   - §1  conventions (LE, LEB128 varint, u64 sizes, canonical varints)
//!   - §3  framing (control + data)
//!   - §4  message catalog
//!   - §6  capability bitset
//!   - §10 wire error codes

pub mod capabilities;
pub mod error;
pub mod frame;
pub mod limits;
pub mod message;
pub mod varint;

pub use capabilities::{Capabilities, Capability};
pub use error::{ErrorCode, ErrorDetail, ERROR_CODE_NAMES};
pub use frame::{
    DataFrame, DataFrameFlags, DataFrameHeader, DataPreamble, Frame, FrameFlags,
    DATA_FRAME_HEADER_LEN, DATA_MAX_CHUNK_LEN, DATA_PREAMBLE_LEN, FRAME_HEADER_LEN,
};
pub use limits::*;
pub use message::{
    Bye, Commit, Committed, Hello, HelloAck, Limits, Message, Ping, Pong, SessionInit,
    SessionOptions, TransferBegin, TransferCreate, TransferCreated, TransferOp, TransferPlan,
    Verify, VerifyResult, AGENT, BYE, COMMIT, COMMITTED, ERROR, HELLO, HELLO_ACK, PING, PONG,
    SESSION_INIT, TRANSFER_BEGIN, TRANSFER_CREATE, TRANSFER_CREATED, TRANSFER_PLAN, VERIFY,
    VERIFY_RESULT,
};
pub use varint::{decode_varint, encode_varint, varint_len};
