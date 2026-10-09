//! Raven wire protocol: encoding, decoding, message catalog.
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
pub mod compression;
pub mod error;
pub mod frame;
pub mod fuzzing;
pub mod limits;
pub mod message;
pub mod varint;

pub use capabilities::{Capabilities, Capability};
pub use compression::{
    compress_if_beneficial, compress_payload, compute_shannon_entropy, decompress_payload_bounded,
    estimate_entropy, AdaptiveCompressionConfig, AdaptiveCompressionSelector,
    AdaptiveCompressionStats, CompressionDecision, EntropyTier, DEFAULT_ENTROPY_BYPASS_THRESHOLD,
    DEFAULT_ZSTD_LEVEL, FAST_ZSTD_LEVEL, HIGH_ZSTD_LEVEL,
};
pub use error::{ErrorCode, ErrorDetail, ERROR_CODE_NAMES};
pub use frame::{
    decode_data_frame_encrypted, decode_data_frame_header, decode_data_preamble, decode_frame,
    encode_data_frame, encode_data_frame_adaptive, encode_data_frame_encrypted,
    encode_data_frame_header, encode_data_frame_maybe_compressed, encode_data_preamble,
    encode_frame, header_size_for, max_message_size, DataFrame, DataFrameFlags, DataFrameHeader,
    DataPreamble, Frame, FrameFlags, DATA_FRAME_HEADER_LEN, DATA_MAX_CHUNK_LEN, DATA_PREAMBLE_LEN,
    FRAME_HEADER_LEN,
};
pub use fuzzing::{assert_decoder_panic_free, assert_no_panic, FuzzMutator};
pub use limits::*;
pub use message::{
    Auth, AuthOk, Bye, Cancel, Checkpoint, ChunkQuery, ChunkResponse, Commit, Committed, ErrorMsg,
    Hello, HelloAck, InventoryHint, Limits, ListQuery, ListResult, ManifestBatch, ManifestBegin,
    ManifestEnd, Message, Ping, Pong, Resume, ResumeState, SessionInit, SessionOptions, StatQuery,
    StatResult, TransferBegin, TransferCreate, TransferCreated, TransferOp, TransferPlan, Verify,
    VerifyResult, AGENT, AUTH, AUTH_OK, BYE, CANCEL, CHECKPOINT, CHUNK_QUERY, CHUNK_RESPONSE,
    COMMIT, COMMITTED, ERROR, HELLO, HELLO_ACK, INVENTORY_HINT, LIST, LIST_RESULT, MANIFEST_BATCH,
    MANIFEST_BEGIN, MANIFEST_END, PING, PONG, RESUME, RESUME_STATE, SESSION_INIT, STAT,
    STAT_RESULT, TRANSFER_BEGIN, TRANSFER_CREATE, TRANSFER_CREATED, TRANSFER_PLAN, VERIFY,
    VERIFY_RESULT,
};
pub use varint::{decode_varint, encode_varint, varint_len};
