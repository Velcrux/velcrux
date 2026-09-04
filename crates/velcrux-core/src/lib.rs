//! velcrux-core
//!
//! Core types and behaviour for the `velcrux` bulk transfer protocol.
//!
//! Layering follows `docs/ARCHITECTURE.md` §1:
//!
//!   protocol  →  transport  →  session  →  (client/server in velcrux-{client,server})
//!
//! Each layer depends only on the one below it. There is no I/O in `protocol`:
//! every decoder is a pure function over `&[u8]` so it can be fuzzed in isolation
//! (DEVELOPMENT.md §6).
//!
//! Invariants from `CLAUDE.md` §1 enforced in this crate:
//!   - No `unsafe` (forbidden via lints).
//!   - No unbounded channels (lints + code review; CI to come).
//!   - All wire sizes/offsets/counters are `u64`; no `u32`/`usize` on the wire
//!     or in persisted structs.
//!   - Every decoder checks length against a named constant *before* allocation.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

pub mod error;
pub mod protocol;
pub mod session;
pub mod transport;
pub mod util;

pub use error::{VelcruxError, Result};
