//! `Secret<T>` newtype with a redacting `Debug`/`Display`.
//!
//! Per `SECURITY.md` §7: never log private keys, key file contents, tokens,
//! signatures, TLS session secrets, TLS exporter output, or full
//! configuration dumps. A `Secret<T>` wrapper guarantees an accidental
//! `format!("{:?}", secret)` prints `[redacted]` instead of the value, and
//! the test in `tests/redacted.rs` exercises a fully-populated config to
//! catch regressions in the wrapper itself.

use std::fmt;

/// A newtype that displays as `[redacted]` in `Debug` and `Display`.
///
/// The inner value is accessible via [`Secret::expose`] (which is the only
/// way to read it; `expose` is a loud name by design) or by destructuring.
#[derive(Clone)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    /// Wrap a value as a secret. Construction is the dangerous step (the
    /// value is in memory and could be observed via memory inspection);
    /// the newtype prevents accidental printing thereafter.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Borrow the inner value. Named `expose` to make the act of reading a
    /// secret visible at the call site.
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Consume the wrapper and return the inner value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[redacted]")
    }
}

impl<T> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[redacted]")
    }
}

// Explicit `PartialEq` so the wrapper still works in test assertions when
// needed, but the comparison goes through the inner type's `PartialEq`.
// (We do NOT implement `Display` for any inner type that could leak.)
impl<T: PartialEq> PartialEq for Secret<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts() {
        let s = Secret::new("super-secret-key");
        assert_eq!(format!("{:?}", s), "[redacted]");
    }

    #[test]
    fn display_redacts() {
        let s = Secret::new("super-secret-key");
        assert_eq!(format!("{}", s), "[redacted]");
    }

    #[test]
    fn expose_returns_value() {
        let s = Secret::new(vec![1u8, 2, 3]);
        assert_eq!(s.expose(), &vec![1, 2, 3]);
    }
}
