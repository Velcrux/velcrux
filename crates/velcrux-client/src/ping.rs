//! `velcrux ping` — the M1 exit test.

use anyhow::Context;
use velcrux_core::session::ClientSession;

/// Send a PING and await the matching PONG. Returns round-trip time in
/// milliseconds.
pub async fn ping(session: &mut ClientSession) -> anyhow::Result<u64> {
    let rtt = session
        .ping()
        .await
        .context("PING/PONG round trip failed")?;
    Ok(rtt)
}
