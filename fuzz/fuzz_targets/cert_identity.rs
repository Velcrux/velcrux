#![no_main]

use libfuzzer_sys::fuzz_target;
use rustls::Certificate;
use velcrux_core::transport::quic::identity_from_chain;

fuzz_target!(|data: &[u8]| {
    let cert = Certificate(data.to_vec());
    let _ = identity_from_chain(&[cert]);
});
