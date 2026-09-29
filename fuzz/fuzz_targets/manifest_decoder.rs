#![no_main]

use libfuzzer_sys::fuzz_target;
use velcrux_core::manifest::codec::{decode_chunk_desc, decode_file_entry, validate_xattrs_security};
use velcrux_core::manifest::reader::ManifestBatchDecoder;
use velcrux_core::protocol::message::ManifestBatch;
use velcrux_core::util::Hash;

fuzz_target!(|data: &[u8]| {
    // 1. Fuzz direct FileEntry decoder
    if let Ok((entry, _)) = decode_file_entry(data) {
        let _ = validate_xattrs_security(&entry.xattrs, false);
        let _ = validate_xattrs_security(&entry.xattrs, true);
    }

    // 2. Fuzz direct ChunkDesc decoder
    let _ = decode_chunk_desc(data);

    // 3. Fuzz ManifestBatch message decode and streaming batch reader
    if let Ok(batch) = ManifestBatch::decode(data) {
        let mut decoder = ManifestBatchDecoder::new(Hash::ZERO);
        let _ = decoder.decode_batch(&batch);
    }
});
