#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use velcrux_core::sync::batch::BatchContainerReader;

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let tmp = std::env::temp_dir();
    let _ = BatchContainerReader::unpack(&mut cursor, &tmp);
});
