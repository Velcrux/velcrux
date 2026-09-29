#![no_main]

use libfuzzer_sys::fuzz_target;
use velcrux_core::protocol::frame::{decode_data_frame_header, decode_data_preamble, decode_frame};
use velcrux_core::protocol::message::Message;
use velcrux_core::protocol::varint::decode_varint;

fuzz_target!(|data: &[u8]| {
    // 1. Fuzz general frame decoder
    if let Ok(frame) = decode_frame(data) {
        // If a frame was decoded, try decoding its message payload
        let _ = Message::decode(frame.type_byte, frame.payload);
    }

    // 2. Fuzz data frame header decoder
    let _ = decode_data_frame_header(data);

    // 3. Fuzz data preamble decoder
    let _ = decode_data_preamble(data);

    // 4. Fuzz varint decoder directly
    let _ = decode_varint(data);
});
