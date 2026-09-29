#![no_main]

use libfuzzer_sys::fuzz_target;
use velcrux_server::config::{parse_size_bytes, ServerConfig};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz size parser
        let _ = parse_size_bytes(s);

        // Fuzz TOML deserializer and validation
        if let Ok(mut cfg) = toml::from_str::<ServerConfig>(s) {
            cfg.apply_env_overrides();
            let _ = cfg.validate();
        }
    }
});
