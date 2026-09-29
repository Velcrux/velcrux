#![no_main]

use libfuzzer_sys::fuzz_target;
use velcrux_core::storage::VPath;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz VPath validate
        if let Ok(vpath) = VPath::validate(s) {
            let _ = vpath.parent();
            let _ = vpath.is_root();

            // Also fuzz symlink target resolution against this valid vpath
            let _ = VPath::validate_symlink_target(&vpath, s);
        }

        // Fuzz validate_symlink_target from root
        let root = VPath::root();
        let _ = VPath::validate_symlink_target(&root, s);
    }
});
