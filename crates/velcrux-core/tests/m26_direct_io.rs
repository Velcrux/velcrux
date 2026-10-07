//! Integration test suite for Milestone Option AH:
//! Kernel Zero-Copy, Page-Cache Bypass & Direct I/O (`O_DIRECT`) Aligned Sector Engine
//! (`REQUIREMENTS.md` §26, §27, `docs/ARCHITECTURE.md` §2).

use tempfile::tempdir;
use velcrux_core::storage::direct_io::{
    AlignedSectorBuffer, DirectFileReader, DirectFileWriter, DirectIoConfig, DirectIoMode,
    DEFAULT_SECTOR_SIZE,
};

#[test]
fn test_aligned_sector_buffer_pointer_alignment_invariants() {
    // 1. Default 4096-byte sector alignment
    let mut buf = AlignedSectorBuffer::new(8192, DEFAULT_SECTOR_SIZE);
    assert_eq!(buf.alignment(), 4096);
    assert!(buf.is_aligned(), "buffer must be 4096-byte aligned");
    assert_eq!(buf.data_ptr() % 4096, 0);
    assert_eq!(buf.len(), 0);
    assert!(buf.capacity() >= 8192);

    // Append data
    let test_data = vec![0x42u8; 1024];
    let appended = buf.append(&test_data);
    assert_eq!(appended, 1024);
    assert_eq!(buf.len(), 1024);
    assert_eq!(buf.as_slice(), &test_data[..]);
    assert!(buf.is_aligned());

    // 2. Various power-of-two alignments (512, 1024, 2048, 8192)
    for align in [512, 1024, 2048, 4096, 8192] {
        let b = AlignedSectorBuffer::new(16384, align);
        assert_eq!(b.alignment(), align);
        assert!(b.is_aligned(), "alignment must hold for {align}");
        assert_eq!(b.data_ptr() % align, 0);
    }

    // 3. Dynamic resizing while preserving alignment
    buf.resize(12000, 0xAA);
    assert!(buf.is_aligned(), "alignment must be preserved after resize");
    assert_eq!(buf.len(), 12000);
    assert_eq!(buf.as_slice()[0], 0x42); // original data preserved
    assert_eq!(buf.as_slice()[1024], 0xAA); // filled with value
}

#[test]
fn test_direct_io_mode_parsing_and_serde() {
    assert_eq!("auto".parse::<DirectIoMode>().unwrap(), DirectIoMode::Auto);
    assert_eq!("AUTO".parse::<DirectIoMode>().unwrap(), DirectIoMode::Auto);
    assert_eq!(
        "always".parse::<DirectIoMode>().unwrap(),
        DirectIoMode::Always
    );
    assert_eq!(
        "force".parse::<DirectIoMode>().unwrap(),
        DirectIoMode::Always
    );
    assert_eq!(
        "disabled".parse::<DirectIoMode>().unwrap(),
        DirectIoMode::Disabled
    );
    assert_eq!(
        "none".parse::<DirectIoMode>().unwrap(),
        DirectIoMode::Disabled
    );
    assert_eq!(
        "off".parse::<DirectIoMode>().unwrap(),
        DirectIoMode::Disabled
    );
    assert!("invalid_mode".parse::<DirectIoMode>().is_err());

    assert_eq!(DirectIoMode::Auto.to_string(), "auto");
    assert_eq!(DirectIoMode::Always.to_string(), "always");
    assert_eq!(DirectIoMode::Disabled.to_string(), "disabled");

    let serialized = serde_json::to_string(&DirectIoMode::Auto).unwrap();
    let deserialized: DirectIoMode = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, DirectIoMode::Auto);
}

#[test]
fn test_direct_io_sector_aligned_roundtrip() {
    let temp = tempdir().unwrap();
    let file_path = temp.path().join("aligned_test.bin");

    // 64 KiB = exactly 16 sectors of 4096 bytes
    let total_size = 64 * 1024;
    let mut payload = Vec::with_capacity(total_size);
    for i in 0..total_size {
        payload.push((i % 251) as u8);
    }
    let original_hash = blake3::hash(&payload);

    let config = DirectIoConfig {
        mode: DirectIoMode::Auto,
        sector_size: DEFAULT_SECTOR_SIZE,
        min_file_size: 4096, // low threshold to engage Direct I/O in test
    };

    // 1. Write via DirectFileWriter using non-aligned streaming chunk sizes
    let mut writer = DirectFileWriter::create(&file_path, Some(total_size as u64), &config)
        .expect("create writer");

    for chunk in payload.chunks(1337) {
        writer.write_chunk(chunk).expect("write chunk");
    }
    let written = writer.finish().expect("finish writer");
    assert_eq!(written, total_size as u64);

    let disk_size = std::fs::metadata(&file_path).unwrap().len();
    assert_eq!(disk_size, total_size as u64);

    // 2. Read back via DirectFileReader
    let mut reader = DirectFileReader::open(&file_path, &config).expect("open reader");
    assert_eq!(reader.file_size(), total_size as u64);

    let mut read_bytes = Vec::new();
    while let Some(block) = reader.read_block().expect("read block") {
        read_bytes.extend_from_slice(block);
    }

    assert_eq!(read_bytes.len(), total_size);
    assert_eq!(read_bytes, payload);
    assert_eq!(blake3::hash(&read_bytes), original_hash);
}

#[test]
fn test_direct_io_odd_size_fractional_tail_truncation() {
    let temp = tempdir().unwrap();
    let file_path = temp.path().join("odd_test.bin");

    // 70,001 bytes = 17 full 4096-byte sectors + 369 trailing fractional bytes
    let total_size = 70001;
    let mut payload = Vec::with_capacity(total_size);
    for i in 0..total_size {
        payload.push(((i * 7 + 13) % 256) as u8);
    }
    let original_hash = blake3::hash(&payload);

    let config = DirectIoConfig {
        mode: DirectIoMode::Auto,
        sector_size: DEFAULT_SECTOR_SIZE,
        min_file_size: 4096,
    };

    // 1. Write via DirectFileWriter
    let mut writer = DirectFileWriter::create(&file_path, Some(total_size as u64), &config)
        .expect("create writer");

    for chunk in payload.chunks(3000) {
        writer.write_chunk(chunk).expect("write chunk");
    }
    let written = writer.finish().expect("finish writer");
    assert_eq!(written, total_size as u64);

    // Verify exact file size on disk (padding was truncated away)
    let disk_size = std::fs::metadata(&file_path).unwrap().len();
    assert_eq!(disk_size, total_size as u64);

    // 2. Read back via DirectFileReader
    let mut reader = DirectFileReader::open(&file_path, &config).expect("open reader");
    assert_eq!(reader.file_size(), total_size as u64);

    let mut read_bytes = Vec::new();
    while let Some(block) = reader.read_block().expect("read block") {
        read_bytes.extend_from_slice(block);
    }

    assert_eq!(read_bytes.len(), total_size);
    assert_eq!(read_bytes, payload);
    assert_eq!(blake3::hash(&read_bytes), original_hash);
}

#[test]
fn test_direct_io_disabled_buffered_fallback() {
    let temp = tempdir().unwrap();
    let file_path = temp.path().join("disabled_test.bin");

    let payload = b"standard buffered streaming fallback payload without direct I/O";
    let config = DirectIoConfig {
        mode: DirectIoMode::Disabled,
        sector_size: DEFAULT_SECTOR_SIZE,
        min_file_size: 0,
    };

    let mut writer = DirectFileWriter::create(&file_path, Some(payload.len() as u64), &config)
        .expect("create writer");
    assert!(!writer.is_direct());
    writer.write_chunk(payload).unwrap();
    writer.finish().unwrap();

    let mut reader = DirectFileReader::open(&file_path, &config).expect("open reader");
    assert!(!reader.is_direct());
    let mut read_bytes = Vec::new();
    while let Some(block) = reader.read_block().unwrap() {
        read_bytes.extend_from_slice(block);
    }
    assert_eq!(read_bytes, payload);
}
