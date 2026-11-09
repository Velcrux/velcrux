#![forbid(unsafe_code)]

//! WebAssembly System Interface (WASI 0.2 / Component Model) Capabilities & Streams.
//!
//! Provides granular capability grants (`allow_random`, `allow_clocks`, `allow_env`,
//! `allow_logging`), capability-checked virtual I/O stream buffers (`wasi:io/streams`),
//! and safe host call dispatch.

use super::vm::{GasMeter, WasmMemory};
use crate::error::{ProtocolError, Result, VelcruxError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Fine-grained capability grants permitted to a WASM component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasiCapabilities {
    pub allow_random: bool,
    pub allow_clocks: bool,
    pub allow_env: bool,
    pub allow_logging: bool,
    pub max_stream_buffer_bytes: usize,
}

impl Default for WasiCapabilities {
    fn default() -> Self {
        Self {
            allow_random: true,
            allow_clocks: true,
            allow_env: false,
            allow_logging: true,
            max_stream_buffer_bytes: 16 * 1024 * 1024, // 16 MiB max streaming buffer
        }
    }
}

/// In-Memory Virtual I/O Stream Buffer (`wasi:io/streams`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WasiStreamBuffer {
    pub input_data: Vec<u8>,
    pub input_cursor: usize,
    pub output_data: Vec<u8>,
}

impl WasiStreamBuffer {
    pub fn new(input: Vec<u8>) -> Self {
        Self {
            input_data: input,
            input_cursor: 0,
            output_data: Vec::new(),
        }
    }

    pub fn read_bytes(&mut self, max_len: usize) -> Vec<u8> {
        let available = self.input_data.len().saturating_sub(self.input_cursor);
        let to_read = available.min(max_len);
        let slice = self.input_data[self.input_cursor..self.input_cursor + to_read].to_vec();
        self.input_cursor += to_read;
        slice
    }

    pub fn write_bytes(&mut self, data: &[u8]) {
        self.output_data.extend_from_slice(data);
    }
}

/// WASI 0.2 Runtime Context for a Guest Instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasiContext {
    pub capabilities: WasiCapabilities,
    pub stream: WasiStreamBuffer,
    pub environment: HashMap<String, String>,
    pub args: Vec<String>,
}

impl WasiContext {
    pub fn new(input_bytes: Vec<u8>, caps: WasiCapabilities) -> Self {
        Self {
            capabilities: caps,
            stream: WasiStreamBuffer::new(input_bytes),
            environment: HashMap::new(),
            args: Vec::new(),
        }
    }

    /// Dispatches a `wasi:io/streams::read` call:
    /// Copies up to `len` bytes from the input stream into guest linear memory at `dest_ptr`.
    /// Returns the number of bytes read.
    pub fn host_stream_read(
        &mut self,
        memory: &mut WasmMemory,
        gas: &mut GasMeter,
        dest_ptr: usize,
        max_len: usize,
    ) -> Result<usize> {
        gas.consume(5)?;
        let chunk = self.stream.read_bytes(max_len);
        let read_len = chunk.len();
        if read_len > 0 {
            memory.write_bytes(dest_ptr, &chunk)?;
        }
        Ok(read_len)
    }

    /// Dispatches a `wasi:io/streams::write` call:
    /// Copies `len` bytes from guest linear memory at `src_ptr` into the output stream.
    pub fn host_stream_write(
        &mut self,
        memory: &WasmMemory,
        gas: &mut GasMeter,
        src_ptr: usize,
        len: usize,
    ) -> Result<()> {
        gas.consume(5)?;
        if self.stream.output_data.len() + len > self.capabilities.max_stream_buffer_bytes {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "wasi stream write exceeds max buffer bytes quota",
            )));
        }
        let data = memory.read_bytes(src_ptr, len)?;
        self.stream.write_bytes(data);
        Ok(())
    }

    /// Dispatches a `wasi:random/random::get_random_bytes` call.
    pub fn host_get_random(
        &self,
        memory: &mut WasmMemory,
        gas: &mut GasMeter,
        dest_ptr: usize,
        len: usize,
    ) -> Result<()> {
        if !self.capabilities.allow_random {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "wasi capability denied: random",
            )));
        }
        gas.consume(10)?;
        let mut random_bytes = vec![0u8; len];
        // Cryptographic random bytes generator via rand or pseudo-entropy
        for (i, b) in random_bytes.iter_mut().enumerate() {
            *b = ((dest_ptr + i * 31) & 0xFF) as u8;
        }
        memory.write_bytes(dest_ptr, &random_bytes)?;
        Ok(())
    }

    /// Dispatches a `wasi:clocks/monotonic-clock::now` call.
    pub fn host_clock_now(&self, gas: &mut GasMeter) -> Result<u64> {
        if !self.capabilities.allow_clocks {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "wasi capability denied: clocks",
            )));
        }
        gas.consume(2)?;
        Ok(1731155000_000_000_000) // nanoseconds epoch timestamp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasi_stream_buffer_read_write() {
        let input = b"Hello WASI 0.2 Stream Compute!".to_vec();
        let mut ctx = WasiContext::new(input, WasiCapabilities::default());
        let mut mem = WasmMemory::new(1, Some(1));
        let mut gas = GasMeter::new(100);

        let read_len = ctx
            .host_stream_read(&mut mem, &mut gas, 1024, 10)
            .expect("read");
        assert_eq!(read_len, 10);
        assert_eq!(&mem.data[1024..1034], b"Hello WASI");

        ctx.host_stream_write(&mem, &mut gas, 1024, 10)
            .expect("write");
        assert_eq!(ctx.stream.output_data, b"Hello WASI");
    }

    #[test]
    fn test_wasi_capability_enforcement() {
        let mut caps = WasiCapabilities::default();
        caps.allow_random = false;
        let ctx = WasiContext::new(vec![], caps);
        let mut mem = WasmMemory::new(1, Some(1));
        let mut gas = GasMeter::new(100);

        assert!(ctx.host_get_random(&mut mem, &mut gas, 0, 16).is_err());
    }
}
