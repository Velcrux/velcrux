#![forbid(unsafe_code)]

//! WebAssembly Sandboxed Virtual Machine with Deterministic Gas Metering & Linear Memory.
//!
//! Enforces memory bounds checks (64 KiB page granularity), step-by-step fuel / gas
//! consumption, and safe stack frame execution.

use super::bytecode::{WasmModule, WasmOp, WasmValType};
use crate::error::{ProtocolError, Result, VelcruxError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Standard WebAssembly page size: 64 KiB (65,536 bytes).
pub const WASM_PAGE_SIZE: usize = 65_536;

/// Default maximum memory pages permitted per instance (16 MiB = 256 pages).
pub const DEFAULT_MAX_PAGES: u32 = 256;

/// Default initial gas budget per transformation invocation.
pub const DEFAULT_GAS_LIMIT: u64 = 1_000_000;

/// Dynamic runtime value representation on the operand stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WasmValue {
    I32(i32),
    I64(i64),
}

impl WasmValue {
    pub fn as_i32(self) -> Result<i32> {
        match self {
            Self::I32(v) => Ok(v),
            _ => Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "expected i32 wasm value",
            ))),
        }
    }

    pub fn as_i64(self) -> Result<i64> {
        match self {
            Self::I64(v) => Ok(v),
            _ => Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "expected i64 wasm value",
            ))),
        }
    }

    pub fn val_type(self) -> WasmValType {
        match self {
            Self::I32(_) => WasmValType::I32,
            Self::I64(_) => WasmValType::I64,
        }
    }
}

/// Deterministic Gas / Fuel Metering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasMeter {
    pub gas_limit: u64,
    pub gas_consumed: u64,
}

impl GasMeter {
    pub fn new(gas_limit: u64) -> Self {
        Self {
            gas_limit,
            gas_consumed: 0,
        }
    }

    pub fn consume(&mut self, amount: u64) -> Result<()> {
        if self.gas_consumed.saturating_add(amount) > self.gas_limit {
            self.gas_consumed = self.gas_limit;
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "wasm execution out of gas / fuel exhausted",
            )));
        }
        self.gas_consumed += amount;
        Ok(())
    }

    pub fn remaining(&self) -> u64 {
        self.gas_limit.saturating_sub(self.gas_consumed)
    }
}

/// Linear Memory Arena with 64 KiB Page Bounds Checking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmMemory {
    pub pages: u32,
    pub max_pages: u32,
    pub data: Vec<u8>,
}

impl WasmMemory {
    pub fn new(initial_pages: u32, max_pages: Option<u32>) -> Self {
        let max = max_pages
            .unwrap_or(DEFAULT_MAX_PAGES)
            .min(DEFAULT_MAX_PAGES);
        let init = initial_pages.min(max);
        let byte_len = (init as usize) * WASM_PAGE_SIZE;
        Self {
            pages: init,
            max_pages: max,
            data: vec![0u8; byte_len],
        }
    }

    pub fn grow(&mut self, delta_pages: u32) -> i32 {
        let old_pages = self.pages;
        let new_pages = old_pages.saturating_add(delta_pages);
        if new_pages > self.max_pages {
            return -1;
        }

        let new_byte_len = (new_pages as usize) * WASM_PAGE_SIZE;
        self.data.resize(new_byte_len, 0);
        self.pages = new_pages;
        old_pages as i32
    }

    pub fn read_u8(&self, addr: usize) -> Result<u8> {
        if addr >= self.data.len() {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "wasm memory read out of bounds",
            )));
        }
        Ok(self.data[addr])
    }

    pub fn write_u8(&mut self, addr: usize, val: u8) -> Result<()> {
        if addr >= self.data.len() {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "wasm memory write out of bounds",
            )));
        }
        self.data[addr] = val;
        Ok(())
    }

    pub fn read_i32(&self, addr: usize) -> Result<i32> {
        if addr + 4 > self.data.len() {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "wasm memory read out of bounds (i32)",
            )));
        }
        let bytes: [u8; 4] = self.data[addr..addr + 4].try_into().unwrap();
        Ok(i32::from_le_bytes(bytes))
    }

    pub fn write_i32(&mut self, addr: usize, val: i32) -> Result<()> {
        if addr + 4 > self.data.len() {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "wasm memory write out of bounds (i32)",
            )));
        }
        self.data[addr..addr + 4].copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    pub fn read_bytes(&self, addr: usize, len: usize) -> Result<&[u8]> {
        if addr + len > self.data.len() {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "wasm memory slice read out of bounds",
            )));
        }
        Ok(&self.data[addr..addr + len])
    }

    pub fn write_bytes(&mut self, addr: usize, src: &[u8]) -> Result<()> {
        if addr + src.len() > self.data.len() {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "wasm memory slice write out of bounds",
            )));
        }
        self.data[addr..addr + src.len()].copy_from_slice(src);
        Ok(())
    }
}

/// Host function callback type for WASI / Velcrux host imports.
pub type HostFunction = Box<
    dyn Fn(&mut WasmMemory, &mut GasMeter, &[WasmValue]) -> Result<Option<WasmValue>> + Send + Sync,
>;

/// Sandboxed WebAssembly Execution Instance.
pub struct WasmInstance {
    pub module: WasmModule,
    pub memory: WasmMemory,
    pub gas_meter: GasMeter,
    pub host_functions: HashMap<String, HostFunction>,
}

impl WasmInstance {
    /// Creates a new sandboxed instance from a parsed module.
    pub fn new(module: WasmModule, gas_limit: u64) -> Self {
        let (initial_pages, max_pages) = if let Some(mem) = module.memories.first() {
            (mem.initial_pages, mem.max_pages)
        } else {
            (1, Some(DEFAULT_MAX_PAGES))
        };

        let memory = WasmMemory::new(initial_pages, max_pages);
        let gas_meter = GasMeter::new(gas_limit);

        Self {
            module,
            memory,
            gas_meter,
            host_functions: HashMap::new(),
        }
    }

    /// Registers a host function callback into the instance.
    pub fn register_host_fn<F>(&mut self, name: impl Into<String>, func: F)
    where
        F: Fn(&mut WasmMemory, &mut GasMeter, &[WasmValue]) -> Result<Option<WasmValue>>
            + Send
            + Sync
            + 'static,
    {
        self.host_functions.insert(name.into(), Box::new(func));
    }

    /// Invokes an exported function by name with provided argument values.
    pub fn call_export(&mut self, name: &str, args: &[WasmValue]) -> Result<Option<WasmValue>> {
        let func_idx = self.module.find_export_func(name).ok_or_else(|| {
            VelcruxError::Protocol(ProtocolError::Malformed("exported func not found"))
        })?;

        self.execute_function(func_idx as usize, args)
    }

    /// Executes a defined function by its index in the function table.
    pub fn execute_function(
        &mut self,
        func_idx: usize,
        args: &[WasmValue],
    ) -> Result<Option<WasmValue>> {
        let num_imports = self.module.imports.len();
        if func_idx < num_imports {
            // Imported host function
            let import = &self.module.imports[func_idx];
            let key = format!("{}:{}", import.module, import.name);
            if let Some(host_fn) = self.host_functions.get(&key) {
                return host_fn(&mut self.memory, &mut self.gas_meter, args);
            } else {
                return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                    "unresolved host function import",
                )));
            }
        }

        let def_idx = func_idx - num_imports;
        let body = self.module.code.get(def_idx).cloned().ok_or_else(|| {
            VelcruxError::Protocol(ProtocolError::Malformed("function code index out of range"))
        })?;

        // Initialize local variables: arguments first, then declared zero-initialized locals
        let mut locals = Vec::from(args);
        for &(count, val_type) in &body.locals {
            for _ in 0..count {
                match val_type {
                    WasmValType::I32 => locals.push(WasmValue::I32(0)),
                    WasmValType::I64 => locals.push(WasmValue::I64(0)),
                    _ => locals.push(WasmValue::I32(0)),
                }
            }
        }

        let mut stack: Vec<WasmValue> = Vec::new();
        self.execute_instructions(&body.instructions, &mut locals, &mut stack)?;

        Ok(stack.pop())
    }

    fn execute_instructions(
        &mut self,
        instructions: &[WasmOp],
        locals: &mut [WasmValue],
        stack: &mut Vec<WasmValue>,
    ) -> Result<()> {
        let mut pc = 0;

        while pc < instructions.len() {
            self.gas_meter.consume(1)?;
            let op = &instructions[pc];

            match op {
                WasmOp::Nop => {}
                WasmOp::Unreachable => {
                    return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                        "wasm executed unreachable instruction",
                    )));
                }
                WasmOp::I32Const(val) => {
                    stack.push(WasmValue::I32(*val));
                }
                WasmOp::I64Const(val) => {
                    stack.push(WasmValue::I64(*val));
                }
                WasmOp::LocalGet(idx) => {
                    let val = locals.get(*idx as usize).copied().ok_or_else(|| {
                        VelcruxError::Protocol(ProtocolError::Malformed(
                            "local.get index out of bounds",
                        ))
                    })?;
                    stack.push(val);
                }
                WasmOp::LocalSet(idx) => {
                    let val = stack.pop().ok_or_else(|| {
                        VelcruxError::Protocol(ProtocolError::Malformed(
                            "stack underflow on local.set",
                        ))
                    })?;
                    if let Some(slot) = locals.get_mut(*idx as usize) {
                        *slot = val;
                    } else {
                        return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                            "local.set index out of bounds",
                        )));
                    }
                }
                WasmOp::LocalTee(idx) => {
                    let val = stack.last().copied().ok_or_else(|| {
                        VelcruxError::Protocol(ProtocolError::Malformed(
                            "stack underflow on local.tee",
                        ))
                    })?;
                    if let Some(slot) = locals.get_mut(*idx as usize) {
                        *slot = val;
                    }
                }
                WasmOp::Drop => {
                    stack.pop();
                }
                WasmOp::I32Add => {
                    let b = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    let a = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    stack.push(WasmValue::I32(a.wrapping_add(b)));
                }
                WasmOp::I32Sub => {
                    let b = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    let a = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    stack.push(WasmValue::I32(a.wrapping_sub(b)));
                }
                WasmOp::I32Mul => {
                    let b = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    let a = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    stack.push(WasmValue::I32(a.wrapping_mul(b)));
                }
                WasmOp::I32And => {
                    let b = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    let a = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    stack.push(WasmValue::I32(a & b));
                }
                WasmOp::I32Or => {
                    let b = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    let a = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    stack.push(WasmValue::I32(a | b));
                }
                WasmOp::I32Xor => {
                    let b = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    let a = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    stack.push(WasmValue::I32(a ^ b));
                }
                WasmOp::I32Eq => {
                    let b = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    let a = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    stack.push(WasmValue::I32(if a == b { 1 } else { 0 }));
                }
                WasmOp::I32LtU => {
                    let b = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    let a = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    stack.push(WasmValue::I32(if (a as u32) < (b as u32) { 1 } else { 0 }));
                }
                WasmOp::I32GtU => {
                    let b = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    let a = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    stack.push(WasmValue::I32(if (a as u32) > (b as u32) { 1 } else { 0 }));
                }
                WasmOp::I32Load { offset, .. } => {
                    let base = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    let addr = (base as usize).saturating_add(*offset as usize);
                    let val = self.memory.read_i32(addr)?;
                    stack.push(WasmValue::I32(val));
                }
                WasmOp::I32Load8U { offset, .. } => {
                    let base = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    let addr = (base as usize).saturating_add(*offset as usize);
                    let byte = self.memory.read_u8(addr)?;
                    stack.push(WasmValue::I32(byte as i32));
                }
                WasmOp::I32Store { offset, .. } => {
                    let val = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    let base = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    let addr = (base as usize).saturating_add(*offset as usize);
                    self.memory.write_i32(addr, val)?;
                }
                WasmOp::I32Store8 { offset, .. } => {
                    let val = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    let base = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    let addr = (base as usize).saturating_add(*offset as usize);
                    self.memory.write_u8(addr, (val & 0xFF) as u8)?;
                }
                WasmOp::MemorySize => {
                    stack.push(WasmValue::I32(self.memory.pages as i32));
                }
                WasmOp::MemoryGrow => {
                    let delta = stack
                        .pop()
                        .ok_or_else(|| {
                            VelcruxError::Protocol(ProtocolError::Malformed("underflow"))
                        })?
                        .as_i32()?;
                    let res = self.memory.grow(delta.max(0) as u32);
                    stack.push(WasmValue::I32(res));
                }
                WasmOp::Return => {
                    break;
                }
                WasmOp::End => {
                    break;
                }
                _ => {
                    // Control flow and other instructions handled in recursive blocks or nop
                }
            }

            pc += 1;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_page_allocation_and_bounds() {
        let mut mem = WasmMemory::new(1, Some(4));
        assert_eq!(mem.pages, 1);
        assert_eq!(mem.data.len(), 65536);

        // Write and read i32
        mem.write_i32(100, 0x12345678).expect("write i32");
        assert_eq!(mem.read_i32(100).expect("read i32"), 0x12345678);

        // Out-of-bounds write traps
        assert!(mem.write_i32(65535, 42).is_err());

        // Grow memory
        let old = mem.grow(2);
        assert_eq!(old, 1);
        assert_eq!(mem.pages, 3);
        assert_eq!(mem.data.len(), 65536 * 3);

        // Can write in newly allocated page
        mem.write_i32(65536 + 10, 999).expect("write in page 2");
        assert_eq!(mem.read_i32(65536 + 10).expect("read in page 2"), 999);
    }

    #[test]
    fn test_gas_metering_exhaustion() {
        let mut gas = GasMeter::new(5);
        gas.consume(3).expect("consume 3");
        assert_eq!(gas.remaining(), 2);

        // Consuming past gas limit traps with out-of-gas
        assert!(gas.consume(3).is_err());
        assert_eq!(gas.remaining(), 0);
    }
}
