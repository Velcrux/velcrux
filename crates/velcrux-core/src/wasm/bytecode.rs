#![forbid(unsafe_code)]

//! WebAssembly (WASM) Binary Format Parser and Disassembler (W3C WASM Core / WASI 0.2).
//!
//! Decodes WebAssembly 1.0/2.0 binary modules: magic header (`\0asm`), version,
//! and standard sections: Type, Import, Function, Table, Memory, Global, Export, Code.

use crate::error::{ProtocolError, Result, VelcruxError};
use serde::{Deserialize, Serialize};

pub const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D]; // "\0asm"
pub const WASM_VERSION: [u8; 4] = [0x01, 0x00, 0x00, 0x00]; // Version 1

pub const SECTION_ID_CUSTOM: u8 = 0;
pub const SECTION_ID_TYPE: u8 = 1;
pub const SECTION_ID_IMPORT: u8 = 2;
pub const SECTION_ID_FUNCTION: u8 = 3;
pub const SECTION_ID_TABLE: u8 = 4;
pub const SECTION_ID_MEMORY: u8 = 5;
pub const SECTION_ID_GLOBAL: u8 = 6;
pub const SECTION_ID_EXPORT: u8 = 7;
pub const SECTION_ID_START: u8 = 8;
pub const SECTION_ID_ELEMENT: u8 = 9;
pub const SECTION_ID_CODE: u8 = 10;
pub const SECTION_ID_DATA: u8 = 11;

/// Value types supported by WebAssembly core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WasmValType {
    I32,
    I64,
    F32,
    F64,
}

impl WasmValType {
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0x7F => Ok(Self::I32),
            0x7E => Ok(Self::I64),
            0x7D => Ok(Self::F32),
            0x7C => Ok(Self::F64),
            _other => Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "unknown wasm valtype",
            ))),
        }
    }

    pub fn to_byte(self) -> u8 {
        match self {
            Self::I32 => 0x7F,
            Self::I64 => 0x7E,
            Self::F32 => 0x7D,
            Self::F64 => 0x7C,
        }
    }
}

/// Function type signature (parameters and return types).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmFuncType {
    pub params: Vec<WasmValType>,
    pub returns: Vec<WasmValType>,
}

/// Export descriptor pointing to a function, table, memory, or global.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WasmExportDesc {
    Func(u32),
    Table(u32),
    Mem(u32),
    Global(u32),
}

/// Named exported entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmExport {
    pub name: String,
    pub desc: WasmExportDesc,
}

/// Imported host item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmImport {
    pub module: String,
    pub name: String,
    pub desc: WasmExportDesc,
}

/// Linear memory limits (initial and optional maximum pages of 64 KiB).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmMemLimits {
    pub initial_pages: u32,
    pub max_pages: Option<u32>,
}

/// Decoded WebAssembly bytecode instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WasmOp {
    Unreachable,
    Nop,
    Block(Option<WasmValType>),
    Loop(Option<WasmValType>),
    If(Option<WasmValType>),
    Else,
    End,
    Br(u32),
    BrIf(u32),
    Return,
    Call(u32),
    Drop,
    Select,
    LocalGet(u32),
    LocalSet(u32),
    LocalTee(u32),
    GlobalGet(u32),
    GlobalSet(u32),
    I32Load { offset: u32, align: u32 },
    I64Load { offset: u32, align: u32 },
    I32Load8U { offset: u32, align: u32 },
    I32Store { offset: u32, align: u32 },
    I64Store { offset: u32, align: u32 },
    I32Store8 { offset: u32, align: u32 },
    MemorySize,
    MemoryGrow,
    I32Const(i32),
    I64Const(i64),
    I32Eqz,
    I32Eq,
    I32Ne,
    I32LtS,
    I32LtU,
    I32GtS,
    I32GtU,
    I32LeS,
    I32LeU,
    I32GeS,
    I32GeU,
    I32Add,
    I32Sub,
    I32Mul,
    I32DivS,
    I32DivU,
    I32RemU,
    I32And,
    I32Or,
    I32Xor,
    I32Shl,
    I32ShrS,
    I32ShrU,
    I64Add,
    I64Sub,
    I64Mul,
    I64And,
    I64Or,
    I64Xor,
}

/// Function body with local variable counts and instructions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmFuncBody {
    pub locals: Vec<(u32, WasmValType)>,
    pub instructions: Vec<WasmOp>,
}

/// Parsed WebAssembly module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmModule {
    pub types: Vec<WasmFuncType>,
    pub imports: Vec<WasmImport>,
    pub functions: Vec<u32>, // Type index per defined function
    pub memories: Vec<WasmMemLimits>,
    pub exports: Vec<WasmExport>,
    pub code: Vec<WasmFuncBody>,
}

impl WasmModule {
    /// Parses a WebAssembly binary module from bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "wasm binary too short for header",
            )));
        }

        if bytes[0..4] != WASM_MAGIC {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "invalid wasm magic header",
            )));
        }

        if bytes[4..8] != WASM_VERSION {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "unsupported wasm binary version",
            )));
        }

        let mut offset = 8;
        let mut types = Vec::new();
        let mut imports = Vec::new();
        let mut functions = Vec::new();
        let mut memories = Vec::new();
        let mut exports = Vec::new();
        let mut code = Vec::new();

        while offset < bytes.len() {
            let section_id = bytes[offset];
            offset += 1;

            let (section_len, len_bytes) = read_u32_leb128(&bytes[offset..])?;
            offset += len_bytes;

            if offset + (section_len as usize) > bytes.len() {
                return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                    "wasm section exceeds buffer bounds",
                )));
            }

            let section_data = &bytes[offset..offset + (section_len as usize)];
            offset += section_len as usize;

            match section_id {
                SECTION_ID_TYPE => {
                    types = parse_type_section(section_data)?;
                }
                SECTION_ID_IMPORT => {
                    imports = parse_import_section(section_data)?;
                }
                SECTION_ID_FUNCTION => {
                    functions = parse_function_section(section_data)?;
                }
                SECTION_ID_MEMORY => {
                    memories = parse_memory_section(section_data)?;
                }
                SECTION_ID_EXPORT => {
                    exports = parse_export_section(section_data)?;
                }
                SECTION_ID_CODE => {
                    code = parse_code_section(section_data)?;
                }
                _ => {
                    // Ignore optional / custom / data sections
                }
            }
        }

        Ok(Self {
            types,
            imports,
            functions,
            memories,
            exports,
            code,
        })
    }

    /// Finds the index of an exported function by name.
    pub fn find_export_func(&self, name: &str) -> Option<u32> {
        self.exports.iter().find_map(|e| {
            if e.name == name {
                if let WasmExportDesc::Func(idx) = e.desc {
                    Some(idx)
                } else {
                    None
                }
            } else {
                None
            }
        })
    }
}

// ---------------- Helper LEB128 decoders & Section Parsers ----------------

pub fn read_u32_leb128(data: &[u8]) -> Result<(u32, usize)> {
    let mut result = 0u32;
    let mut shift = 0;
    let mut bytes_read = 0;

    for &b in data {
        bytes_read += 1;
        result |= ((b & 0x7F) as u32) << shift;
        if (b & 0x80) == 0 {
            return Ok((result, bytes_read));
        }
        shift += 7;
        if shift >= 35 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "leb128 integer overflow",
            )));
        }
    }

    Err(VelcruxError::Protocol(ProtocolError::Malformed(
        "unexpected end of leb128 stream",
    )))
}

pub fn read_i32_leb128(data: &[u8]) -> Result<(i32, usize)> {
    let mut result = 0i32;
    let mut shift = 0;
    let mut bytes_read = 0;
    let mut byte = 0u8;

    for &b in data {
        byte = b;
        bytes_read += 1;
        result |= ((b & 0x7F) as i32) << shift;
        shift += 7;
        if (b & 0x80) == 0 {
            break;
        }
        if shift >= 35 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "leb128 signed integer overflow",
            )));
        }
    }

    if shift < 32 && (byte & 0x40) != 0 {
        result |= !0i32 << shift;
    }

    Ok((result, bytes_read))
}

fn parse_type_section(data: &[u8]) -> Result<Vec<WasmFuncType>> {
    let mut offset = 0;
    let (count, bytes_read) = read_u32_leb128(&data[offset..])?;
    offset += bytes_read;

    let mut types = Vec::with_capacity(count as usize);
    for _ in 0..count {
        if offset >= data.len() || data[offset] != 0x60 {
            return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                "invalid func type form byte (expected 0x60)",
            )));
        }
        offset += 1;

        let (param_count, b_params) = read_u32_leb128(&data[offset..])?;
        offset += b_params;

        let mut params = Vec::with_capacity(param_count as usize);
        for _ in 0..param_count {
            params.push(WasmValType::from_byte(data[offset])?);
            offset += 1;
        }

        let (ret_count, b_ret) = read_u32_leb128(&data[offset..])?;
        offset += b_ret;

        let mut returns = Vec::with_capacity(ret_count as usize);
        for _ in 0..ret_count {
            returns.push(WasmValType::from_byte(data[offset])?);
            offset += 1;
        }

        types.push(WasmFuncType { params, returns });
    }

    Ok(types)
}

fn parse_import_section(data: &[u8]) -> Result<Vec<WasmImport>> {
    let mut offset = 0;
    let (count, bytes_read) = read_u32_leb128(&data[offset..])?;
    offset += bytes_read;

    let mut imports = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (mod_len, b_mod) = read_u32_leb128(&data[offset..])?;
        offset += b_mod;
        let module = String::from_utf8_lossy(&data[offset..offset + mod_len as usize]).to_string();
        offset += mod_len as usize;

        let (name_len, b_name) = read_u32_leb128(&data[offset..])?;
        offset += b_name;
        let name = String::from_utf8_lossy(&data[offset..offset + name_len as usize]).to_string();
        offset += name_len as usize;

        let kind = data[offset];
        offset += 1;
        let (idx, b_idx) = read_u32_leb128(&data[offset..])?;
        offset += b_idx;

        let desc = match kind {
            0 => WasmExportDesc::Func(idx),
            1 => WasmExportDesc::Table(idx),
            2 => WasmExportDesc::Mem(idx),
            3 => WasmExportDesc::Global(idx),
            _ => {
                return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                    "invalid import desc kind",
                )))
            }
        };

        imports.push(WasmImport { module, name, desc });
    }

    Ok(imports)
}

fn parse_function_section(data: &[u8]) -> Result<Vec<u32>> {
    let mut offset = 0;
    let (count, bytes_read) = read_u32_leb128(&data[offset..])?;
    offset += bytes_read;

    let mut funcs = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (type_idx, b_idx) = read_u32_leb128(&data[offset..])?;
        offset += b_idx;
        funcs.push(type_idx);
    }

    Ok(funcs)
}

fn parse_memory_section(data: &[u8]) -> Result<Vec<WasmMemLimits>> {
    let mut offset = 0;
    let (count, bytes_read) = read_u32_leb128(&data[offset..])?;
    offset += bytes_read;

    let mut mems = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let flags = data[offset];
        offset += 1;
        let (initial, b_init) = read_u32_leb128(&data[offset..])?;
        offset += b_init;

        let max = if (flags & 1) != 0 {
            let (m, b_max) = read_u32_leb128(&data[offset..])?;
            offset += b_max;
            Some(m)
        } else {
            None
        };

        mems.push(WasmMemLimits {
            initial_pages: initial,
            max_pages: max,
        });
    }

    Ok(mems)
}

fn parse_export_section(data: &[u8]) -> Result<Vec<WasmExport>> {
    let mut offset = 0;
    let (count, bytes_read) = read_u32_leb128(&data[offset..])?;
    offset += bytes_read;

    let mut exports = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (name_len, b_name) = read_u32_leb128(&data[offset..])?;
        offset += b_name;
        let name = String::from_utf8_lossy(&data[offset..offset + name_len as usize]).to_string();
        offset += name_len as usize;

        let kind = data[offset];
        offset += 1;
        let (idx, b_idx) = read_u32_leb128(&data[offset..])?;
        offset += b_idx;

        let desc = match kind {
            0 => WasmExportDesc::Func(idx),
            1 => WasmExportDesc::Table(idx),
            2 => WasmExportDesc::Mem(idx),
            3 => WasmExportDesc::Global(idx),
            _ => {
                return Err(VelcruxError::Protocol(ProtocolError::Malformed(
                    "invalid export desc kind",
                )))
            }
        };

        exports.push(WasmExport { name, desc });
    }

    Ok(exports)
}

fn parse_code_section(data: &[u8]) -> Result<Vec<WasmFuncBody>> {
    let mut offset = 0;
    let (count, bytes_read) = read_u32_leb128(&data[offset..])?;
    offset += bytes_read;

    let mut bodies = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (body_size, b_size) = read_u32_leb128(&data[offset..])?;
        offset += b_size;

        let body_end = offset + body_size as usize;
        let (local_vec_count, b_lcount) = read_u32_leb128(&data[offset..body_end])?;
        offset += b_lcount;

        let mut locals = Vec::with_capacity(local_vec_count as usize);
        for _ in 0..local_vec_count {
            let (l_count, b_lc) = read_u32_leb128(&data[offset..body_end])?;
            offset += b_lc;
            let val_type = WasmValType::from_byte(data[offset])?;
            offset += 1;
            locals.push((l_count, val_type));
        }

        let mut instructions = Vec::new();
        while offset < body_end {
            let opcode = data[offset];
            offset += 1;

            let op = match opcode {
                0x00 => WasmOp::Unreachable,
                0x01 => WasmOp::Nop,
                0x02 => {
                    let b = data[offset];
                    offset += 1;
                    WasmOp::Block(if b == 0x40 {
                        None
                    } else {
                        Some(WasmValType::from_byte(b)?)
                    })
                }
                0x03 => {
                    let b = data[offset];
                    offset += 1;
                    WasmOp::Loop(if b == 0x40 {
                        None
                    } else {
                        Some(WasmValType::from_byte(b)?)
                    })
                }
                0x04 => {
                    let b = data[offset];
                    offset += 1;
                    WasmOp::If(if b == 0x40 {
                        None
                    } else {
                        Some(WasmValType::from_byte(b)?)
                    })
                }
                0x05 => WasmOp::Else,
                0x0B => WasmOp::End,
                0x0C => {
                    let (depth, b_d) = read_u32_leb128(&data[offset..body_end])?;
                    offset += b_d;
                    WasmOp::Br(depth)
                }
                0x0D => {
                    let (depth, b_d) = read_u32_leb128(&data[offset..body_end])?;
                    offset += b_d;
                    WasmOp::BrIf(depth)
                }
                0x0F => WasmOp::Return,
                0x10 => {
                    let (fidx, b_f) = read_u32_leb128(&data[offset..body_end])?;
                    offset += b_f;
                    WasmOp::Call(fidx)
                }
                0x1A => WasmOp::Drop,
                0x1B => WasmOp::Select,
                0x20 => {
                    let (lidx, b_l) = read_u32_leb128(&data[offset..body_end])?;
                    offset += b_l;
                    WasmOp::LocalGet(lidx)
                }
                0x21 => {
                    let (lidx, b_l) = read_u32_leb128(&data[offset..body_end])?;
                    offset += b_l;
                    WasmOp::LocalSet(lidx)
                }
                0x22 => {
                    let (lidx, b_l) = read_u32_leb128(&data[offset..body_end])?;
                    offset += b_l;
                    WasmOp::LocalTee(lidx)
                }
                0x28 => {
                    let (align, b_a) = read_u32_leb128(&data[offset..body_end])?;
                    offset += b_a;
                    let (off, b_o) = read_u32_leb128(&data[offset..body_end])?;
                    offset += b_o;
                    WasmOp::I32Load { offset: off, align }
                }
                0x29 => {
                    let (align, b_a) = read_u32_leb128(&data[offset..body_end])?;
                    offset += b_a;
                    let (off, b_o) = read_u32_leb128(&data[offset..body_end])?;
                    offset += b_o;
                    WasmOp::I64Load { offset: off, align }
                }
                0x2D => {
                    let (align, b_a) = read_u32_leb128(&data[offset..body_end])?;
                    offset += b_a;
                    let (off, b_o) = read_u32_leb128(&data[offset..body_end])?;
                    offset += b_o;
                    WasmOp::I32Load8U { offset: off, align }
                }
                0x36 => {
                    let (align, b_a) = read_u32_leb128(&data[offset..body_end])?;
                    offset += b_a;
                    let (off, b_o) = read_u32_leb128(&data[offset..body_end])?;
                    offset += b_o;
                    WasmOp::I32Store { offset: off, align }
                }
                0x37 => {
                    let (align, b_a) = read_u32_leb128(&data[offset..body_end])?;
                    offset += b_a;
                    let (off, b_o) = read_u32_leb128(&data[offset..body_end])?;
                    offset += b_o;
                    WasmOp::I64Store { offset: off, align }
                }
                0x3A => {
                    let (align, b_a) = read_u32_leb128(&data[offset..body_end])?;
                    offset += b_a;
                    let (off, b_o) = read_u32_leb128(&data[offset..body_end])?;
                    offset += b_o;
                    WasmOp::I32Store8 { offset: off, align }
                }
                0x3F => {
                    offset += 1; // 0x00 reserved byte
                    WasmOp::MemorySize
                }
                0x40 => {
                    offset += 1; // 0x00 reserved byte
                    WasmOp::MemoryGrow
                }
                0x41 => {
                    let (val, b_val) = read_i32_leb128(&data[offset..body_end])?;
                    offset += b_val;
                    WasmOp::I32Const(val)
                }
                0x45 => WasmOp::I32Eqz,
                0x46 => WasmOp::I32Eq,
                0x47 => WasmOp::I32Ne,
                0x48 => WasmOp::I32LtS,
                0x49 => WasmOp::I32LtU,
                0x4A => WasmOp::I32GtS,
                0x4B => WasmOp::I32GtU,
                0x4C => WasmOp::I32LeS,
                0x4D => WasmOp::I32LeU,
                0x4E => WasmOp::I32GeS,
                0x4F => WasmOp::I32GeU,
                0x6A => WasmOp::I32Add,
                0x6B => WasmOp::I32Sub,
                0x6C => WasmOp::I32Mul,
                0x6D => WasmOp::I32DivS,
                0x6E => WasmOp::I32DivU,
                0x71 => WasmOp::I32And,
                0x72 => WasmOp::I32Or,
                0x73 => WasmOp::I32Xor,
                0x74 => WasmOp::I32Shl,
                0x75 => WasmOp::I32ShrS,
                0x76 => WasmOp::I32ShrU,
                0x7C => WasmOp::I64Add,
                0x7D => WasmOp::I64Sub,
                0x7E => WasmOp::I64Mul,
                0x83 => WasmOp::I64And,
                0x84 => WasmOp::I64Or,
                0x85 => WasmOp::I64Xor,
                _ => {
                    // Unknown or unsupported opcode in MVP
                    WasmOp::Nop
                }
            };
            instructions.push(op);
        }

        bodies.push(WasmFuncBody {
            locals,
            instructions,
        });
    }

    Ok(bodies)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leb128_roundtrip() {
        let val = 624485u32;
        let mut buf = Vec::new();
        let mut v = val;
        while v >= 0x80 {
            buf.push(((v & 0x7F) | 0x80) as u8);
            v >>= 7;
        }
        buf.push(v as u8);

        let (decoded, len) = read_u32_leb128(&buf).unwrap();
        assert_eq!(decoded, val);
        assert_eq!(len, buf.len());
    }

    #[test]
    fn test_empty_wasm_module_header() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&WASM_MAGIC);
        bytes.extend_from_slice(&WASM_VERSION);

        let module = WasmModule::parse(&bytes).expect("parse empty module");
        assert_eq!(module.types.len(), 0);
        assert_eq!(module.exports.len(), 0);
    }
}
