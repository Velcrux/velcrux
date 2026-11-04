//! Canonical 64-bit eBPF Instruction Set, Assembler, Verifier, and VM (`ADR-066`).
//!
//! Implements a pure safe-Rust (`#![forbid(unsafe_code)]`) eBPF virtual machine
//! and bytecode toolchain for wire-speed in-kernel packet filtering, QUIC connection ID
//! demuxing, and AF_XDP socket queue steering.

use serde::{Deserialize, Serialize};

use crate::error::VelcruxError;
use crate::xdp::XdpAction;

// ---------------------------------------------------------------------------
// 1. eBPF Instruction Encoding & Opcodes
// ---------------------------------------------------------------------------

// Instruction Classes (bits 0..2)
pub const BPF_CLASS_LD: u8 = 0x00;
pub const BPF_CLASS_LDX: u8 = 0x01;
pub const BPF_CLASS_ST: u8 = 0x02;
pub const BPF_CLASS_STX: u8 = 0x03;
pub const BPF_CLASS_ALU32: u8 = 0x04;
pub const BPF_CLASS_JMP: u8 = 0x05;
pub const BPF_CLASS_JMP32: u8 = 0x06;
pub const BPF_CLASS_ALU64: u8 = 0x07;

// Size modifiers for LD/ST
pub const BPF_SIZE_W: u8 = 0x00; // 32-bit word
pub const BPF_SIZE_H: u8 = 0x08; // 16-bit halfword
pub const BPF_SIZE_B: u8 = 0x10; // 8-bit byte
pub const BPF_SIZE_DW: u8 = 0x18; // 64-bit doubleword

// Mode modifiers for LD/ST
pub const BPF_MODE_IMM: u8 = 0x00;
pub const BPF_MODE_ABS: u8 = 0x20;
pub const BPF_MODE_IND: u8 = 0x40;
pub const BPF_MODE_MEM: u8 = 0x60;

// Source modifier (bit 3)
pub const BPF_SRC_IMM: u8 = 0x00; // immediate
pub const BPF_SRC_REG: u8 = 0x08; // register

// ALU Operations (bits 4..7)
pub const BPF_ALU_ADD: u8 = 0x00;
pub const BPF_ALU_SUB: u8 = 0x10;
pub const BPF_ALU_MUL: u8 = 0x20;
pub const BPF_ALU_DIV: u8 = 0x30;
pub const BPF_ALU_OR: u8 = 0x40;
pub const BPF_ALU_AND: u8 = 0x50;
pub const BPF_ALU_LSH: u8 = 0x60;
pub const BPF_ALU_RSH: u8 = 0x70;
pub const BPF_ALU_NEG: u8 = 0x80;
pub const BPF_ALU_MOD: u8 = 0x90;
pub const BPF_ALU_XOR: u8 = 0xa0;
pub const BPF_ALU_MOV: u8 = 0xb0;
pub const BPF_ALU_ARSH: u8 = 0xc0;

// Jump Operations (bits 4..7)
pub const BPF_JMP_JA: u8 = 0x00;
pub const BPF_JMP_JEQ: u8 = 0x10;
pub const BPF_JMP_JGT: u8 = 0x20;
pub const BPF_JMP_JGE: u8 = 0x30;
pub const BPF_JMP_JSET: u8 = 0x40;
pub const BPF_JMP_JNE: u8 = 0x50;
pub const BPF_JMP_JSGT: u8 = 0x60;
pub const BPF_JMP_JSGE: u8 = 0x70;
pub const BPF_JMP_CALL: u8 = 0x80;
pub const BPF_JMP_EXIT: u8 = 0x90;
pub const BPF_JMP_JLT: u8 = 0xa0;
pub const BPF_JMP_JLE: u8 = 0xb0;

/// BPF Register Index (0..=10).
pub const BPF_REG_0: u8 = 0; // Return value
pub const BPF_REG_1: u8 = 1; // Function arg 1 / context pointer (xdp_md)
pub const BPF_REG_2: u8 = 2; // Function arg 2
pub const BPF_REG_3: u8 = 3; // Function arg 3
pub const BPF_REG_4: u8 = 4; // Function arg 4
pub const BPF_REG_5: u8 = 5; // Function arg 5
pub const BPF_REG_6: u8 = 6; // Callee-saved
pub const BPF_REG_7: u8 = 7; // Callee-saved
pub const BPF_REG_8: u8 = 8; // Callee-saved
pub const BPF_REG_9: u8 = 9; // Callee-saved
pub const BPF_REG_10: u8 = 10; // Read-only stack frame pointer

/// An 8-byte eBPF instruction following the standard Linux BPF kernel specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfInsn {
    /// Opcode combining class, operation, and modifiers.
    pub opcode: u8,
    /// Destination register (4 bits, 0..=10).
    pub dst_reg: u8,
    /// Source register (4 bits, 0..=10).
    pub src_reg: u8,
    /// Signed 16-bit offset for memory addressing or jump targets.
    pub off: i16,
    /// Signed 32-bit immediate constant.
    pub imm: i32,
}

impl EbpfInsn {
    /// Create a raw instruction.
    pub const fn new(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self {
            opcode,
            dst_reg: dst,
            src_reg: src,
            off,
            imm,
        }
    }

    /// `dst = imm` (64-bit ALU immediate move)
    pub const fn mov64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_CLASS_ALU64 | BPF_SRC_IMM | BPF_ALU_MOV, dst, 0, 0, imm)
    }

    /// `dst = src` (64-bit ALU register move)
    pub const fn mov64_reg(dst: u8, src: u8) -> Self {
        Self::new(BPF_CLASS_ALU64 | BPF_SRC_REG | BPF_ALU_MOV, dst, src, 0, 0)
    }

    /// `dst += imm` (64-bit ALU add immediate)
    pub const fn add64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_CLASS_ALU64 | BPF_SRC_IMM | BPF_ALU_ADD, dst, 0, 0, imm)
    }

    /// `dst += src` (64-bit ALU add register)
    pub const fn add64_reg(dst: u8, src: u8) -> Self {
        Self::new(BPF_CLASS_ALU64 | BPF_SRC_REG | BPF_ALU_ADD, dst, src, 0, 0)
    }

    /// `dst -= imm` (64-bit ALU sub immediate)
    pub const fn sub64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_CLASS_ALU64 | BPF_SRC_IMM | BPF_ALU_SUB, dst, 0, 0, imm)
    }

    /// `dst &= imm` (64-bit ALU and immediate)
    pub const fn and64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_CLASS_ALU64 | BPF_SRC_IMM | BPF_ALU_AND, dst, 0, 0, imm)
    }

    /// `dst ^= src` (64-bit ALU xor register)
    pub const fn xor64_reg(dst: u8, src: u8) -> Self {
        Self::new(BPF_CLASS_ALU64 | BPF_SRC_REG | BPF_ALU_XOR, dst, src, 0, 0)
    }

    /// `dst = *(size *)(src + off)` (Memory Load)
    pub const fn ldx_mem(size: u8, dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_CLASS_LDX | BPF_MODE_MEM | size, dst, src, off, 0)
    }

    /// `*(size *)(dst + off) = src` (Memory Store Register)
    pub const fn stx_mem(size: u8, dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_CLASS_STX | BPF_MODE_MEM | size, dst, src, off, 0)
    }

    /// `*(size *)(dst + off) = imm` (Memory Store Immediate)
    pub const fn st_mem(size: u8, dst: u8, off: i16, imm: i32) -> Self {
        Self::new(BPF_CLASS_ST | BPF_MODE_MEM | size, dst, 0, off, imm)
    }

    /// `if (dst == imm) goto pc + off`
    pub const fn jeq_imm(dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_CLASS_JMP | BPF_SRC_IMM | BPF_JMP_JEQ, dst, 0, off, imm)
    }

    /// `if (dst != imm) goto pc + off`
    pub const fn jne_imm(dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_CLASS_JMP | BPF_SRC_IMM | BPF_JMP_JNE, dst, 0, off, imm)
    }

    /// `if (dst > imm) goto pc + off`
    pub const fn jgt_imm(dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_CLASS_JMP | BPF_SRC_IMM | BPF_JMP_JGT, dst, 0, off, imm)
    }

    /// `if (dst >= imm) goto pc + off`
    pub const fn jge_imm(dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_CLASS_JMP | BPF_SRC_IMM | BPF_JMP_JGE, dst, 0, off, imm)
    }

    /// `if (dst > src) goto pc + off`
    pub const fn jgt_reg(dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_CLASS_JMP | BPF_SRC_REG | BPF_JMP_JGT, dst, src, off, 0)
    }

    /// `goto pc + off` (Unconditional jump)
    pub const fn ja(off: i16) -> Self {
        Self::new(BPF_CLASS_JMP | BPF_SRC_IMM | BPF_JMP_JA, 0, 0, off, 0)
    }

    /// `exit` (Return R0)
    pub const fn exit() -> Self {
        Self::new(BPF_CLASS_JMP | BPF_JMP_EXIT, 0, 0, 0, 0)
    }
}

// ---------------------------------------------------------------------------
// 2. Program Representation and Disassembler
// ---------------------------------------------------------------------------

/// Compiled eBPF Program containing bytecode instructions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfProgram {
    /// Name or identifier of the program.
    pub name: String,
    /// List of 64-bit eBPF instructions.
    pub instructions: Vec<EbpfInsn>,
}

impl EbpfProgram {
    /// Create a new program.
    pub fn new(name: impl Into<String>, instructions: Vec<EbpfInsn>) -> Self {
        Self {
            name: name.into(),
            instructions,
        }
    }

    /// Disassemble the bytecode into human-readable BPF assembly text.
    pub fn disassemble(&self) -> String {
        let mut out = format!(
            "; eBPF Program: {}\n; Instructions: {}\n",
            self.name,
            self.instructions.len()
        );
        for (pc, insn) in self.instructions.iter().enumerate() {
            out.push_str(&format!("{:04}: {}\n", pc, disassemble_insn(insn, pc)));
        }
        out
    }
}

/// Disassemble a single instruction with PC context.
pub fn disassemble_insn(insn: &EbpfInsn, pc: usize) -> String {
    let class = insn.opcode & 0x07;
    let mode_or_op = insn.opcode & 0xf0;
    let is_reg = (insn.opcode & 0x08) != 0;

    let dst = format!("r{}", insn.dst_reg);
    let src = format!("r{}", insn.src_reg);

    match class {
        BPF_CLASS_ALU64 => {
            let op_str = match mode_or_op {
                BPF_ALU_ADD => "+=",
                BPF_ALU_SUB => "-=",
                BPF_ALU_MUL => "*=",
                BPF_ALU_DIV => "/=",
                BPF_ALU_OR => "|=",
                BPF_ALU_AND => "&=",
                BPF_ALU_LSH => "<<=",
                BPF_ALU_RSH => ">>=",
                BPF_ALU_XOR => "^=",
                BPF_ALU_MOV => "=",
                _ => "?=",
            };
            if is_reg {
                format!("{} {} {}", dst, op_str, src)
            } else {
                format!("{} {} {}", dst, op_str, insn.imm)
            }
        }
        BPF_CLASS_LDX => {
            let size_str = match insn.opcode & 0x18 {
                BPF_SIZE_B => "u8",
                BPF_SIZE_H => "u16",
                BPF_SIZE_W => "u32",
                BPF_SIZE_DW => "u64",
                _ => "unknown",
            };
            if insn.off >= 0 {
                format!("{} = *({} *)({} + {})", dst, size_str, src, insn.off)
            } else {
                format!("{} = *({} *)({} - {})", dst, size_str, src, -insn.off)
            }
        }
        BPF_CLASS_STX => {
            let size_str = match insn.opcode & 0x18 {
                BPF_SIZE_B => "u8",
                BPF_SIZE_H => "u16",
                BPF_SIZE_W => "u32",
                BPF_SIZE_DW => "u64",
                _ => "unknown",
            };
            format!("*({} *)({} + {}) = {}", size_str, dst, insn.off, src)
        }
        BPF_CLASS_JMP => {
            if mode_or_op == BPF_JMP_EXIT {
                return "exit".to_string();
            }
            if mode_or_op == BPF_JMP_JA {
                let target = (pc as isize) + 1 + (insn.off as isize);
                return format!("goto +{} <{:04}>", insn.off, target);
            }
            let jmp_str = match mode_or_op {
                BPF_JMP_JEQ => "==",
                BPF_JMP_JGT => ">",
                BPF_JMP_JGE => ">=",
                BPF_JMP_JNE => "!=",
                BPF_JMP_JLT => "<",
                BPF_JMP_JLE => "<=",
                _ => "??",
            };
            let rhs = if is_reg { src } else { insn.imm.to_string() };
            let target = (pc as isize) + 1 + (insn.off as isize);
            format!(
                "if {} {} {} goto +{} <{:04}>",
                dst, jmp_str, rhs, insn.off, target
            )
        }
        _ => format!(
            "raw opcode 0x{:02x} dst={} src={} off={} imm={}",
            insn.opcode, insn.dst_reg, insn.src_reg, insn.off, insn.imm
        ),
    }
}

// ---------------------------------------------------------------------------
// 3. Static eBPF Verifier
// ---------------------------------------------------------------------------

/// Verifier report documenting safety analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierReport {
    pub passed: bool,
    pub total_instructions: usize,
    pub jump_targets_valid: bool,
    pub register_bounds_valid: bool,
    pub has_valid_exit: bool,
    pub error_message: Option<String>,
}

/// In-kernel static verifier simulator verifying eBPF bytecode safety.
pub struct EbpfVerifier;

impl EbpfVerifier {
    /// Verify an eBPF program for kernel safety invariants.
    pub fn verify(program: &EbpfProgram) -> Result<VerifierReport, VelcruxError> {
        let insns = &program.instructions;
        if insns.is_empty() {
            return Err(VelcruxError::Internal("eBPF program is empty".to_string()));
        }
        if insns.len() > 4096 {
            return Err(VelcruxError::Internal(format!(
                "eBPF program exceeds maximum 4096 instruction limit (got {})",
                insns.len()
            )));
        }

        let mut has_exit = false;

        for (pc, insn) in insns.iter().enumerate() {
            // Check register index bounds (0..=10)
            if insn.dst_reg > 10 || insn.src_reg > 10 {
                return Err(VelcruxError::Internal(format!(
                    "invalid register at insn {}: dst={} src={}",
                    pc, insn.dst_reg, insn.src_reg
                )));
            }

            // R10 is read-only frame pointer; it cannot be modified
            let class = insn.opcode & 0x07;
            if (class == BPF_CLASS_ALU64 || class == BPF_CLASS_ALU32 || class == BPF_CLASS_LDX)
                && insn.dst_reg == BPF_REG_10
            {
                return Err(VelcruxError::Internal(format!(
                    "cannot modify read-only frame pointer r10 at insn {}",
                    pc
                )));
            }

            // Check divide-by-zero on immediate ALU ops
            let mode_or_op = insn.opcode & 0xf0;
            if (class == BPF_CLASS_ALU64 || class == BPF_CLASS_ALU32)
                && (mode_or_op == BPF_ALU_DIV || mode_or_op == BPF_ALU_MOD)
                && (insn.opcode & BPF_SRC_REG) == 0
                && insn.imm == 0
            {
                return Err(VelcruxError::Internal(format!(
                    "division or modulo by zero at insn {}",
                    pc
                )));
            }

            // Check jump targets
            if class == BPF_CLASS_JMP {
                if mode_or_op == BPF_JMP_EXIT {
                    has_exit = true;
                    continue;
                }
                let target = (pc as isize) + 1 + (insn.off as isize);
                if target < 0 || target >= (insns.len() as isize) {
                    return Err(VelcruxError::Internal(format!(
                        "out-of-bounds jump at insn {}: target {} not in 0..{}",
                        pc,
                        target,
                        insns.len()
                    )));
                }
            }
        }

        if !has_exit {
            return Err(VelcruxError::Internal(
                "program missing terminal BPF_EXIT instruction".to_string(),
            ));
        }

        Ok(VerifierReport {
            passed: true,
            total_instructions: insns.len(),
            jump_targets_valid: true,
            register_bounds_valid: true,
            has_valid_exit: true,
            error_message: None,
        })
    }
}

// ---------------------------------------------------------------------------
// 4. Pure Safe-Rust eBPF Virtual Machine
// ---------------------------------------------------------------------------

/// Context passed to XDP BPF program representing incoming packet buffer.
#[derive(Debug, Clone)]
pub struct XdpMd<'a> {
    pub data: &'a [u8],
}

/// eBPF Execution Virtual Machine.
pub struct EbpfVm<'a> {
    regs: [u64; 11],
    stack: [u8; 512],
    ctx: &'a XdpMd<'a>,
}

impl<'a> EbpfVm<'a> {
    /// Construct a new VM instance with the packet context.
    pub fn new(ctx: &'a XdpMd<'a>) -> Self {
        let mut regs = [0u64; 11];
        // R1: context pointer
        regs[1] = 0x1000;
        // R10: stack frame pointer (top of stack)
        regs[10] = 512;

        Self {
            regs,
            stack: [0u8; 512],
            ctx,
        }
    }

    /// Execute the program and return the resulting XdpAction verdict.
    pub fn execute(&mut self, program: &EbpfProgram) -> Result<XdpAction, VelcruxError> {
        let insns = &program.instructions;
        let mut pc = 0;
        let mut steps = 0;
        let max_steps = 100_000;

        while pc < insns.len() {
            steps += 1;
            if steps > max_steps {
                return Err(VelcruxError::Internal(
                    "eBPF VM execution timeout (cycle limit exceeded)".to_string(),
                ));
            }

            let insn = insns[pc];
            let class = insn.opcode & 0x07;
            let mode_or_op = insn.opcode & 0xf0;
            let is_reg = (insn.opcode & 0x08) != 0;

            match class {
                BPF_CLASS_ALU64 => {
                    let rhs = if is_reg {
                        self.regs[insn.src_reg as usize]
                    } else {
                        insn.imm as u64
                    };
                    let dst = self.regs[insn.dst_reg as usize];
                    let res = match mode_or_op {
                        BPF_ALU_ADD => dst.wrapping_add(rhs),
                        BPF_ALU_SUB => dst.wrapping_sub(rhs),
                        BPF_ALU_MUL => dst.wrapping_mul(rhs),
                        BPF_ALU_DIV => {
                            if rhs == 0 {
                                0
                            } else {
                                dst / rhs
                            }
                        }
                        BPF_ALU_OR => dst | rhs,
                        BPF_ALU_AND => dst & rhs,
                        BPF_ALU_LSH => dst << (rhs & 63),
                        BPF_ALU_RSH => dst >> (rhs & 63),
                        BPF_ALU_XOR => dst ^ rhs,
                        BPF_ALU_MOV => rhs,
                        _ => dst,
                    };
                    self.regs[insn.dst_reg as usize] = res;
                    pc += 1;
                }
                BPF_CLASS_LDX => {
                    // Memory load: dst = *(src + off)
                    let src_val = self.regs[insn.src_reg as usize];
                    let addr = src_val.wrapping_add(insn.off as i64 as u64);

                    let loaded = if src_val == 0x1000 {
                        // Simulated packet context offset:
                        // 0 = data_start (0x2000), 4 = data_end (0x2000 + data.len())
                        if insn.off == 0 {
                            0x2000
                        } else if insn.off == 4 {
                            0x2000 + (self.ctx.data.len() as u64)
                        } else {
                            0
                        }
                    } else if addr >= 0x2000 && addr < 0x2000 + (self.ctx.data.len() as u64) {
                        let pkt_off = (addr - 0x2000) as usize;
                        match insn.opcode & 0x18 {
                            BPF_SIZE_B => self.ctx.data.get(pkt_off).copied().unwrap_or(0) as u64,
                            BPF_SIZE_H => {
                                if pkt_off + 2 <= self.ctx.data.len() {
                                    u16::from_be_bytes([
                                        self.ctx.data[pkt_off],
                                        self.ctx.data[pkt_off + 1],
                                    ]) as u64
                                } else {
                                    0
                                }
                            }
                            BPF_SIZE_W => {
                                if pkt_off + 4 <= self.ctx.data.len() {
                                    u32::from_be_bytes([
                                        self.ctx.data[pkt_off],
                                        self.ctx.data[pkt_off + 1],
                                        self.ctx.data[pkt_off + 2],
                                        self.ctx.data[pkt_off + 3],
                                    ]) as u64
                                } else {
                                    0
                                }
                            }
                            BPF_SIZE_DW => {
                                if pkt_off + 8 <= self.ctx.data.len() {
                                    let mut b = [0u8; 8];
                                    b.copy_from_slice(&self.ctx.data[pkt_off..pkt_off + 8]);
                                    u64::from_be_bytes(b)
                                } else {
                                    0
                                }
                            }
                            _ => 0,
                        }
                    } else if (addr as usize) < self.stack.len() {
                        self.stack[addr as usize] as u64
                    } else {
                        0
                    };

                    self.regs[insn.dst_reg as usize] = loaded;
                    pc += 1;
                }
                BPF_CLASS_STX => {
                    let dst_val = self.regs[insn.dst_reg as usize];
                    let addr = dst_val.wrapping_add(insn.off as i64 as u64);
                    let val = self.regs[insn.src_reg as usize] as u8;
                    if (addr as usize) < self.stack.len() {
                        self.stack[addr as usize] = val;
                    }
                    pc += 1;
                }
                BPF_CLASS_JMP => {
                    if mode_or_op == BPF_JMP_EXIT {
                        break;
                    }
                    if mode_or_op == BPF_JMP_JA {
                        pc = (pc as isize + 1 + insn.off as isize) as usize;
                        continue;
                    }

                    let lhs = self.regs[insn.dst_reg as usize];
                    let rhs = if is_reg {
                        self.regs[insn.src_reg as usize]
                    } else {
                        insn.imm as u64
                    };

                    let cond = match mode_or_op {
                        BPF_JMP_JEQ => lhs == rhs,
                        BPF_JMP_JGT => lhs > rhs,
                        BPF_JMP_JGE => lhs >= rhs,
                        BPF_JMP_JNE => lhs != rhs,
                        BPF_JMP_JLT => lhs < rhs,
                        BPF_JMP_JLE => lhs <= rhs,
                        _ => false,
                    };

                    if cond {
                        pc = (pc as isize + 1 + insn.off as isize) as usize;
                    } else {
                        pc += 1;
                    }
                }
                _ => {
                    pc += 1;
                }
            }
        }

        // Return verdict from R0:
        // 1 = Drop, 2 = Pass, 3 = Tx, 4 = Redirect
        let ret = self.regs[0];
        let action = match ret {
            1 => XdpAction::Drop,
            3 => XdpAction::Tx,
            4 => XdpAction::Redirect,
            _ => XdpAction::Pass,
        };
        Ok(action)
    }
}

// ---------------------------------------------------------------------------
// 5. High-Level BPF Assembler for QUIC UDP Filtering
// ---------------------------------------------------------------------------

/// Builder that generates canonical eBPF programs for QUIC UDP demuxing.
pub struct QuicFilterAssembler;

impl QuicFilterAssembler {
    /// Builds a canonical eBPF filter program matching QUIC packets on the target UDP port.
    pub fn build(target_port: u16) -> EbpfProgram {
        let mut insns = Vec::new();

        // 1. r2 = *(u32 *)(r1 + 0)   ; r2 = data_start
        insns.push(EbpfInsn::ldx_mem(BPF_SIZE_W, BPF_REG_2, BPF_REG_1, 0));
        // 2. r3 = *(u32 *)(r1 + 4)   ; r3 = data_end
        insns.push(EbpfInsn::ldx_mem(BPF_SIZE_W, BPF_REG_3, BPF_REG_1, 4));

        // 3. r4 = r2
        insns.push(EbpfInsn::mov64_reg(BPF_REG_4, BPF_REG_2));
        // 4. r4 += 42                 ; Ethernet (14) + IPv4 (20) + UDP (8) = 42
        insns.push(EbpfInsn::add64_imm(BPF_REG_4, 42));

        // 5. if r4 > r3 goto +12     ; bounds check -> PASS
        insns.push(EbpfInsn::jgt_reg(BPF_REG_4, BPF_REG_3, 12));

        // 6. r5 = *(u16 *)(r2 + 12)  ; EtherType
        insns.push(EbpfInsn::ldx_mem(BPF_SIZE_H, BPF_REG_5, BPF_REG_2, 12));
        // 7. if r5 != 0x0800 goto +10; not IPv4 -> PASS
        insns.push(EbpfInsn::jne_imm(BPF_REG_5, 0x0800, 10));

        // 8. r5 = *(u8 *)(r2 + 23)   ; IP protocol (14 + 9)
        insns.push(EbpfInsn::ldx_mem(BPF_SIZE_B, BPF_REG_5, BPF_REG_2, 23));
        // 9. if r5 != 17 goto +8     ; not UDP -> PASS
        insns.push(EbpfInsn::jne_imm(BPF_REG_5, 17, 8));

        // 10. r5 = *(u16 *)(r2 + 36) ; UDP Dst Port (14 + 20 + 2)
        insns.push(EbpfInsn::ldx_mem(BPF_SIZE_H, BPF_REG_5, BPF_REG_2, 36));
        // 11. if r5 != target_port goto +6; port mismatch -> PASS
        insns.push(EbpfInsn::jne_imm(BPF_REG_5, target_port as i32, 6));

        // 12. MATCH! Check for invalid port 0 probe
        // if r5 == 0 goto +3         ; drop
        insns.push(EbpfInsn::jeq_imm(BPF_REG_5, 0, 3));

        // 13. Redirect to AF_XDP (XDP_REDIRECT = 4)
        insns.push(EbpfInsn::mov64_imm(BPF_REG_0, 4));
        insns.push(EbpfInsn::exit());

        // 14. Drop target (XDP_DROP = 1)
        insns.push(EbpfInsn::mov64_imm(BPF_REG_0, 1));
        insns.push(EbpfInsn::exit());

        // 15. Pass target (XDP_PASS = 2)
        insns.push(EbpfInsn::mov64_imm(BPF_REG_0, 2));
        insns.push(EbpfInsn::exit());

        EbpfProgram::new(format!("quic_filter_udp_{}", target_port), insns)
    }
}
