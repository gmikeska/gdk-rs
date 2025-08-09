//! Bitcoin script parsing and execution engine.

use super::encode::{Encodable, Decodable, write_varint, read_varint};
use super::hash::{hash160, sha256, sha256d, Hash160, Hash256};
use crate::{Result, GdkError};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};


/// Bitcoin script opcodes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    // Push value
    OP_0 = 0x00,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_RESERVED = 0x50,
    OP_1 = 0x51,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,

    // Control
    OP_NOP = 0x61,
    OP_VER = 0x62,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,

    // Stack ops
    OP_TOALTSTACK = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_2DROP = 0x6d,
    OP_2DUP = 0x6e,
    OP_3DUP = 0x6f,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_ROT = 0x7b,
    OP_SWAP = 0x7c,
    OP_TUCK = 0x7d,

    // String splice ops
    OP_CAT = 0x7e,
    OP_SUBSTR = 0x7f,
    OP_LEFT = 0x80,
    OP_RIGHT = 0x81,
    OP_SIZE = 0x82,

    // Bit logic
    OP_INVERT = 0x83,
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,

    // Numeric
    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    OP_2MUL = 0x8d,
    OP_2DIV = 0x8e,
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,

    OP_ADD = 0x93,
    OP_SUB = 0x94,
    OP_MUL = 0x95,
    OP_DIV = 0x96,
    OP_MOD = 0x97,
    OP_LSHIFT = 0x98,
    OP_RSHIFT = 0x99,

    OP_BOOLAND = 0x9a,
    OP_BOOLOR = 0x9b,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_GREATERTHAN = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,

    OP_WITHIN = 0xa5,

    // Crypto
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CODESEPARATOR = 0xab,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    // Expansion
    OP_NOP1 = 0xb0,
    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    OP_CHECKSEQUENCEVERIFY = 0xb2,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,

    // More crypto
    OP_CHECKSIGADD = 0xba,

    OP_INVALIDOPCODE = 0xff,
}

impl From<u8> for Opcode {
    fn from(b: u8) -> Self {
        match b {
            0x00 => Opcode::OP_0,
            0x4c => Opcode::OP_PUSHDATA1,
            0x4d => Opcode::OP_PUSHDATA2,
            0x4e => Opcode::OP_PUSHDATA4,
            0x4f => Opcode::OP_1NEGATE,
            0x50 => Opcode::OP_RESERVED,
            0x51 => Opcode::OP_1,
            0x52 => Opcode::OP_2,
            0x53 => Opcode::OP_3,
            0x54 => Opcode::OP_4,
            0x55 => Opcode::OP_5,
            0x56 => Opcode::OP_6,
            0x57 => Opcode::OP_7,
            0x58 => Opcode::OP_8,
            0x59 => Opcode::OP_9,
            0x5a => Opcode::OP_10,
            0x5b => Opcode::OP_11,
            0x5c => Opcode::OP_12,
            0x5d => Opcode::OP_13,
            0x5e => Opcode::OP_14,
            0x5f => Opcode::OP_15,
            0x60 => Opcode::OP_16,
            0x61 => Opcode::OP_NOP,
            0x62 => Opcode::OP_VER,
            0x63 => Opcode::OP_IF,
            0x64 => Opcode::OP_NOTIF,
            0x65 => Opcode::OP_VERIF,
            0x66 => Opcode::OP_VERNOTIF,
            0x67 => Opcode::OP_ELSE,
            0x68 => Opcode::OP_ENDIF,
            0x69 => Opcode::OP_VERIFY,
            0x6a => Opcode::OP_RETURN,
            0x6b => Opcode::OP_TOALTSTACK,
            0x6c => Opcode::OP_FROMALTSTACK,
            0x6d => Opcode::OP_2DROP,
            0x6e => Opcode::OP_2DUP,
            0x6f => Opcode::OP_3DUP,
            0x70 => Opcode::OP_2OVER,
            0x71 => Opcode::OP_2ROT,
            0x72 => Opcode::OP_2SWAP,
            0x73 => Opcode::OP_IFDUP,
            0x74 => Opcode::OP_DEPTH,
            0x75 => Opcode::OP_DROP,
            0x76 => Opcode::OP_DUP,
            0x77 => Opcode::OP_NIP,
            0x78 => Opcode::OP_OVER,
            0x79 => Opcode::OP_PICK,
            0x7a => Opcode::OP_ROLL,
            0x7b => Opcode::OP_ROT,
            0x7c => Opcode::OP_SWAP,
            0x7d => Opcode::OP_TUCK,
            0x7e => Opcode::OP_CAT,
            0x7f => Opcode::OP_SUBSTR,
            0x80 => Opcode::OP_LEFT,
            0x81 => Opcode::OP_RIGHT,
            0x82 => Opcode::OP_SIZE,
            0x83 => Opcode::OP_INVERT,
            0x84 => Opcode::OP_AND,
            0x85 => Opcode::OP_OR,
            0x86 => Opcode::OP_XOR,
            0x87 => Opcode::OP_EQUAL,
            0x88 => Opcode::OP_EQUALVERIFY,
            0x89 => Opcode::OP_RESERVED1,
            0x8a => Opcode::OP_RESERVED2,
            0x8b => Opcode::OP_1ADD,
            0x8c => Opcode::OP_1SUB,
            0x8d => Opcode::OP_2MUL,
            0x8e => Opcode::OP_2DIV,
            0x8f => Opcode::OP_NEGATE,
            0x90 => Opcode::OP_ABS,
            0x91 => Opcode::OP_NOT,
            0x92 => Opcode::OP_0NOTEQUAL,
            0x93 => Opcode::OP_ADD,
            0x94 => Opcode::OP_SUB,
            0x95 => Opcode::OP_MUL,
            0x96 => Opcode::OP_DIV,
            0x97 => Opcode::OP_MOD,
            0x98 => Opcode::OP_LSHIFT,
            0x99 => Opcode::OP_RSHIFT,
            0x9a => Opcode::OP_BOOLAND,
            0x9b => Opcode::OP_BOOLOR,
            0x9c => Opcode::OP_NUMEQUAL,
            0x9d => Opcode::OP_NUMEQUALVERIFY,
            0x9e => Opcode::OP_NUMNOTEQUAL,
            0x9f => Opcode::OP_LESSTHAN,
            0xa0 => Opcode::OP_GREATERTHAN,
            0xa1 => Opcode::OP_LESSTHANOREQUAL,
            0xa2 => Opcode::OP_GREATERTHANOREQUAL,
            0xa3 => Opcode::OP_MIN,
            0xa4 => Opcode::OP_MAX,
            0xa5 => Opcode::OP_WITHIN,
            0xa6 => Opcode::OP_RIPEMD160,
            0xa7 => Opcode::OP_SHA1,
            0xa8 => Opcode::OP_SHA256,
            0xa9 => Opcode::OP_HASH160,
            0xaa => Opcode::OP_HASH256,
            0xab => Opcode::OP_CODESEPARATOR,
            0xac => Opcode::OP_CHECKSIG,
            0xad => Opcode::OP_CHECKSIGVERIFY,
            0xae => Opcode::OP_CHECKMULTISIG,
            0xaf => Opcode::OP_CHECKMULTISIGVERIFY,
            0xb0 => Opcode::OP_NOP1,
            0xb1 => Opcode::OP_CHECKLOCKTIMEVERIFY,
            0xb2 => Opcode::OP_CHECKSEQUENCEVERIFY,
            0xb3 => Opcode::OP_NOP4,
            0xb4 => Opcode::OP_NOP5,
            0xb5 => Opcode::OP_NOP6,
            0xb6 => Opcode::OP_NOP7,
            0xb7 => Opcode::OP_NOP8,
            0xb8 => Opcode::OP_NOP9,
            0xb9 => Opcode::OP_NOP10,
            0xba => Opcode::OP_CHECKSIGADD,
            _ => Opcode::OP_INVALIDOPCODE,
        }
    }
}

/// Script instruction
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction {
    /// Push data onto the stack
    PushBytes(Vec<u8>),
    /// Execute an opcode
    Op(Opcode),
}

/// Bitcoin script
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Script(pub Vec<u8>);

impl Script {
    /// Create a new empty script
    pub fn new() -> Self {
        Script(Vec::new())
    }
    
    /// Create a script from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Script(bytes)
    }
    
    /// Get the script bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    
    /// Get the script length
    pub fn len(&self) -> usize {
        self.0.len()
    }
    
    /// Check if the script is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    
    /// Parse the script into instructions
    pub fn instructions(&self) -> Result<Vec<Instruction>> {
        let mut instructions = Vec::new();
        let mut i = 0;
        
        while i < self.0.len() {
            let opcode = self.0[i];
            i += 1;
            
            if opcode <= 75 {
                // Direct push of 1-75 bytes
                if i + opcode as usize > self.0.len() {
                    return Err(GdkError::InvalidInput("Script truncated".to_string()));
                }
                let data = self.0[i..i + opcode as usize].to_vec();
                instructions.push(Instruction::PushBytes(data));
                i += opcode as usize;
            } else if opcode == 0x4c {
                // OP_PUSHDATA1
                if i >= self.0.len() {
                    return Err(GdkError::InvalidInput("Script truncated".to_string()));
                }
                let len = self.0[i] as usize;
                i += 1;
                if i + len > self.0.len() {
                    return Err(GdkError::InvalidInput("Script truncated".to_string()));
                }
                let data = self.0[i..i + len].to_vec();
                instructions.push(Instruction::PushBytes(data));
                i += len;
            } else if opcode == 0x4d {
                // OP_PUSHDATA2
                if i + 1 >= self.0.len() {
                    return Err(GdkError::InvalidInput("Script truncated".to_string()));
                }
                let len = u16::from_le_bytes([self.0[i], self.0[i + 1]]) as usize;
                i += 2;
                if i + len > self.0.len() {
                    return Err(GdkError::InvalidInput("Script truncated".to_string()));
                }
                let data = self.0[i..i + len].to_vec();
                instructions.push(Instruction::PushBytes(data));
                i += len;
            } else if opcode == 0x4e {
                // OP_PUSHDATA4
                if i + 3 >= self.0.len() {
                    return Err(GdkError::InvalidInput("Script truncated".to_string()));
                }
                let len = u32::from_le_bytes([self.0[i], self.0[i + 1], self.0[i + 2], self.0[i + 3]]) as usize;
                i += 4;
                if i + len > self.0.len() {
                    return Err(GdkError::InvalidInput("Script truncated".to_string()));
                }
                let data = self.0[i..i + len].to_vec();
                instructions.push(Instruction::PushBytes(data));
                i += len;
            } else {
                // Regular opcode
                instructions.push(Instruction::Op(Opcode::from(opcode)));
            }
        }
        
        Ok(instructions)
    }
    
    /// Check if this is a P2PKH script pattern
    pub fn is_p2pkh(&self) -> bool {
        self.0.len() == 25 &&
        self.0[0] == 0x76 && // OP_DUP
        self.0[1] == 0xa9 && // OP_HASH160
        self.0[2] == 0x14 && // Push 20 bytes
        self.0[23] == 0x88 && // OP_EQUALVERIFY
        self.0[24] == 0xac    // OP_CHECKSIG
    }
    
    /// Check if this is a P2SH script pattern
    pub fn is_p2sh(&self) -> bool {
        self.0.len() == 23 &&
        self.0[0] == 0xa9 && // OP_HASH160
        self.0[1] == 0x14 && // Push 20 bytes
        self.0[22] == 0x87   // OP_EQUAL
    }
    
    /// Check if this is a P2WPKH script pattern
    pub fn is_p2wpkh(&self) -> bool {
        self.0.len() == 22 &&
        self.0[0] == 0x00 && // OP_0
        self.0[1] == 0x14    // Push 20 bytes
    }
    
    /// Check if this is a P2WSH script pattern
    pub fn is_p2wsh(&self) -> bool {
        self.0.len() == 34 &&
        self.0[0] == 0x00 && // OP_0
        self.0[1] == 0x20    // Push 32 bytes
    }
    
    /// Check if this is an OP_RETURN script
    pub fn is_op_return(&self) -> bool {
        !self.0.is_empty() && self.0[0] == 0x6a
    }
    
    /// Extract the hash160 from a P2PKH or P2SH script
    pub fn extract_hash160(&self) -> Option<Hash160> {
        if self.is_p2pkh() {
            let mut hash = [0u8; 20];
            hash.copy_from_slice(&self.0[3..23]);
            Some(hash)
        } else if self.is_p2sh() {
            let mut hash = [0u8; 20];
            hash.copy_from_slice(&self.0[2..22]);
            Some(hash)
        } else if self.is_p2wpkh() {
            let mut hash = [0u8; 20];
            hash.copy_from_slice(&self.0[2..22]);
            Some(hash)
        } else {
            None
        }
    }
    
    /// Extract the hash256 from a P2WSH script
    pub fn extract_hash256(&self) -> Option<Hash256> {
        if self.is_p2wsh() {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&self.0[2..34]);
            Some(hash)
        } else {
            None
        }
    }
    
    /// Validate script size and complexity
    pub fn validate(&self) -> Result<()> {
        // Check maximum script size (10,000 bytes)
        if self.0.len() > 10000 {
            return Err(GdkError::InvalidInput("Script too large".to_string()));
        }
        
        // Parse instructions to validate structure
        let instructions = self.instructions()?;
        
        // Check for excessive push operations
        let mut push_count = 0;
        for instruction in &instructions {
            match instruction {
                Instruction::PushBytes(data) => {
                    push_count += 1;
                    // Check maximum push size (520 bytes)
                    if data.len() > 520 {
                        return Err(GdkError::InvalidInput("Push data too large".to_string()));
                    }
                }
                Instruction::Op(_) => {}
            }
        }
        
        // Check maximum number of operations (201)
        if instructions.len() > 201 {
            return Err(GdkError::InvalidInput("Too many operations in script".to_string()));
        }
        
        Ok(())
    }
    
    /// Create a P2PKH script for the given hash160
    pub fn new_p2pkh(hash160: &Hash160) -> Self {
        let mut script = Vec::with_capacity(25);
        script.push(0x76); // OP_DUP
        script.push(0xa9); // OP_HASH160
        script.push(0x14); // Push 20 bytes
        script.extend_from_slice(hash160);
        script.push(0x88); // OP_EQUALVERIFY
        script.push(0xac); // OP_CHECKSIG
        Script(script)
    }
    
    /// Create a P2SH script for the given hash160
    pub fn new_p2sh(hash160: &Hash160) -> Self {
        let mut script = Vec::with_capacity(23);
        script.push(0xa9); // OP_HASH160
        script.push(0x14); // Push 20 bytes
        script.extend_from_slice(hash160);
        script.push(0x87); // OP_EQUAL
        Script(script)
    }
    
    /// Create a P2WPKH script for the given hash160
    pub fn new_p2wpkh(hash160: &Hash160) -> Self {
        let mut script = Vec::with_capacity(22);
        script.push(0x00); // OP_0
        script.push(0x14); // Push 20 bytes
        script.extend_from_slice(hash160);
        Script(script)
    }
    
    /// Create a P2WSH script for the given hash256
    pub fn new_p2wsh(hash256: &Hash256) -> Self {
        let mut script = Vec::with_capacity(34);
        script.push(0x00); // OP_0
        script.push(0x20); // Push 32 bytes
        script.extend_from_slice(hash256);
        Script(script)
    }

    /// Execute the script with the given stack and transaction context
    pub fn execute(&self, stack: &mut Vec<Vec<u8>>, tx_context: Option<&ScriptExecutionContext>) -> Result<bool> {
        let mut executor = ScriptExecutor::new(stack, tx_context);
        executor.execute(self)
    }

    /// Verify a script signature (simplified version for basic validation)
    pub fn verify_signature(&self, signature: &[u8], public_key: &[u8], message_hash: &[u8]) -> Result<bool> {
        // This is a simplified signature verification
        // In a full implementation, this would use secp256k1 signature verification
        if signature.is_empty() || public_key.is_empty() || message_hash.is_empty() {
            return Ok(false);
        }
        
        // For now, we'll do basic length checks
        // Real implementation would verify ECDSA signature
        Ok(signature.len() >= 64 && public_key.len() == 33 && message_hash.len() == 32)
    }
}

impl Encodable for Script {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        let mut written = write_varint(writer, self.0.len() as u64)?;
        written += writer.write(&self.0)?;
        Ok(written)
    }
}

impl Decodable for Script {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self> {
        let len = read_varint(reader)?;
        let mut buf = vec![0u8; len as usize];
        reader.read_exact(&mut buf)?;
        Ok(Script(buf))
    }
}

/// Context for script execution with transaction information
#[derive(Debug, Clone)]
pub struct ScriptExecutionContext {
    pub transaction_hash: Hash256,
    pub input_index: u32,
    pub amount: u64,
    pub lock_time: u32,
    pub sequence: u32,
}

/// Script execution engine
pub struct ScriptExecutor<'a> {
    stack: &'a mut Vec<Vec<u8>>,
    alt_stack: Vec<Vec<u8>>,
    tx_context: Option<&'a ScriptExecutionContext>,
    op_count: usize,
}

impl<'a> ScriptExecutor<'a> {
    /// Create a new script executor
    pub fn new(stack: &'a mut Vec<Vec<u8>>, tx_context: Option<&'a ScriptExecutionContext>) -> Self {
        Self {
            stack,
            alt_stack: Vec::new(),
            tx_context,
            op_count: 0,
        }
    }

    /// Execute a script
    pub fn execute(&mut self, script: &Script) -> Result<bool> {
        let instructions = script.instructions()?;
        
        for instruction in instructions {
            self.op_count += 1;
            if self.op_count > 201 {
                return Err(GdkError::InvalidInput("Too many operations".to_string()));
            }

            match instruction {
                Instruction::PushBytes(data) => {
                    if data.len() > 520 {
                        return Err(GdkError::InvalidInput("Push data too large".to_string()));
                    }
                    self.stack.push(data);
                }
                Instruction::Op(opcode) => {
                    self.execute_opcode(opcode)?;
                }
            }
        }

        // Script succeeds if stack is not empty and top element is true
        Ok(!self.stack.is_empty() && self.is_true(&self.stack[self.stack.len() - 1]))
    }

    /// Execute a single opcode
    fn execute_opcode(&mut self, opcode: Opcode) -> Result<()> {
        match opcode {
            // Constants
            Opcode::OP_0 => self.stack.push(vec![]),
            Opcode::OP_1NEGATE => self.stack.push(vec![0x81]), // -1 in script number format
            Opcode::OP_1 => self.stack.push(vec![0x01]),
            Opcode::OP_2 => self.stack.push(vec![0x02]),
            Opcode::OP_3 => self.stack.push(vec![0x03]),
            Opcode::OP_4 => self.stack.push(vec![0x04]),
            Opcode::OP_5 => self.stack.push(vec![0x05]),
            Opcode::OP_6 => self.stack.push(vec![0x06]),
            Opcode::OP_7 => self.stack.push(vec![0x07]),
            Opcode::OP_8 => self.stack.push(vec![0x08]),
            Opcode::OP_9 => self.stack.push(vec![0x09]),
            Opcode::OP_10 => self.stack.push(vec![0x0a]),
            Opcode::OP_11 => self.stack.push(vec![0x0b]),
            Opcode::OP_12 => self.stack.push(vec![0x0c]),
            Opcode::OP_13 => self.stack.push(vec![0x0d]),
            Opcode::OP_14 => self.stack.push(vec![0x0e]),
            Opcode::OP_15 => self.stack.push(vec![0x0f]),
            Opcode::OP_16 => self.stack.push(vec![0x10]),

            // Flow control
            Opcode::OP_NOP | Opcode::OP_NOP1 | Opcode::OP_NOP4 | Opcode::OP_NOP5 |
            Opcode::OP_NOP6 | Opcode::OP_NOP7 | Opcode::OP_NOP8 | Opcode::OP_NOP9 | Opcode::OP_NOP10 => {
                // No operation
            }
            Opcode::OP_VERIFY => {
                if self.stack.is_empty() {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                let value = self.stack.pop().unwrap();
                if !self.is_true(&value) {
                    return Err(GdkError::InvalidInput("OP_VERIFY failed".to_string()));
                }
            }
            Opcode::OP_RETURN => {
                return Err(GdkError::InvalidInput("OP_RETURN executed".to_string()));
            }

            // Stack operations
            Opcode::OP_TOALTSTACK => {
                if self.stack.is_empty() {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                let value = self.stack.pop().unwrap();
                self.alt_stack.push(value);
            }
            Opcode::OP_FROMALTSTACK => {
                if self.alt_stack.is_empty() {
                    return Err(GdkError::InvalidInput("Alt stack underflow".to_string()));
                }
                let value = self.alt_stack.pop().unwrap();
                self.stack.push(value);
            }
            Opcode::OP_2DROP => {
                if self.stack.len() < 2 {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                self.stack.pop();
                self.stack.pop();
            }
            Opcode::OP_2DUP => {
                if self.stack.len() < 2 {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                let a = self.stack[self.stack.len() - 2].clone();
                let b = self.stack[self.stack.len() - 1].clone();
                self.stack.push(a);
                self.stack.push(b);
            }
            Opcode::OP_3DUP => {
                if self.stack.len() < 3 {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                let a = self.stack[self.stack.len() - 3].clone();
                let b = self.stack[self.stack.len() - 2].clone();
                let c = self.stack[self.stack.len() - 1].clone();
                self.stack.push(a);
                self.stack.push(b);
                self.stack.push(c);
            }
            Opcode::OP_2OVER => {
                if self.stack.len() < 4 {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                let a = self.stack[self.stack.len() - 4].clone();
                let b = self.stack[self.stack.len() - 3].clone();
                self.stack.push(a);
                self.stack.push(b);
            }
            Opcode::OP_2ROT => {
                if self.stack.len() < 6 {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                let len = self.stack.len();
                let a = self.stack.remove(len - 6);
                let b = self.stack.remove(len - 6);
                self.stack.push(a);
                self.stack.push(b);
            }
            Opcode::OP_2SWAP => {
                if self.stack.len() < 4 {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                let len = self.stack.len();
                self.stack.swap(len - 4, len - 2);
                self.stack.swap(len - 3, len - 1);
            }
            Opcode::OP_IFDUP => {
                if self.stack.is_empty() {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                let value = self.stack[self.stack.len() - 1].clone();
                if self.is_true(&value) {
                    self.stack.push(value);
                }
            }
            Opcode::OP_DEPTH => {
                let depth = self.stack.len() as u8;
                self.stack.push(vec![depth]);
            }
            Opcode::OP_DROP => {
                if self.stack.is_empty() {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                self.stack.pop();
            }
            Opcode::OP_DUP => {
                if self.stack.is_empty() {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                let value = self.stack[self.stack.len() - 1].clone();
                self.stack.push(value);
            }
            Opcode::OP_NIP => {
                if self.stack.len() < 2 {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                let len = self.stack.len();
                self.stack.remove(len - 2);
            }
            Opcode::OP_OVER => {
                if self.stack.len() < 2 {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                let value = self.stack[self.stack.len() - 2].clone();
                self.stack.push(value);
            }
            Opcode::OP_ROT => {
                if self.stack.len() < 3 {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                let len = self.stack.len();
                let value = self.stack.remove(len - 3);
                self.stack.push(value);
            }
            Opcode::OP_SWAP => {
                if self.stack.len() < 2 {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                let len = self.stack.len();
                self.stack.swap(len - 2, len - 1);
            }
            Opcode::OP_TUCK => {
                if self.stack.len() < 2 {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                let value = self.stack[self.stack.len() - 1].clone();
                let len = self.stack.len();
                self.stack.insert(len - 2, value);
            }

            // Bitwise logic
            Opcode::OP_EQUAL => {
                if self.stack.len() < 2 {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                let b = self.stack.pop().unwrap();
                let a = self.stack.pop().unwrap();
                let result = if a == b { vec![1] } else { vec![] };
                self.stack.push(result);
            }
            Opcode::OP_EQUALVERIFY => {
                if self.stack.len() < 2 {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                let b = self.stack.pop().unwrap();
                let a = self.stack.pop().unwrap();
                if a != b {
                    return Err(GdkError::InvalidInput("OP_EQUALVERIFY failed".to_string()));
                }
            }

            // Crypto operations
            Opcode::OP_SHA256 => {
                if self.stack.is_empty() {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                let data = self.stack.pop().unwrap();
                let hash = sha256(&data);
                self.stack.push(hash.to_vec());
            }
            Opcode::OP_HASH160 => {
                if self.stack.is_empty() {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                let data = self.stack.pop().unwrap();
                let hash = hash160(&data);
                self.stack.push(hash.to_vec());
            }
            Opcode::OP_HASH256 => {
                if self.stack.is_empty() {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                let data = self.stack.pop().unwrap();
                let hash = sha256d(&data);
                self.stack.push(hash.to_vec());
            }
            Opcode::OP_CHECKSIG => {
                if self.stack.len() < 2 {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                let pubkey = self.stack.pop().unwrap();
                let signature = self.stack.pop().unwrap();
                
                // Simplified signature verification
                let result = if let Some(ctx) = self.tx_context {
                    self.verify_signature(&signature, &pubkey, &ctx.transaction_hash)?
                } else {
                    // Without transaction context, we can only do basic validation
                    !signature.is_empty() && !pubkey.is_empty()
                };
                
                self.stack.push(if result { vec![1] } else { vec![] });
            }
            Opcode::OP_CHECKSIGVERIFY => {
                if self.stack.len() < 2 {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                let pubkey = self.stack.pop().unwrap();
                let signature = self.stack.pop().unwrap();
                
                let result = if let Some(ctx) = self.tx_context {
                    self.verify_signature(&signature, &pubkey, &ctx.transaction_hash)?
                } else {
                    !signature.is_empty() && !pubkey.is_empty()
                };
                
                if !result {
                    return Err(GdkError::InvalidInput("OP_CHECKSIGVERIFY failed".to_string()));
                }
            }
            Opcode::OP_CHECKMULTISIG => {
                if self.stack.is_empty() {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                
                let n_bytes = self.stack.pop().unwrap();
                let n = self.script_num_to_int(&n_bytes)?;
                if n < 0 || n > 20 {
                    return Err(GdkError::InvalidInput("Invalid pubkey count".to_string()));
                }
                
                if self.stack.len() < n as usize {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                
                let mut pubkeys = Vec::new();
                for _ in 0..n {
                    pubkeys.push(self.stack.pop().unwrap());
                }
                
                if self.stack.is_empty() {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                
                let m_bytes = self.stack.pop().unwrap();
                let m = self.script_num_to_int(&m_bytes)?;
                if m < 0 || m > n {
                    return Err(GdkError::InvalidInput("Invalid signature count".to_string()));
                }
                
                if self.stack.len() < m as usize {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                
                let mut signatures = Vec::new();
                for _ in 0..m {
                    signatures.push(self.stack.pop().unwrap());
                }
                
                // Remove extra value due to off-by-one bug in original implementation
                if self.stack.is_empty() {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                self.stack.pop();
                
                // Simplified multisig verification
                let result = signatures.len() == m as usize && pubkeys.len() == n as usize;
                self.stack.push(if result { vec![1] } else { vec![] });
            }

            // Timelock operations
            Opcode::OP_CHECKLOCKTIMEVERIFY => {
                if self.stack.is_empty() {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                
                let locktime = self.script_num_to_int(&self.stack[self.stack.len() - 1])?;
                
                if let Some(ctx) = self.tx_context {
                    if locktime < 0 {
                        return Err(GdkError::InvalidInput("Negative locktime".to_string()));
                    }
                    
                    // Simplified locktime check
                    if ctx.lock_time < locktime as u32 {
                        return Err(GdkError::InvalidInput("Locktime not satisfied".to_string()));
                    }
                }
            }
            Opcode::OP_CHECKSEQUENCEVERIFY => {
                if self.stack.is_empty() {
                    return Err(GdkError::InvalidInput("Stack underflow".to_string()));
                }
                
                let sequence = self.script_num_to_int(&self.stack[self.stack.len() - 1])?;
                
                if let Some(ctx) = self.tx_context {
                    if sequence < 0 {
                        return Err(GdkError::InvalidInput("Negative sequence".to_string()));
                    }
                    
                    // Simplified sequence check
                    if ctx.sequence < sequence as u32 {
                        return Err(GdkError::InvalidInput("Sequence not satisfied".to_string()));
                    }
                }
            }

            // Disabled or invalid opcodes
            Opcode::OP_RESERVED | Opcode::OP_VER | Opcode::OP_VERIF | Opcode::OP_VERNOTIF |
            Opcode::OP_RESERVED1 | Opcode::OP_RESERVED2 | Opcode::OP_INVALIDOPCODE => {
                return Err(GdkError::InvalidInput("Invalid opcode".to_string()));
            }

            // Unimplemented opcodes (would need full implementation)
            _ => {
                return Err(GdkError::InvalidInput(format!("Unimplemented opcode: {:?}", opcode)));
            }
        }

        Ok(())
    }

    /// Check if a value is considered "true" in script context
    fn is_true(&self, value: &[u8]) -> bool {
        if value.is_empty() {
            return false;
        }
        
        // Check for negative zero
        if value.len() == 1 && value[0] == 0x80 {
            return false;
        }
        
        // Check if all bytes are zero
        for &byte in value {
            if byte != 0 {
                return true;
            }
        }
        
        false
    }

    /// Convert script number to integer
    fn script_num_to_int(&self, data: &[u8]) -> Result<i64> {
        if data.is_empty() {
            return Ok(0);
        }
        
        if data.len() > 4 {
            return Err(GdkError::InvalidInput("Script number too long".to_string()));
        }
        
        let mut result = 0i64;
        for (i, &byte) in data.iter().enumerate() {
            if i == data.len() - 1 {
                // Last byte contains sign bit
                result |= ((byte & 0x7f) as i64) << (8 * i);
                if byte & 0x80 != 0 {
                    result = -result;
                }
            } else {
                result |= (byte as i64) << (8 * i);
            }
        }
        
        Ok(result)
    }

    /// Verify a signature (simplified implementation)
    fn verify_signature(&self, signature: &[u8], public_key: &[u8], message_hash: &[u8]) -> Result<bool> {
        // This is a placeholder for actual ECDSA signature verification
        // In a real implementation, this would use secp256k1 library
        if signature.is_empty() || public_key.is_empty() || message_hash.is_empty() {
            return Ok(false);
        }
        
        // Basic length validation
        if signature.len() < 64 || public_key.len() != 33 || message_hash.len() != 32 {
            return Ok(false);
        }
        
        // For now, just return true for valid-looking inputs
        // Real implementation would perform actual cryptographic verification
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_parsing() {
        // P2PKH script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let p2pkh_script = Script::new_p2pkh(&[0x12; 20]);
        let instructions = p2pkh_script.instructions().unwrap();
        
        assert_eq!(instructions.len(), 5);
        assert_eq!(instructions[0], Instruction::Op(Opcode::OP_DUP));
        assert_eq!(instructions[1], Instruction::Op(Opcode::OP_HASH160));
        assert_eq!(instructions[2], Instruction::PushBytes(vec![0x12; 20]));
        assert_eq!(instructions[3], Instruction::Op(Opcode::OP_EQUALVERIFY));
        assert_eq!(instructions[4], Instruction::Op(Opcode::OP_CHECKSIG));
    }

    #[test]
    fn test_script_patterns() {
        let hash160 = [0x12; 20];
        let hash256 = [0x34; 32];
        
        let p2pkh = Script::new_p2pkh(&hash160);
        assert!(p2pkh.is_p2pkh());
        assert!(!p2pkh.is_p2sh());
        assert!(!p2pkh.is_p2wpkh());
        assert!(!p2pkh.is_p2wsh());
        assert_eq!(p2pkh.extract_hash160(), Some(hash160));
        
        let p2sh = Script::new_p2sh(&hash160);
        assert!(!p2sh.is_p2pkh());
        assert!(p2sh.is_p2sh());
        assert!(!p2sh.is_p2wpkh());
        assert!(!p2sh.is_p2wsh());
        assert_eq!(p2sh.extract_hash160(), Some(hash160));
        
        let p2wpkh = Script::new_p2wpkh(&hash160);
        assert!(!p2wpkh.is_p2pkh());
        assert!(!p2wpkh.is_p2sh());
        assert!(p2wpkh.is_p2wpkh());
        assert!(!p2wpkh.is_p2wsh());
        assert_eq!(p2wpkh.extract_hash160(), Some(hash160));
        
        let p2wsh = Script::new_p2wsh(&hash256);
        assert!(!p2wsh.is_p2pkh());
        assert!(!p2wsh.is_p2sh());
        assert!(!p2wsh.is_p2wpkh());
        assert!(p2wsh.is_p2wsh());
        assert_eq!(p2wsh.extract_hash256(), Some(hash256));
    }

    #[test]
    fn test_script_validation() {
        let valid_script = Script::new_p2pkh(&[0x12; 20]);
        assert!(valid_script.validate().is_ok());
        
        // Test script too large
        let large_script = Script(vec![0; 10001]);
        assert!(large_script.validate().is_err());
        
        // Test truncated script
        let truncated_script = Script(vec![0x4c, 0x10]); // PUSHDATA1 16 bytes, but no data
        assert!(truncated_script.validate().is_err());
    }

    #[test]
    fn test_pushdata_parsing() {
        // Test PUSHDATA1
        let mut script_bytes = vec![0x4c, 0x03]; // PUSHDATA1, 3 bytes
        script_bytes.extend_from_slice(&[0x01, 0x02, 0x03]);
        let script = Script(script_bytes);
        let instructions = script.instructions().unwrap();
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0], Instruction::PushBytes(vec![0x01, 0x02, 0x03]));
        
        // Test PUSHDATA2
        let mut script_bytes = vec![0x4d, 0x03, 0x00]; // PUSHDATA2, 3 bytes (little endian)
        script_bytes.extend_from_slice(&[0x01, 0x02, 0x03]);
        let script = Script(script_bytes);
        let instructions = script.instructions().unwrap();
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0], Instruction::PushBytes(vec![0x01, 0x02, 0x03]));
    }

    #[test]
    fn test_op_return() {
        let op_return_script = Script(vec![0x6a, 0x04, 0x01, 0x02, 0x03, 0x04]); // OP_RETURN + 4 bytes
        assert!(op_return_script.is_op_return());
        
        let regular_script = Script::new_p2pkh(&[0x12; 20]);
        assert!(!regular_script.is_op_return());
    }

    #[test]
    fn test_script_encode_decode() {
        let original = Script::new_p2pkh(&[0x12; 20]);
        let encoded = original.consensus_encode_to_vec().unwrap();
        let decoded = Script::consensus_decode_from_slice(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_script_execution_basic() {
        // Test simple push and verify
        let script = Script(vec![0x01, 0x01, 0x69]); // Push 1, OP_VERIFY
        let mut stack = vec![];
        let result = script.execute(&mut stack, None);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_script_execution_stack_ops() {
        // Test OP_DUP
        let script = Script(vec![0x01, 0x42, 0x76]); // Push 0x42, OP_DUP
        let mut stack = vec![];
        let result = script.execute(&mut stack, None);
        assert!(result.is_ok());
        assert_eq!(stack.len(), 2);
        assert_eq!(stack[0], vec![0x42]);
        assert_eq!(stack[1], vec![0x42]);

        // Test OP_SWAP
        let mut stack = vec![vec![0x01], vec![0x02]];
        let script = Script(vec![0x7c]); // OP_SWAP
        let result = script.execute(&mut stack, None);
        assert!(result.is_ok());
        assert_eq!(stack[0], vec![0x02]);
        assert_eq!(stack[1], vec![0x01]);
    }

    #[test]
    fn test_script_execution_crypto_ops() {
        // Test OP_HASH160
        let script = Script(vec![0x04, 0x01, 0x02, 0x03, 0x04, 0xa9]); // Push 4 bytes, OP_HASH160
        let mut stack = vec![];
        let result = script.execute(&mut stack, None);
        assert!(result.is_ok());
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].len(), 20); // Hash160 produces 20 bytes

        // Test OP_SHA256
        let script = Script(vec![0x04, 0x01, 0x02, 0x03, 0x04, 0xa8]); // Push 4 bytes, OP_SHA256
        let mut stack = vec![];
        let result = script.execute(&mut stack, None);
        assert!(result.is_ok());
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0].len(), 32); // SHA256 produces 32 bytes
    }

    #[test]
    fn test_script_execution_equal_ops() {
        // Test OP_EQUAL with equal values
        let script = Script(vec![0x01, 0x42, 0x01, 0x42, 0x87]); // Push 0x42, Push 0x42, OP_EQUAL
        let mut stack = vec![];
        let result = script.execute(&mut stack, None);
        assert!(result.is_ok());
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0], vec![1u8]); // True

        // Test OP_EQUAL with different values
        let script = Script(vec![0x01, 0x42, 0x01, 0x43, 0x87]); // Push 0x42, Push 0x43, OP_EQUAL
        let mut stack = vec![];
        let result = script.execute(&mut stack, None);
        assert!(result.is_ok());
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0], Vec::<u8>::new()); // False
    }

    #[test]
    fn test_script_execution_verify_ops() {
        // Test OP_EQUALVERIFY success
        let script = Script(vec![0x01, 0x42, 0x01, 0x42, 0x88]); // Push 0x42, Push 0x42, OP_EQUALVERIFY
        let mut stack = vec![];
        let result = script.execute(&mut stack, None);
        assert!(result.is_ok());

        // Test OP_EQUALVERIFY failure
        let script = Script(vec![0x01, 0x42, 0x01, 0x43, 0x88]); // Push 0x42, Push 0x43, OP_EQUALVERIFY
        let mut stack = vec![];
        let result = script.execute(&mut stack, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_script_execution_checksig() {
        // Test OP_CHECKSIG with valid-looking signature and pubkey
        let signature = vec![0x30, 0x44, 0x02, 0x20]; // DER signature prefix
        signature.extend_from_slice(&[0x12; 32]); // r value
        signature.extend_from_slice(&[0x02, 0x20]); // s prefix
        signature.extend_from_slice(&[0x34; 32]); // s value
        signature.push(0x01); // SIGHASH_ALL
        
        let pubkey = vec![0x02]; // Compressed pubkey prefix
        pubkey.extend_from_slice(&[0x56; 32]); // x coordinate
        
        let mut script_bytes = vec![];
        script_bytes.push(signature.len() as u8);
        script_bytes.extend_from_slice(&signature);
        script_bytes.push(pubkey.len() as u8);
        script_bytes.extend_from_slice(&pubkey);
        script_bytes.push(0xac); // OP_CHECKSIG
        
        let script = Script(script_bytes);
        let mut stack = vec![];
        
        let tx_context = ScriptExecutionContext {
            transaction_hash: [0x78; 32],
            input_index: 0,
            amount: 100000,
            lock_time: 0,
            sequence: 0xffffffff,
        };
        
        let result = script.execute(&mut stack, Some(&tx_context));
        assert!(result.is_ok());
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0], vec![1]); // Should succeed with simplified verification
    }

    #[test]
    fn test_script_execution_multisig() {
        // Test simple 1-of-2 multisig
        let signature = vec![0x30, 0x44]; // Simplified signature
        signature.extend_from_slice(&[0x12; 66]);
        
        let pubkey1 = vec![0x02];
        pubkey1.extend_from_slice(&[0x11; 32]);
        let pubkey2 = vec![0x03];
        pubkey2.extend_from_slice(&[0x22; 32]);
        
        let mut script_bytes = vec![];
        script_bytes.push(0x51); // OP_1 (m = 1)
        script_bytes.push(signature.len() as u8);
        script_bytes.extend_from_slice(&signature);
        script_bytes.push(0x52); // OP_2 (n = 2)
        script_bytes.push(pubkey1.len() as u8);
        script_bytes.extend_from_slice(&pubkey1);
        script_bytes.push(pubkey2.len() as u8);
        script_bytes.extend_from_slice(&pubkey2);
        script_bytes.push(0xae); // OP_CHECKMULTISIG
        
        let script = Script(script_bytes);
        let mut stack = vec![vec![]]; // Extra value for off-by-one bug
        
        let result = script.execute(&mut stack, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_script_execution_alt_stack() {
        // Test OP_TOALTSTACK and OP_FROMALTSTACK
        let script = Script(vec![0x01, 0x42, 0x6b, 0x01, 0x43, 0x6c]); // Push 0x42, OP_TOALTSTACK, Push 0x43, OP_FROMALTSTACK
        let mut stack = vec![];
        let result = script.execute(&mut stack, None);
        assert!(result.is_ok());
        assert_eq!(stack.len(), 2);
        assert_eq!(stack[0], vec![0x43]);
        assert_eq!(stack[1], vec![0x42]);
    }

    #[test]
    fn test_script_execution_constants() {
        // Test OP_0 through OP_16
        let script = Script(vec![0x00, 0x51, 0x52, 0x60]); // OP_0, OP_1, OP_2, OP_16
        let mut stack = vec![];
        let result = script.execute(&mut stack, None);
        assert!(result.is_ok());
        assert_eq!(stack.len(), 4);
        assert_eq!(stack[0], vec![]); // OP_0 pushes empty
        assert_eq!(stack[1], vec![0x01]); // OP_1
        assert_eq!(stack[2], vec![0x02]); // OP_2
        assert_eq!(stack[3], vec![0x10]); // OP_16
    }

    #[test]
    fn test_script_execution_errors() {
        // Test stack underflow
        let script = Script(vec![0x76]); // OP_DUP with empty stack
        let mut stack = vec![];
        let result = script.execute(&mut stack, None);
        assert!(result.is_err());

        // Test OP_RETURN
        let script = Script(vec![0x6a]); // OP_RETURN
        let mut stack = vec![];
        let result = script.execute(&mut stack, None);
        assert!(result.is_err());

        // Test invalid opcode
        let script = Script(vec![0x50]); // OP_RESERVED
        let mut stack = vec![];
        let result = script.execute(&mut stack, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_script_execution_limits() {
        // Test operation count limit
        let mut script_bytes = vec![];
        for _ in 0..202 {
            script_bytes.push(0x61); // OP_NOP
        }
        let script = Script(script_bytes);
        let mut stack = vec![];
        let result = script.execute(&mut stack, None);
        assert!(result.is_err());

        // Test push data size limit
        let mut script_bytes = vec![0x4d, 0x09, 0x02]; // PUSHDATA2, 521 bytes
        script_bytes.extend_from_slice(&vec![0x00; 521]);
        let script = Script(script_bytes);
        let mut stack = vec![];
        let result = script.execute(&mut stack, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_signature_verification() {
        let script = Script::new();
        
        // Test with valid-looking inputs
        let signature = vec![0x30, 0x44]; // DER prefix
        signature.extend_from_slice(&[0x12; 66]); // Valid length signature
        let pubkey = vec![0x02]; // Compressed pubkey
        pubkey.extend_from_slice(&[0x34; 32]);
        let message_hash = [0x56; 32];
        
        let result = script.verify_signature(&signature, &pubkey, &message_hash);
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Test with invalid inputs
        let result = script.verify_signature(&[], &pubkey, &message_hash);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_script_num_conversion() {
        let executor = ScriptExecutor::new(&mut vec![], None);
        
        // Test positive number
        assert_eq!(executor.script_num_to_int(&[0x01]).unwrap(), 1);
        assert_eq!(executor.script_num_to_int(&[0x02]).unwrap(), 2);
        assert_eq!(executor.script_num_to_int(&[0x7f]).unwrap(), 127);
        
        // Test negative number
        assert_eq!(executor.script_num_to_int(&[0x81]).unwrap(), -1);
        assert_eq!(executor.script_num_to_int(&[0x82]).unwrap(), -2);
        
        // Test zero
        assert_eq!(executor.script_num_to_int(&[]).unwrap(), 0);
        assert_eq!(executor.script_num_to_int(&[0x00]).unwrap(), 0);
        assert_eq!(executor.script_num_to_int(&[0x80]).unwrap(), 0); // Negative zero
        
        // Test multi-byte numbers
        assert_eq!(executor.script_num_to_int(&[0x00, 0x01]).unwrap(), 256);
        assert_eq!(executor.script_num_to_int(&[0x00, 0x81]).unwrap(), -256);
    }

    #[test]
    fn test_is_true() {
        let executor = ScriptExecutor::new(&mut vec![], None);
        
        // Test true values
        assert!(executor.is_true(&[0x01]));
        assert!(executor.is_true(&[0xff]));
        assert!(executor.is_true(&[0x00, 0x01]));
        
        // Test false values
        assert!(!executor.is_true(&[]));
        assert!(!executor.is_true(&[0x00]));
        assert!(!executor.is_true(&[0x00, 0x00]));
        assert!(!executor.is_true(&[0x80])); // Negative zero
    }
}