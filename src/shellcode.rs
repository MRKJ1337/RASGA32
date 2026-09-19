use std::{
    collections::VecDeque, fs, io::{self}, string::FromUtf8Error
};

use crate::prelude::*;

#[derive(Default)]
pub struct Shellcode {
    pub opcodes: Vec<u8>,
    pub check_alphanumeric: bool,

    /// A queue that stores "placeholders", which is (offset, size).
    pub placeholders: VecDeque<(u32, u32)>,
    pub last_placeholder: (u32, u32),
}

impl Clone for Shellcode {
    fn clone(&self) -> Self {
        let mut result = Self::default();
        result.cat(self);
        result
    }
}

impl TryFrom<&Shellcode> for String {
    type Error = FromUtf8Error;

    fn try_from(value: &Shellcode) -> Result<Self, Self::Error> {
        String::from_utf8(value.opcodes.clone())
    }
}

impl<const N: usize> From<&[u8; N]> for Shellcode {
    fn from(value: &[u8; N]) -> Self {
        let mut shellcode = Shellcode::default();
        shellcode.opcodes.extend_from_slice(value);
        shellcode
    }
}

impl From<&String> for Shellcode {
    fn from(value: &String) -> Self {
        let mut shellcode = Shellcode::default();
        shellcode.opcodes.extend_from_slice(value.as_bytes());
        shellcode
    }
}

impl Shellcode {
    pub fn cat(&mut self, shellcode: &Shellcode) {
        if self.check_alphanumeric {
            shellcode.is_alphanumeric().unwrap();
        }
        let other_opcodes = &shellcode.opcodes;

        self.opcodes.extend_from_slice(other_opcodes);
    }

    pub fn append_byte(&mut self, c: u8) {
        if self.check_alphanumeric && !c.is_ascii_alphanumeric() {
            panic!("Bad alphanumeric : 0x{:x}", c);
        }
        self.opcodes.push(c);
    }

    pub fn from_binary_file(&mut self, file_path: &str) {
        let content = fs::read(file_path).expect("Could not open binary file");
        let mut s = Shellcode::default();
        s.opcodes.clear();
        s.opcodes.extend_from_slice(&content);
        self.cat(&s);
    }

    pub fn write_binary(&self, file_path: &str) -> io::Result<()> {
        fs::write(file_path, &self.opcodes)
    }

    fn append_opcode(
        &mut self,
        op: Opcode,
        signed: bool,
        register: Register,
    ) -> Result<(), String> {
        let n = register;
        if signed {
            match op {
                Opcode::EOR => {
                    self.append_byte(0x30 | (n as u8));
                }
                Opcode::SUB => {
                    self.append_byte(0x50 | (n as u8));
                }
                Opcode::RSB => {
                    self.append_byte(0x70 | (n as u8));
                }
                _ => {
                    return Err(format!("Insupported operation in signed mode : {:?}", op));
                }
            }
        } else {
            match op {
                Opcode::SUB => {
                    self.append_byte(0x40 | (n as u8));
                }
                Opcode::RSB => {
                    self.append_byte(0x60 | (n as u8));
                }
                _ => {
                    return Err(format!("Insupported operation in unsigned mode : {:?}", op));
                }
            }
        }
        Ok(())
    }

    pub fn add_marker(
        &mut self,
        r_null: Register
    ) {
        r_null.nullify_with_register(self, r_null);
        r_null.nullify_with_register(self, r_null);
        r_null.nullify_with_register(self, r_null);
    }

    ///
    /// (EOR/SUB/RSB)(PL/MI){S} rd, rn, #imm
    ///
    pub fn dpimm(
        &mut self,
        op: Opcode,
        cond: Cond,
        signed: bool,
        d: Register,
        n: Register,
        imm: u8,
    ) {
        self.append_byte(imm);
        self.append_byte((d as u8) << 4);

        self.append_opcode(op, signed, n).unwrap();

        match cond {
            Cond::PL => {
                self.append_byte(0x52);
            }
            Cond::MI => {
                self.append_byte(0x42);
            }
        }
    }

    ///
    /// (EOR/SUB/RSB)PL{S} rd, rn, ra ROR #imm
    ///
    pub fn dpshiftimm(
        &mut self,
        op: Opcode,
        signed: bool,
        d: Register,
        n: Register,
        a: Register,
        imm: u8,
    ) {
        self.append_byte(0x60 | (a as u8));
        self.append_byte(((d as u8) << 4) | (imm >> 1));

        self.append_opcode(op, signed, n).unwrap();

        self.append_byte(0x50);
    }

    ///
    /// (EOR/SUB/RSB)PL{S} rd, rn, ra (ROR/LSR) rb
    ///
    pub fn dpshiftreg(
        &mut self,
        op: Opcode,
        signed: bool,
        d: Register,
        n: Register,
        a: Register,
        shift: Shift,
        b: Register,
    ) {
        match shift {
            Shift::LSR => {
                self.append_byte(0x30 | (a as u8));
            }
            Shift::ROR => {
                self.append_byte(0x70 | (a as u8));
            }
        }
        self.append_byte(((d as u8) << 4) | (b as u8));

        self.append_opcode(op, signed, n).unwrap();

        self.append_byte(0x50);
    }

    ///
    /// (LDR/STR)(PL/MI)B rd, [rn, #-imm]
    ///
    pub fn lsbyte(&mut self, op: Opcode, cond: Cond, d: Register, n: Register, imm: u8) {
        self.append_byte(imm);
        self.append_byte((d as u8) << 4);

        match op {
            Opcode::STR => {
                self.append_byte(0x40 | (n as u8));
            }
            _ => {
                self.append_byte(0x50 | (n as u8));
            }
        }

        match cond {
            Cond::PL => {
                self.append_byte(0x55);
            }
            Cond::MI => {
                self.append_byte(0x45);
            }
        }
    }

    /// LDMPLDB rn!, (Register List)
    pub fn lmul(&mut self, n: Register, registers: &[Register]) {
        let mut register_list: u16 = 0;
        for r in registers {
            register_list |= 1 << (*r as u8);
        }
        let register_list_low = (register_list & 0xff) as u8;
        let register_list_high = ((register_list >> 8) & 0xff) as u8;
        self.append_byte(register_list_low);
        self.append_byte(register_list_high);
        self.append_byte(0x30 | (n as u8));
        self.append_byte(0x59);
    }

    /// SWI(PL/MI) 0x9f0002
    pub fn swi(&mut self, cond: Cond) {
        self.append_byte(0x02);
        self.append_byte(0x00);
        self.append_byte(0x9f);
        match cond {
            Cond::MI => {
                self.append_byte(0x4f);
            }
            Cond::PL => {
                self.append_byte(0x5f);
            }
        }
    }

    /// BMI 0xfffff4
    pub fn bmi(&mut self) {
        self.append_byte(0xdc);
        self.append_byte(0xff);
        self.append_byte(0xff);
        self.append_byte(0x4b);
    }

    /// STRPLB rd, [!rn, -(rm ROR #imm)] with P=0 i.e. post-indexed addressing mode
    pub fn sbyteposti(&mut self, d: Register, n: Register, m: Register, imm: u8) {
        self.append_byte(0x60 | (m as u8));
        self.append_byte(((d as u8) << 4) | (imm >> 1));
        self.append_byte(0x40 | (n as u8));
        self.append_byte(0x56);
    }

    pub fn is_alphanumeric(&self) -> Result<(), Vec<String>> {
        let mut errors: Vec<String> = vec![];
        let mut i = 0;
        for x in self.opcodes.iter() {
            if !x.is_ascii_alphanumeric() {
                let message = format!("Bad character detected at index={} : 0x{:x}", i, x);
                errors.push(message);
            }
            i += 1;
        }

        if errors.is_empty() {
            return Ok(());
        }
        Err(errors)
    }
}
