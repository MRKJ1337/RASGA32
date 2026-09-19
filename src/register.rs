use core::panic;

use rand::rngs::StdRng;

use crate::prelude::*;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Register {
    R0 = 0,
    R1 = 1,
    R2 = 2,
    R3 = 3,
    R4 = 4,
    R5 = 5,
    R6 = 6,
    R7 = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
}

impl Default for Register {
    fn default() -> Self {
        return Register::R0;
    }
}

impl Register {
    pub const PC: Register = Register::R15;
    pub const LR: Register = Register::R14;
    pub const SP: Register = Register::R13;

    pub fn increment(&self, shellcode: &mut Shellcode, r_minus_1: Register) {
        shellcode.dpshiftreg(Opcode::SUB, false, *self, *self, r_minus_1, Shift::ROR, r_minus_1);
    }

    /// Cancel out the current register
    /// by calling `EORSPL <r> ROR 16` twice.
    pub fn nullify(
        self,
        _prng: &mut StdRng,
        shellcode: &mut Shellcode,
    ) {
        shellcode.dpshiftimm(Opcode::EOR, true, self, self, self, 16);
        shellcode.dpshiftimm(Opcode::EOR, true, self, self, self, 16);
    }

    /// Nullify a registry with a register that is already null
    /// with an EOR operation.
    pub fn nullify_with_register(
        &self,
        shellcode: &mut Shellcode,
        r_null: Register
    ) {
        shellcode.dpshiftreg(Opcode::SUB, true, *self, *self, *self, Shift::ROR, r_null);
    }

    /// Subtract the current register with `r_sub`.
    /// This implies that `ROR` will be 0, thus the necessity of a null registry.
    pub fn sub_with_register(
        &self,
        shellcode: &mut Shellcode,
        r_sub: Register,
        r_null: Register
    ) {
        shellcode.dpshiftreg(
            Opcode::SUB,
            false,
            *self,
            *self,
            r_sub,
            Shift::ROR,
            r_null
        );
    }

    /// Repeatedly substract the current register
    /// with a fixed step until we reach the value.
    pub fn sub(
        &self,
        prng: &mut StdRng,
        shellcode: &mut Shellcode,
        cond: Cond,
        r_null: Register,
        r_null_2: Register,
        value: u32,
    ) {
        let block_size: u8 = 0x7a;

        let amount_multiple  = value / (block_size as u32);
        for _ in 0..amount_multiple {
            shellcode.dpimm(Opcode::SUB, cond, false, *self, *self, block_size);
        }

        let reminder = (value % (block_size as u32)) as u8;
        if reminder > 0 {
            let x = get_random_alphanumeric_complement_char(prng, reminder);
            let y = reminder ^ x;

            shellcode.dpimm(Opcode::EOR, Cond::PL, true, r_null, r_null, x);
            shellcode.dpimm(Opcode::EOR, Cond::PL, true, r_null, r_null, y);
            self.sub_with_register(shellcode, r_null, r_null_2);
            
            r_null.nullify_with_register(shellcode, r_null_2);
        }
    }

    /// Repeatedly add the current **null** register
    /// with a fixed step until we reach the value.
    pub fn add(
        &self,
        prng: &mut StdRng,
        shellcode: &mut Shellcode,
        r_null: Register,
        r_null_2: Register,
        value: u32,
    ) {
        let block_size: u8 = 0x7a;

        // Store the step
        // then flip it
        r_null.set_u8_value_from_reg(prng, shellcode, r_null, block_size, 0);
        r_null.switch_to_negative(shellcode, r_null_2);
        let amount_multiple  = value / (block_size as u32);
        for _ in 0..amount_multiple {
            shellcode.dpshiftreg(Opcode::SUB, false, *self, *self, r_null, Shift::ROR, r_null_2);
        }
        r_null.nullify_with_register(shellcode, r_null_2);

        // Slightly modified algorithm
        let reminder = (value % (block_size as u32)) as u8;
        if reminder > 0 {
            let x = get_random_alphanumeric_complement_char(prng, reminder);
            let y = reminder ^ x;

            shellcode.dpimm(Opcode::EOR, Cond::PL, true, r_null, r_null, x);
            shellcode.dpimm(Opcode::EOR, Cond::PL, true, r_null, r_null, y);
            r_null.switch_to_negative(shellcode, r_null_2);
            self.sub_with_register(shellcode, r_null, r_null_2);
            
            r_null.nullify_with_register(shellcode, r_null_2);
        }
    }

    fn is_alphanumeric_register(&self) -> bool {
        return [
            Register::R3,
            Register::R5,
            Register::R7,
        ].contains(self);
    }

    /// Set an 8 bits value on current register `r{3/5/7}`
    /// by XORing from another register.
    /// 
    /// Only *positive* (complementary to 0x100) values are supported.
    pub fn set_u8_value_from_reg(
        &self,
        prng: &mut StdRng,
        shellcode: &mut Shellcode,
        src: Register,
        target_value: u8,
        known_value: u8
    ) {
        if ! self.is_alphanumeric_register() {
            panic!("This operation is not supported for other registers than r{{3,5,7}}.");
        }
        
        if target_value >= 0x80 {
            panic!("0x{:x} >= 0x80 is not supported.", target_value);
        } else {
            if (target_value).is_ascii_alphanumeric() {
                shellcode.dpimm(Opcode::EOR, Cond::PL, true, *self, src, target_value);
            } else {
                let x = get_random_alphanumeric_complement_char(prng, target_value);
                let y = x ^ target_value ^ known_value;
                shellcode.dpimm(Opcode::EOR, Cond::PL, true, *self, src, x);
                shellcode.dpimm(Opcode::EOR, Cond::PL, true, *self, *self, y);
            }
        }
    }

    pub fn switch_to_negative(
        &self,
        shellcode: &mut Shellcode,
        r_null: Register
    ) {
        shellcode.dpshiftreg(
            Opcode::SUB,
            false,
            *self,
            r_null,
            *self,
            Shift::ROR,
            r_null
        );
    }

    /// If the register is zero, turn it into -1.
    /// Also serves as a helper to set the negative flag `N == 1`.
    pub fn set_minus_1_from_null(&self, shellcode: &mut Shellcode, set_negative_flag: bool) {
        shellcode.dpimm(Opcode::EOR, Cond::PL, true, *self, *self, 0x30);
        shellcode.dpimm(Opcode::SUB, Cond::PL, set_negative_flag, *self, *self, 0x31);
    }

    /// Reset the negative flag.
    pub fn reset_n_flag(&self, shellcode: &mut Shellcode) {
        let r = *self;
        shellcode.dpimm(Opcode::EOR, Cond::MI, true, r, r, 0x30);
        shellcode.dpimm(Opcode::SUB, Cond::PL, true, r, r, 0x30);
    }
}