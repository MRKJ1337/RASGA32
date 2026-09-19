use crate::prelude::*;

pub struct State {
    /// ### Legacy
    /// An integer randomly choosed between 1 and 9, both included.
    /// It is used as a marker to end the decoder loop.
    pub marker: u8,

    /// This register is primarily used to set other registers to 0.
    /// It is assigned the constant `x`.
    /// 
    /// As this is will the register
    /// that will be zero-ed (and will be assigned 'x'),
    /// we use R5 as we know its value
    /// and can be nullified quite easily.
    pub i: Register,
    /// This register is primarily used to increment other registers. Therefore, it is mainly equal to `0xffffffff`.
    pub j: Register,
    pub k: Register,

    /// The constant value used to either set
    /// registers to 0 or -1 (0xffffffff).
    pub x: u8,
    /// The register that stores the current working address. May be `$PC` or `$SP`, shifted by an arbitrary (alphanumeric?) offset.
    pub address: Register,
}

impl Default for State {
    fn default() -> Self {
        Self {
            marker: 8,

            i: Register::R5,
            j: Register::R3,
            k: Register::R7,

            x: 0x45,
            address: Register::R6
        }
    }
}

impl State {
    /// Restore the register `r{i}` with `x`.
    /// Only usable if `r{i}` has been zero-ed.
    pub fn restore_i(&self, shellcode: &mut Shellcode) {
        shellcode.dpimm(Opcode::EOR, Cond::PL, true, self.i, self.i, self.x);
    }

    /// Use shorter instructions to nullify a register
    /// by using `r{i}` if it is already null.
    pub fn nullify_with_i(&self, register: Register, cond: Cond, shellcode: &mut Shellcode) {
        shellcode.dpimm(Opcode::SUB, cond, false, register, self.i, self.x);
    }

    /// Set the register to `-1`.
    /// # Warning
    pub fn set_minus_1_with_i(&self, register: Register, cond: Cond, shellcode: &mut Shellcode, signed: bool) {
        shellcode.dpimm(Opcode::SUB, cond, signed, register, self.i, self.x + 1);
    }
}