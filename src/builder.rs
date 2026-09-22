use crate::prelude::*;

/// As some operations (substraction, etc.)
/// cannot be done without remaining alphanumeric, we need to create an alphanumeric offset.
const OFFSET: u8 = 0x30;

impl Shellcode {
    pub fn add_encoded_data(&mut self, prng: &mut StdRng, input: &Shellcode, state: &mut State) {
        let encoded_data = encode_data(prng, &input.opcodes, state.marker);
        self.opcodes.extend_from_slice(&encoded_data);

        let max = 0x30 | state.marker;
        self.append_byte(get_random_alphanumeric_char(prng) as u8);
        // This will be the byte that determines
        // whether this is the end of the payload or not.
        self.append_byte(get_random_alphanumeric_char_ltmax(prng, max));
    }

    /// Create a new alphanumeric placeholder that
    /// can be replaced later seemlessly with the real bytes.
    pub fn create_placeholders(&mut self, size: u32) {
        let offset = self.opcodes.len() as u32;
        self.placeholders.push_back((offset, size));
        for _ in 0..size {
            self.opcodes.push(0x41);
        }
    }

    /// Replace all non-alphanumeric chars by
    /// 'A'.
    pub fn replace_by_alphanumeric(
        &mut self,
    ) {
        for i in 0..self.opcodes.len() {
            if !self.opcodes[i].is_ascii_alphanumeric() {
                self.opcodes[i] = 0x41;
            }
        }
    }

    pub fn pad_with_nop(
        &mut self,
        size: usize,
        r_null: Register
    ) {
        if self.opcodes.len() > size {
            panic!("Shellcode is already longer than the desired size.");
        }

        for _ in (0..size - self.opcodes.len()).step_by(4) {
            r_null.nullify_with_register(self, r_null);
        }
    }

    pub fn pad_with_crash(
        &mut self,
        size: usize,
        r_null: Register
    ) {
        if self.opcodes.len() > size {
            panic!("Shellcode is already longer than the desired size.");
        }

        for _ in (0..size - self.opcodes.len()).step_by(4) {
            self.lsbyte(Opcode::LDR, Cond::PL, r_null, r_null, OFFSET);
        }
    }

    pub fn gap_traverse(
        &mut self,
        prng: &mut StdRng,
        offset: u32,
        r_addr: Register,
        r_null: Register,
        r_null_2: Register,

        init_address: bool
    ) {
        // Need to add an offset
        // because "replace_bytes()"
        // actually needs an offset to be set
        // that decreases the size
        if init_address {
            // Set R := $PC - OFFSET
            self.dpimm(Opcode::SUB, Cond::PL, false, r_null, Register::PC, OFFSET);
            // Move R to R{addr}
            self.dpshiftreg(Opcode::SUB, false, r_addr, r_null, r_null_2, Shift::ROR, r_null_2);
            // Reset R
            r_null.nullify_with_register(self, r_null_2);

            // Looking at GDB,
            // the register actually holds $PC + 8

            // We also need to add OFFSET twice
            // because it gets substracted twice
            // when self-modifying

            // Substract also by 4
            // because when replacing bytes,
            // additional offset = 4 gets added
            r_addr.add(prng, self, r_null, r_null_2, offset - 8 + (OFFSET as u32) * 2 - 4);
        } else {
            r_addr.add(prng, self, r_null, r_null_2, offset);
        }
    }



    /// A wrapper for the gap traverse, instead using the state directly.
    /// 
    /// **Ensure** that `r{i} = x` and `r{k} = 0` before calling this method.
    pub fn gap_traverse_with_state(
        &mut self,
        prng: &mut StdRng,
        offset: u32,
        state: &State,
        init_address: bool
    ) {
        state.nullify_with_i(state.i, Cond::PL, self);
        self.gap_traverse(prng, offset, state.address, state.i, state.k, init_address);
        state.restore_i(self);
    }

    /// A wrapper for the gap traverse, instead using the state directly.
    /// 
    /// **Ensure** that `r{i} = x` and `r{k} = 0` before calling this method.
    pub fn gap_traverse_with_state_until_next_placeholder(
        &mut self,
        target: &Shellcode,
        prng: &mut StdRng,
        state: &State,
        init_address: bool
    ) {
        let next_offset = target.placeholders.get(0).unwrap().0;
        let offset = next_offset - (target.last_placeholder.0 + target.last_placeholder.1);
        
        if offset == 0 {
            return;
        }

        self.gap_traverse_with_state(prng, offset, state, init_address);
    }

    /// This is the function that will decode parts
    /// of the decoder loop, as it contains some non-alphanumeric chars.
    /// 
    /// For alphanumeric chars, `r{address}` will simply increment by 1.
    /// Otherwise, the byte will be replaced on site.
    /// 
    /// To move the address pointer further, you need
    /// to interact with `gap_traverse`.
    pub fn replace_bytes_on_place(
        &mut self,
        prng: &mut StdRng,
        target: &mut Shellcode,
        data: &[u8],
        state: &mut State,
    ) {
        let placeholder = target.placeholders.pop_front().unwrap();
        target.last_placeholder = placeholder;
        let offset = placeholder.0;
        let size = placeholder.1;

        if data.len() as u32 != size {
            panic!("Data length is not equal to the current placeholder size ({} != {}).", data.len(), size);
        }

        for p in 0..data.len() {
            let y = data[p];
            if y.is_ascii_alphanumeric() {
                state.address.sub_with_register(self, state.j, state.k);
                target.opcodes[(offset as usize) + p] = y;
                continue;
            }

            if y >= 0x80 {
                if (!y).is_ascii_alphabetic() {
                    self.dpimm(
                        Opcode::EOR,
                        Cond::PL,
                        true,
                        state.k,
                        state.j,
                        !y,
                    );

                    self.lsbyte(
                        Opcode::STR,
                        Cond::MI,
                        state.k,
                        state.address,
                        OFFSET,
                    );

                    self.dpimm(
                        Opcode::SUB,
                        Cond::MI,
                        true,
                        state.k,
                        state.i,
                        state.x,
                    );

                    state.address.sub_with_register(self, state.j, state.k);

                    continue;
                }

                let a = get_random_alphanumeric_complement_char(prng, !y);
                let b =  a ^ (!y);
                self.dpimm(Opcode::EOR, Cond::PL, true, state.k, state.j, a);
                self.dpimm(Opcode::EOR, Cond::MI, true, state.k, state.k, b);
                self.lsbyte(Opcode::STR, Cond::MI, state.k, state.address, OFFSET);
                self.dpimm(Opcode::SUB, Cond::MI, true, state.k, state.i, state.x);

                state.address.sub_with_register(self, state.j, state.k);
                continue;
            }

            if state.x > y {
                let z1 = state.x - y;
                if z1.is_ascii_alphanumeric() {
                    self.dpimm(Opcode::SUB, Cond::PL, false, state.k, state.i, z1);
                    self.lsbyte(Opcode::STR, Cond::PL, state.k, state.address, OFFSET);

                    state.address.sub_with_register(self, state.j, state.k);
                    continue;
                }
            }

            let z2 = state.x + y;
            if z2.is_ascii_alphanumeric() {
                self.dpimm(Opcode::RSB, Cond::PL, false, state.k, state.i, z2);
                self.lsbyte(Opcode::STR, Cond::PL, state.k, state.address, OFFSET);

                state.address.sub_with_register(self, state.j, state.k);
                continue;
            }

            let z3 = state.x ^ y;
            if z3.is_ascii_alphanumeric() {
                self.dpimm(Opcode::EOR, Cond::PL, true, state.k, state.i, z3);
                
                self.lsbyte(Opcode::STR, Cond::PL, state.k, state.address, OFFSET);

                state.address.sub_with_register(self, state.j, state.k);
                continue;
            }

            let a2 = get_random_alphanumeric_complement_char(prng, z3);
            let b2 = a2 ^ z3;
            self.dpimm(Opcode::EOR, Cond::PL, true, state.k, state.i, a2);
            self.dpimm(Opcode::EOR, Cond::PL, true, state.k, state.k, b2);
            self.lsbyte(Opcode::STR, Cond::PL, state.k, state.address, OFFSET);

            state.address.sub_with_register(self, state.j, state.k);
        }
    }

    pub fn check_remaining_placeholders(&self) {
        if ! self.placeholders.is_empty() {
            panic!("There are remaining placeholders : {:?}", self.placeholders);
        }
    }

    /// A crash stub, useful for blind debugging outside of *gdb*,
    /// as the behavior of the shellcode does vary.
    pub fn crash(&mut self) {
        self.lsbyte(Opcode::LDR, Cond::PL, Register::R3, Register::R3, OFFSET);
        self.lsbyte(Opcode::LDR, Cond::MI, Register::R3, Register::R3, OFFSET);
    }
}

/// This is the most important function out of the
/// 4 ones, as it saves the used registers in the state struct.
/// The initializer will later set values for them.
pub fn build_decoder_of_decoder_loop(
    prng: &mut StdRng,
    target: &mut Shellcode,
    state: &mut State,
    size: u32
) -> Shellcode {
    let mut shellcode = build_initializer(prng, state);

    shellcode.gap_traverse_with_state(prng, size - shellcode.opcodes.len() as u32, state, true);

    // Syscall - svcmi #0
    // We **replace only** the data part
    shellcode.gap_traverse_with_state_until_next_placeholder(target, prng, state, false);
    shellcode.replace_bytes_on_place(prng, target, &[0, 0, 0, 0x4f], state);

    // Check end of loop
    // * No need to replace bytes

    // Loop back - bmi 0xfffffX
    shellcode.gap_traverse_with_state_until_next_placeholder(target, prng, state, false);
    shellcode.replace_bytes_on_place(prng, target, &[0xf5, 0xff, 0xff, 0x4a], state);

    // Syscall - svcmi #0
    // We **replace only** the data part
    shellcode.gap_traverse_with_state_until_next_placeholder(target, prng, state, false);
    shellcode.replace_bytes_on_place(prng, target, &[0, 0, 0, 0x4f], state);

    state.nullify_with_i(state.i, Cond::PL, &mut shellcode);
    Register::R4.nullify_with_register(&mut shellcode, state.i);
    Register::R6.nullify_with_register(&mut shellcode, state.i);
    let r_minus_1 = state.j;
    let r_null = Register::R4;
    let r_current_byte = state.k;

    let m: Register  = state.i;
    let c = get_random_alphanumeric_offset_char_aligned(prng, 24);

    // Prepare to call syscall(SYS_sync)
    // with a dummy address buffer ;
    // Turns out that it also flushes the instruction cache
    // similarly to the old EABI swi #0x9f0002

    // Set stack address into r{m}
    shellcode.dpimm(Opcode::SUB, Cond::PL, false, m,Register::SP, c + 24);

    write_dword(prng, 0, &mut shellcode, r_minus_1, r_current_byte, r_null, m);
    // We set R1 as -1 for later use
    // THIS CANNOT BE CHANGED
    write_dword(prng, 0xffffffff, &mut shellcode, r_minus_1, r_current_byte, r_null, m);
    write_dword(prng, 0, &mut shellcode, r_minus_1, r_current_byte, r_null, m);

    shellcode.dpimm(Opcode::SUB, Cond::PL, false, m, Register::SP, c);
    shellcode.lmul(m, &[
        Register::R0,
        Register::R1,
        Register::R2,
        Register::R6,

        Register::R8,
        Register::R14,
    ]);

    // ------------------------------
    // Set r7 for syscall
    // ------------------------------
    Register::R7.set_u8_value_from_reg(prng, &mut shellcode, r_null, 0x24, 0);

    // ------------------------------
    // Reset registers
    // ------------------------------
    state.i.nullify_with_register(&mut shellcode, r_null);
    state.restore_i(&mut shellcode);
    state.j.nullify_with_register(&mut shellcode, r_null);
    Register::R6.nullify_with_register(&mut shellcode, r_null);

    shellcode.pad_with_nop((size - 4) as usize, r_null);

    state.set_minus_1_with_i(state.j, Cond::PL, &mut shellcode, true);

    shellcode
}

pub fn build_decoder_loop(
    prng: &mut StdRng,
    state: &State,
    size: u32
) -> Shellcode {
    let mut shellcode = Shellcode::default();

    // svcmi #0
    shellcode.create_placeholders(4);

    // Reset N == 0
    shellcode.dpimm(Opcode::EOR, Cond::MI, true, state.k, state.i, state.x);

    // Registers
    // NOTE: We suppose that all these registers are already null !
    let p = Register::R3;
    let s = Register::R4;
    let q = Register::R7;
    let t = Register::R6;
    // It is set thanks to using LDMSTR previously
    let r_minus_1 = Register::R1;
    let shift = Register::R5;
    p.nullify_with_register(&mut shellcode, state.k);
    q.nullify_with_register(&mut shellcode, state.k);
    s.nullify_with_register(&mut shellcode, state.k);
    t.nullify_with_register(&mut shellcode, state.k);
    shift.nullify_with_register(&mut shellcode, state.k);

    // Set s, t pointing to SP
    shellcode.gap_traverse(prng, size - shellcode.opcodes.len() as u32 + 4, s, p, q, true);
    shellcode.dpshiftreg(Opcode::SUB, false, t, s, p, Shift::ROR, p);

    // Use a register for shifting
    shift.set_u8_value_from_reg(prng, &mut shellcode, shift, 28, 0);

    // ::::::::::::::::::::::::::::::
    // LOOP START [*]
    // ::::::::::::::::::::::::::::::
    // Set N == 0
    shellcode.dpimm(Opcode::EOR, Cond::MI, true, p, shift, 0x70);

    // The loop that will store
    // the bytes 0xCD, 0xEF into respectively
    // r{p} and r{q}. r{s} will get incremented.
    shellcode.lsbyte(Opcode::LDR, Cond::PL, p, s, OFFSET);
    s.increment(&mut shellcode, r_minus_1);

    shellcode.lsbyte(Opcode::LDR, Cond::PL, q, s, OFFSET);
    // Store 0xCD0 ^ 0xEF = 0xAD in r{p}
    shellcode.dpshiftreg(Opcode::EOR, true, p, q, p, Shift::ROR, shift);
    // Store 0xAD at [t]
    shellcode.lsbyte(Opcode::STR, Cond::PL, p, t, OFFSET);
    t.increment(&mut shellcode, r_minus_1);
    s.increment(&mut shellcode, r_minus_1);

    // ------------------------------
    // LOOP END - Check if we reach the marker
    // at the end of the encoded shellcode
    // ------------------------------
    shellcode.dpimm(Opcode::RSB, Cond::PL, true, q, q, 0x30 | state.marker);

    // BMI 0xfffffX
    // Go back to [*] 
    shellcode.create_placeholders(4);

    // ------------------------------
    // Set r7 for syscall
    // ------------------------------
    Register::R3.nullify(prng, &mut shellcode);
    Register::R7.set_u8_value_from_reg(prng, &mut shellcode, Register::R3, 0x24, 0);
    Register::R3.set_minus_1_from_null(&mut shellcode, true);

    // svcmi #0
    shellcode.create_placeholders(4);
    
    let r_null = Register::R3;
    shellcode.pad_with_nop(size as usize, r_null);

    shellcode
}

/// Set values for the registers `r{i/j/address}`.
/// For instance :
/// ```plain
/// r{i} := x          
/// r{j} := -1
/// ```
/// 
/// Also add NOP sleds to the init. block so
/// the encoded decoder to decode gets actually replaced at the good address.
/// 
/// ## Warnings
/// - This function **must** be run after the decoder,
/// but **before** during runtime.
/// - The offset is not known in advance.
pub fn build_initializer(
    prng: &mut StdRng,
    state: &mut State,
) -> Shellcode {
    let mut shellcode = Shellcode::default();
    state.i.nullify(prng, &mut shellcode);
    state.j.nullify_with_register(&mut shellcode, state.i);
    state.k.nullify_with_register(&mut shellcode, state.i);
    state.address.nullify_with_register(&mut shellcode, state.i);

    state.restore_i(&mut shellcode);
    state.set_minus_1_with_i(state.j, Cond::PL, &mut shellcode, false);

    shellcode
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_data(data: &[u8]) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        for i in (0..data.len() - 1).step_by(2) {
            let cd = data[i];
            let ef = data[i + 1];

            let cd = cd << 4;
            result.push(cd ^ ef);
        }
        result
    }

    #[test]
    fn test_data_encoder() {
        let mut prng = StdRng::seed_from_u64(0);
        let plain_data = String::from("Hello world");
        let encoded_data = encode_data(&mut prng, plain_data.as_bytes(), 8);

        let decoded_data = decode_data(&encoded_data);
        let decoded_data = String::from_utf8(decoded_data).unwrap();

        assert_eq!(decoded_data, plain_data);
    }
}