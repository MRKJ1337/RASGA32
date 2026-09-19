use crate::prelude::*;

// ==============================
// LEGACY
// ==============================
pub fn encode_data(prng: &mut StdRng, input: &[u8], marker: u8) -> Vec<u8> {
    let mut result: Vec<u8> = vec![];
    for ab in input.iter() {
        let b = (ab) & 0xf;
        let e0 = enc_data_msn(prng, b, marker) << 4;
        let ef = e0 | b;

        let d = ((ab & 0xf0) ^ e0) >> 4;
        let c0 = (enc_data_msn(prng, d, marker)) << 4;
        let cd: u8 = c0 | d;

        // 0xAB (from input)
        // gets splitted into two bytes
        // such as 0xAB = 0xCD XOR 0xEF
        result.push(cd);
        result.push(ef);
    }
    result
}

pub fn enc_data_msn(prng: &mut StdRng, c: u8, i: u8) -> u8 {
    let output: u8 = match c {
        c if c <= i => {
            if c == 0 {
                let array  = [5, 7];
                *array.choose(prng).unwrap()
            } else {
                let array = [4, 5, 6, 7];
                *array.choose(prng).unwrap()
            }
        },
        c if c == 0 => {
            let array = [3, 5, 7];
            *array.choose(prng).unwrap()
        },
        c => {
            if c <= 0x0A {
                let array = [4, 5, 6, 7];
                *array.choose(prng).unwrap()
            } else {
                let array = [4, 6];
                *array.choose(prng).unwrap()
            }
        }
    };
    output
}
// ==============================
// LEGACY
// ==============================

fn write_byte_internal(
    prng: &mut StdRng,
    value: u8,
    output: &mut Shellcode,

    r_current_byte: Register,
    r_null: Register
) {
    if value.is_ascii_alphanumeric() {
        output.dpimm(Opcode::EOR, Cond::PL, true, r_current_byte, r_null,value);
    } else {
        if value < 0x80 {
            r_current_byte.set_u8_value_from_reg(prng, output, r_null, value, 0);
        } else if value == 0x80 {
            output.dpimm(Opcode::SUB, Cond::PL, false, r_current_byte, r_null, 0x4f); 
            output.dpimm(Opcode::SUB, Cond::PL, false, r_current_byte, r_current_byte, 0x31);
        } else {
            let opposite = !value;
            
            if opposite.is_ascii_alphabetic() {
                output.dpimm(Opcode::EOR, Cond::PL, true, r_current_byte, r_null, opposite);
            } else {
                r_current_byte.set_u8_value_from_reg(prng, output, r_null, opposite, 0);
            }

            output.dpshiftreg(Opcode::SUB, false, r_current_byte, r_null, r_current_byte, Shift::ROR, r_null);
        }
    }
}

pub fn write_byte(
    prng: &mut StdRng,
    value: u8,
    output: &mut Shellcode,

    r_minus_1: Register,
    r_current_byte: Register,
    r_null: Register,
    r_addr: Register,
) {
    if value != 0 {
        if value == 0xff {
            output.sbyteposti(r_minus_1, r_addr, r_minus_1, 18);
        } else {
            write_byte_internal(prng, value, output, r_current_byte, r_null);
            output.sbyteposti(r_current_byte, r_addr, r_minus_1, 18);
        }
    } else {
        output.sbyteposti(r_null, r_addr, r_minus_1, 18);
    }
}

pub fn write_dword(
    prng: &mut StdRng,
    value: u32,
    output: &mut Shellcode,

    r_minus_1: Register,
    r_current_byte: Register,
    r_null: Register,
    r_addr: Register,
) {
    let bytes = value.to_ne_bytes();
    for b in bytes {
        write_byte(prng, b, output, r_minus_1, r_current_byte, r_null, r_addr);
    }
}

pub fn branch(cond: Cond, offset: i32) -> Vec<u8> {
    let imm24 = ((offset - 8) >> 2) & 0xffffff;
    let v = imm24.to_ne_bytes();
    let mut r : Vec<u8> = vec![];
    r.push(v[0]);
    r.push(v[1]);
    r.push(v[2]);
    r.push(0xa | ((cond as u8) << 4));

    return r;
}