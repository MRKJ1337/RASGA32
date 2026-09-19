use rand::prelude::*;

pub const ALPHANUMERIC_BYTES: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Get a random alphanumeric char.
pub fn get_random_alphanumeric_char(prng: &mut StdRng) -> u8 {
    let array = ALPHANUMERIC_BYTES.as_bytes();
    let e = *array.choose(prng).unwrap();
    e
}

/// Get a random alphanumeric char such as it is 4-bytes aligned.
pub fn get_random_alphanumeric_char_aligned(prng: &mut StdRng) -> u8 {
    loop {
        let array = ALPHANUMERIC_BYTES.as_bytes();
        let e = *array.choose(prng).unwrap();
        if e % 4 == 0 {
            return e;
        }
    }
}

/// Get a random alphanumeric char such as it does not exceed `max`.
pub fn get_random_alphanumeric_char_ltmax(prng: &mut StdRng, max: u8) -> u8 {
    let vector = ALPHANUMERIC_BYTES.as_bytes();
    let index = vector.iter().position(|&x| (x as u8) > max).expect("Cannot find random alphanumeric element.");
    let selected_index = prng.random_range(0..index);
    let e = *vector.get(selected_index).unwrap();
    e
}

/// Get a random alphanumeric char `x` such as `c + x` is also alphanumeric.
pub fn get_random_alphanumeric_offset_char(prng: &mut StdRng, c: u8) -> u8 {
    if c <= 0x4a {
        let max = 16 * 7 + 10 - c;
        loop {
            let x = get_random_alphanumeric_char_ltmax(prng, max);

            if (c + x).is_ascii_alphanumeric() {
                return x;
            }
        }
    }
    0
}

/// Get a random alphanumeric char `x` such as `c + x` is also alphanumeric and is 4-bytes aligned.
pub fn get_random_alphanumeric_offset_char_aligned(prng: &mut StdRng, c: u8) -> u8 {
    if c <= 0x4a {
        let max = 16 * 7 + 10 - c;
        loop {
            let x = get_random_alphanumeric_char_ltmax(prng, max);

            if (c + x).is_ascii_alphanumeric() && x % 4 == 0 {
                return x;
            }
        }
    }
    0
}

/// Get a random alphanumeric char `x` such as `c ^ x` is also alphanumeric and is 4-bytes aligned.
pub fn get_random_alphanumeric_complement_char(prng: &mut StdRng, c: u8) -> u8 {
    loop {
        let ret = get_random_alphanumeric_char(prng);
        if (c ^ ret).is_ascii_alphanumeric() {
            return ret;
        }
    }
}