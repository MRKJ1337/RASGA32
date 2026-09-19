use rasga::prelude::*;

fn main() {
    let mut prng = StdRng::seed_from_u64(0);

    let mut state = State::default();
    let initializer = build_initializer(&mut prng, &mut state);

    let mut output = Shellcode::default();
    output.cat(&initializer);

    // ==============================
    // The shellcode to rewrite
    // ==============================
    let mut target = Shellcode::default();
    target.create_placeholders(4);
    
    // ==============================
    // Set r{addr}
    // ==============================
    let size = 0x100;
    output.gap_traverse_with_state(&mut prng, size - output.opcodes.len() as u32, &state, true);

    // ==============================
    // Call self-modifying code snippet
    // ==============================
    output.gap_traverse_with_state_until_next_placeholder(&mut target, &mut prng, &mut state, false);
    output.replace_bytes_on_place(&mut prng, &mut target, &[0xef, 0xbe, 0xad, 0xde], &mut state);
    output.pad_with_crash(size as usize, state.i);

    // The overwritten part
    // which should be appended to the first block
    output.cat(&target);

    output.is_alphanumeric().unwrap();

    match String::try_from(&output) {
        Ok(s) => {
            println!("{}", s);
        },
        Err(e) => {
            panic!("{}", e);
        }
    }
}
