use rasga::prelude::*;

fn main() {
    let mut prng = StdRng::seed_from_u64(0);
    let mut state = State::default();
    state.marker = prng.random_range(1..=9);
    state.x = get_random_alphanumeric_offset_char(&mut prng, 0x01);

    // ------------------------------
    // Encode original shellcode
    // ------------------------------
    let mut input = Shellcode::default();
    let plain = "HELLO WORLD I AM JEFF";
    for c in plain.bytes() {
        input.append_byte(c);
    }

    let mut encoded_input = Shellcode::default();
    encoded_input.add_encoded_data(&mut prng, &input, &mut state); 

    let mut decoder_loop = build_decoder_loop(&mut prng, &state, 0x100);

    let decoder = build_decoder_of_decoder_loop(&mut prng, &mut decoder_loop, &mut state, 0x1B0);

    let mut output = Shellcode::default();
    output.check_alphanumeric = true;

    output.cat(&decoder);
    output.cat(&decoder_loop);
    output.cat(&encoded_input);

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
