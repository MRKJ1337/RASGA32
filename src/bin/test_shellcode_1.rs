use rasga::prelude::*;

fn main() {
    let mut prng = StdRng::seed_from_u64(0);

    let mut state = State::default();
    let mut output = Shellcode::default();
    
    let initializer = build_initializer(&mut prng, &mut state);
    output.cat(&initializer);
    output.gap_traverse_with_state(&mut prng, 0x100, &state, true);

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
