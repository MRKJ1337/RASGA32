use rasga::prelude::*;

fn main() {
    let mut prng = StdRng::seed_from_u64(0);

    let mut output = Shellcode::default();
    Register::R3.nullify(&mut prng, &mut output);
    Register::R5.nullify_with_register(&mut output, Register::R3);
    Register::R7.nullify_with_register(&mut output, Register::R3);

    Register::R3.add(&mut prng, &mut output, Register::R5, Register::R7, 0x100);
    Register::R3.add(&mut prng, &mut output, Register::R5, Register::R7, 0x7a);
    Register::R3.add(&mut prng, &mut output, Register::R5, Register::R7, 0x180);

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
