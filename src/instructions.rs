#[derive(Clone, Copy, Debug)]
pub enum Opcode {
    EOR = 1,
    SUB = 2,
    RSB = 3,
    LDR = 6,
    STR = 7,
    LDM = 8,
    STM = 9,
}

#[derive(Clone, Copy)]
pub enum Cond {
    MI = 4,
    PL = 5,
}

#[derive(Clone, Copy)]
pub enum Shift {
    ROR = 10,
    LSR = 11,
}
