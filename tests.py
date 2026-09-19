from pwn import *

import unittest

class TestShellcode(unittest.TestCase):
    def setUp(self) -> None:
        self.core = Coredump("./core")

    def tearDown(self) -> None:
        pass

    def print_registers(self):
        for reg, value in self.core.registers.items():
            print('{:4s} => 0x{:08x}'.format(reg, value))

    def assertEqualHex(self, actual: int, expected: int):
        self.assertEqual(actual, expected, 'expected 0x{:08x}, got 0x{:08x}'.format(expected, actual))

    def test_register_1(self):
        self.assertEqualHex(self.core.registers['r3'], 0x100000000-0x7a)

    def test_register_2(self):
        self.assertEqualHex(self.core.registers['r3'], 0x100000000-0x200-0x7a)

    def test_register_3(self):
        self.assertEqualHex(self.core.registers['r3'], 0x100+0x7a+0x180)

    def test_register_4(self):
        self.assertEqualHex(self.core.registers['r3'], 0x7f)

    def test_shellcode_1(self):
        # The current PC value
        # where the instruction that will saves $PC into R holds at
        pc = 0x70776020

        # The offset, the OFFSET constant (2x, explained in the code)
        # and 4 bytes to remove
        self.assertEqualHex(self.core.registers['r6'], pc + 0x100 + 0x30 - 4)

    def test_shellcode_2(self):
        pc = 0x70776000+0x100
        value = u32(self.core.read(pc, 4))
        self.assertEqualHex(value, 0xdeadbeef)

if __name__ == '__main__':
    unittest.main()