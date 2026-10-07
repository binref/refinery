import gc

from refinery.lib.java import JvString

from ... import TestUnitBase


class TestJavaDisassembler(TestUnitBase):

    def test_keylogger_sample(self):
        unit = self.load(join=True, gray=True)
        data = self.download_sample('31055a528f9a139104a0ce8f4da6b4b89a37a800715292ae7f8f190b2a7b6582')
        dasm = unit(data)

        self.assertIn(B'lookupswitch    ___default => 0x0000095e', dasm)
        self.assertIn(B'lookupswitch    ___default => 0x000002b2', dasm)
        self.assertIn(B'tableswitch     ___default => 0x00000049', dasm)
        self.assertIn(B'00000049: 2b', dasm)
        self.assertIn(B'invokestatic    org.jnativehook.keyboard.NativeKeyEvent::getKeyText', dasm)

    def test_a_run_keeps_no_constant_pool_entry_alive(self):
        def strings():
            gc.collect()
            return sum(isinstance(obj, JvString) for obj in gc.get_objects())
        data = self.download_sample('31055a528f9a139104a0ce8f4da6b4b89a37a800715292ae7f8f190b2a7b6582')
        before = strings()
        self.load()(data)
        self.assertEqual(strings(), before)
