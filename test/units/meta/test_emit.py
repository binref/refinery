from .. import TestUnitBase


class TestEmitter(TestUnitBase):

    def test_append(self):
        emit = self.load('x::', 'World')
        self.assertEqual(emit(B'Hello'), B'Hello\nWorld')

    def test_prepend(self):
        emit = self.load('Hello', 'x::')
        self.assertEqual(emit(B'World'), B'Hello\nWorld')

    def test_prepend_and_append(self):
        emit = self.load('Hello', 'x::', 'World')
        self.assertEqual(emit(B'cruel'), B'Hello\ncruel\nWorld')
