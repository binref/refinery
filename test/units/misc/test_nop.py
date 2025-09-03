from .. import TestUnitBase


class TestNop(TestUnitBase):

    def test_doing_nothing(self):
        unit = self.load()
        data = self.generate_random_buffer(200)
        self.assertEqual(data, unit(data))
