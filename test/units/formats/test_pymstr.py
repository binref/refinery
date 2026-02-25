import marshal

from .. import TestUnitBase


class TestPyMarshalStrings(TestUnitBase):

    def test_simple_strings(self):
        unit = self.load()
        data = {
            'baz': {
                'foo': b'refined',
                'bar': b'binaries',
            },
        }
        test = marshal.dumps(data) | unit | {str}
        goal = {'foo', 'bar', 'baz', 'refined', 'binaries'}
        self.assertEqual(test, goal)
