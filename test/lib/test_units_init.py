import enum

from .. import TestBase

from refinery.units import autoinvoke, Argument, Arg


class TestAutoinvoke(TestBase):

    def test_basic_positional_args(self):
        def func(a, b):
            return a + b
        result = autoinvoke(func, {'a': 3, 'b': 4})
        self.assertEqual(result, 7)

    def test_keyword_only_args(self):
        def func(*, key):
            return key
        result = autoinvoke(func, {'key': 'value'})
        self.assertEqual(result, 'value')

    def test_default_value_used(self):
        def func(x, y=10):
            return x + y
        result = autoinvoke(func, {'x': 5})
        self.assertEqual(result, 15)

    def test_missing_required_raises(self):
        def func(required_param):
            return required_param
        with self.assertRaises(ValueError):
            autoinvoke(func, {})

    def test_var_keyword_passthrough(self):
        def func(a, **kw):
            return (a, kw)
        result = autoinvoke(func, {'a': 1, 'extra1': 2, 'extra2': 3})
        self.assertEqual(result[0], 1)
        self.assertIn('extra1', result[1])
        self.assertIn('extra2', result[1])

    def test_var_positional(self):
        def func(a, *args):
            return (a, args)
        result = autoinvoke(func, {'a': 1, 'args': [2, 3, 4]})
        self.assertEqual(result[0], 1)
        self.assertEqual(result[1], (2, 3, 4))

    def test_mixed_positional_and_keyword_only(self):
        def func(a, b, *, c):
            return a * b + c
        result = autoinvoke(func, {'a': 2, 'b': 3, 'c': 10})
        self.assertEqual(result, 16)

    def test_extra_keys_consumed_by_var_keyword(self):
        def func(**kwargs):
            return kwargs
        result = autoinvoke(func, {'x': 1, 'y': 2})
        self.assertEqual(result, {'x': 1, 'y': 2})

    def test_no_params(self):
        def func():
            return 42
        result = autoinvoke(func, {})
        self.assertEqual(result, 42)


class TestArgument(TestBase):

    def test_rmatmul_calls_function(self):
        def add(a, b):
            return a + b
        arg = Argument(3, 4)
        result = add @ arg
        self.assertEqual(result, 7)

    def test_rmatmul_with_kwargs(self):
        def greet(name, greeting='Hello'):
            return F'{greeting}, {name}!'
        arg = Argument('World', greeting='Hi')
        result = greet @ arg
        self.assertEqual(result, 'Hi, World!')

    def test_repr_simple_args(self):
        arg = Argument(1, 'two', True)
        r = repr(arg)
        self.assertIn('1', r)
        self.assertIn("'two'", r)
        self.assertIn('True', r)

    def test_repr_kwargs(self):
        arg = Argument(key='value')
        r = repr(arg)
        self.assertIn('key', r)
        self.assertIn('value', r)

    def test_repr_object_with_name(self):
        class Named:
            __name__ = 'MyName'
        arg = Argument(key=Named())
        r = repr(arg)
        self.assertIn('MyName', r)

    def test_repr_object_with_repr_starting_with_angle(self):
        class AnotherClass:
            def __repr__(self):
                return '<special>'
        arg = Argument(key=AnotherClass())
        r = repr(arg)
        self.assertIn('AnotherClass', r)

    def test_slots(self):
        arg = Argument(1, 2, x=3)
        self.assertEqual(arg.args, [1, 2])
        self.assertEqual(arg.kwargs, {'x': 3})


class TestArg(TestBase):

    def test_arg_is_argument(self):
        arg = Arg('--foo', help='A foo argument')
        self.assertIsInstance(arg, Argument)

    def test_arg_omit_sentinel(self):
        arg = Arg('--bar')
        self.assertNotIn('action', arg.kwargs)

    def test_arg_explicit_kwargs(self):
        arg = Arg('--baz', action='store_true', help='enable baz')
        self.assertEqual(arg.kwargs.get('action'), 'store_true')
        self.assertEqual(arg.kwargs.get('help'), 'enable baz')

    def test_delete(self):
        arg = Arg.Delete()
        self.assertIsInstance(arg, Arg)
        self.assertIs(arg.kwargs.get('nargs'), Arg.delete)

    def test_counts(self):
        arg = Arg.Counts('-v', '--verbose', help='increase verbosity')
        self.assertIsInstance(arg, Arg)
        self.assertEqual(arg.kwargs.get('action'), 'count')

    def test_switch_default(self):
        arg = Arg.Switch('-q', '--quiet', help='be quiet')
        self.assertIsInstance(arg, Arg)
        self.assertEqual(arg.kwargs.get('action'), 'store_true')

    def test_switch_off(self):
        arg = Arg.Switch('-n', '--no-color', off=True, help='disable color')
        self.assertIsInstance(arg, Arg)
        self.assertEqual(arg.kwargs.get('action'), 'store_false')

    def test_fspath(self):
        arg = Arg.FsPath('-o', '--output', help='output path')
        self.assertIsInstance(arg, Arg)
        self.assertEqual(arg.kwargs.get('metavar'), 'B')

    def test_fspath_no_dash_no_metavar(self):
        arg = Arg.FsPath('path', help='a path')
        self.assertIsInstance(arg, Arg)
        self.assertNotEqual(arg.kwargs.get('metavar'), 'B')

    def test_binary(self):
        arg = Arg.Binary('-k', '--key', help='encryption key')
        self.assertIsInstance(arg, Arg)
        self.assertEqual(arg.kwargs.get('metavar'), 'B')

    def test_binary_no_dash(self):
        arg = Arg.Binary('data', help='input data')
        self.assertIsInstance(arg, Arg)

    def test_string(self):
        arg = Arg.String('-s', '--sep', help='separator')
        self.assertIsInstance(arg, Arg)
        self.assertEqual(arg.kwargs.get('metavar'), 'STR')

    def test_group(self):
        arg = Arg('--foo', group='advanced', help='advanced option')
        self.assertEqual(arg.group, 'advanced')

    def test_guessed(self):
        arg = Arg('--foo', guessed={'help', 'type'})
        self.assertEqual(arg.guessed, {'help', 'type'})

    def test_guessed_default_empty(self):
        arg = Arg('--foo')
        self.assertEqual(arg.guessed, set())

    def test_update_help_format_default_int(self):
        arg = Arg('--count', help='Number of items (default: {default})', default=5)
        arg.update_help()
        self.assertIn('5', arg.kwargs['help'])

    def test_update_help_format_default_str(self):
        arg = Arg('--mode', help='Mode to use (default: {default})', default='fast')
        arg.update_help()
        self.assertIn('fast', arg.kwargs['help'])

    def test_update_help_format_default_bytes_alnum(self):
        arg = Arg('--key', help='Key value (default: {default})', default=b'abc123')
        arg.update_help()
        self.assertIn('abc123', arg.kwargs['help'])

    def test_update_help_format_default_bytes_hex(self):
        arg = Arg('--key', help='Key (default: {default})', default=b'\xFF\x00')
        arg.update_help()
        self.assertIn('H:ff00', arg.kwargs['help'])

    def test_update_help_format_default_empty_list(self):
        arg = Arg('--items', help='Items (default: {default})', default=[])
        arg.update_help()
        self.assertIn('empty', arg.kwargs['help'])

    def test_update_help_format_default_single_element_list(self):
        arg = Arg('--items', help='Items (default: {default})', default=[42])
        arg.update_help()
        self.assertIn('42', arg.kwargs['help'])

    def test_update_help_format_choices(self):
        arg = Arg('--mode', help='Mode ({choices})', choices=['a', 'b', 'c'])
        arg.update_help()
        self.assertIn('a, b, c', arg.kwargs['help'])

    def test_update_help_format_default_slice(self):
        arg = Arg('--range', help='Range (default: {default})', default=slice(1, 10, 2))
        arg.update_help()
        self.assertIn('1:10:2', arg.kwargs['help'])

    def test_update_help_no_help_key_no_crash(self):
        arg = Arg('--foo')
        arg.update_help()

    def test_rmatmul_calls_update_help(self):
        def dummy_method(*args, **kwargs):
            pass
        arg = Arg('--test', help='test {default}', default=99)
        _ = dummy_method @ arg
        self.assertIn('99', arg.kwargs['help'])


class TestAsOption(TestBase):

    def test_none_returns_none(self):
        class Color(enum.Enum):
            RED = 1
        self.assertIsNone(Arg.AsOption(None, Color))

    def test_instance_returns_same(self):
        class Color(enum.Enum):
            RED = 1
        v = Color.RED
        self.assertIs(Arg.AsOption(v, Color), v)

    def test_string_name_lookup(self):
        class Color(enum.Enum):
            RED = 1
            BLUE = 2
        result = Arg.AsOption('RED', Color)
        self.assertEqual(result, Color.RED)

    def test_string_case_insensitive(self):
        class Mode(enum.Enum):
            FAST = 1
            SLOW = 2
        result = Arg.AsOption('fast', Mode)
        self.assertEqual(result, Mode.FAST)

    def test_value_lookup(self):
        class Priority(enum.IntEnum):
            LOW = 1
            HIGH = 2
        result = Arg.AsOption(2, Priority)
        self.assertEqual(result, Priority.HIGH)

    def test_invalid_raises(self):
        class Color(enum.Enum):
            RED = 1
        with self.assertRaises(ValueError):
            Arg.AsOption('PURPLE', Color)
