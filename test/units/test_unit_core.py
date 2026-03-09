import enum
import re
import unittest

from refinery.units import autoinvoke, Entry, Argument, Arg


class TestAutoinvoke(unittest.TestCase):

    def test_simple_positional_args(self):
        def func(a, b, c):
            return (a, b, c)
        kw = dict(a=1, b=2, c=3)
        result = autoinvoke(func, kw)
        self.assertEqual(result, (1, 2, 3))

    def test_keywords_are_popped(self):
        def func(a, b):
            return a + b
        kw = dict(a=10, b=20, extra='leftover')
        autoinvoke(func, kw)
        self.assertIn('extra', kw)
        self.assertNotIn('a', kw)
        self.assertNotIn('b', kw)

    def test_default_values_used_when_key_missing(self):
        def func(a, b=99):
            return (a, b)
        kw = dict(a=5)
        result = autoinvoke(func, kw)
        self.assertEqual(result, (5, 99))

    def test_keyword_only_args(self):
        def func(a, *, kw1, kw2='default'):
            return (a, kw1, kw2)
        kw = dict(a=1, kw1='hello')
        result = autoinvoke(func, kw)
        self.assertEqual(result, (1, 'hello', 'default'))

    def test_keyword_only_with_provided_value(self):
        def func(a, *, kw1, kw2='default'):
            return (a, kw1, kw2)
        kw = dict(a=1, kw1='hello', kw2='world')
        result = autoinvoke(func, kw)
        self.assertEqual(result, (1, 'hello', 'world'))

    def test_var_positional(self):
        def func(a, *args):
            return (a, args)
        kw = dict(a=1, args=[10, 20, 30])
        result = autoinvoke(func, kw)
        self.assertEqual(result, (1, (10, 20, 30)))

    def test_var_keyword_merges_remaining(self):
        def func(a, **kwargs):
            return (a, kwargs)
        kw = dict(a=1, extra1='x', extra2='y')
        result = autoinvoke(func, kw)
        self.assertEqual(result, (1, {'extra1': 'x', 'extra2': 'y'}))

    def test_var_keyword_explicit_and_remaining(self):
        def func(a, b, **kwargs):
            return (a, b, kwargs)
        kw = dict(a=1, b=2, c=3, d=4)
        result = autoinvoke(func, kw)
        self.assertEqual(result, (1, 2, {'c': 3, 'd': 4}))

    def test_missing_required_parameter_raises_value_error(self):
        def func(a, b, c):
            return (a, b, c)
        kw = dict(a=1, b=2)
        with self.assertRaises(ValueError) as cm:
            autoinvoke(func, kw)
        self.assertIn('c', str(cm.exception))

    def test_no_params_no_keywords(self):
        def func():
            return 'ok'
        result = autoinvoke(func, {})
        self.assertEqual(result, 'ok')

    def test_extra_keywords_without_var_keyword_stay_in_dict(self):
        def func(a):
            return a
        kw = dict(a=1, extra='stays')
        autoinvoke(func, kw)
        self.assertEqual(kw, {'extra': 'stays'})

    def test_extra_keywords_consumed_when_var_keyword_present(self):
        def func(a, **kwargs):
            return kwargs
        kw = dict(a=1, extra='consumed')
        result = autoinvoke(func, kw)
        self.assertEqual(result, {'extra': 'consumed'})

    def test_positional_only_args(self):
        # Use exec to define a function with positional-only params for Python 3.8+
        ns = {}
        exec("def func(a, b, /, c): return (a, b, c)", ns)
        func = ns['func']
        kw = dict(a=10, b=20, c=30)
        result = autoinvoke(func, kw)
        self.assertEqual(result, (10, 20, 30))


class TestEntry(unittest.TestCase):

    def test_entry_is_instantiable(self):
        e = Entry()
        self.assertIsInstance(e, Entry)

    def test_entry_is_a_class(self):
        self.assertTrue(isinstance(Entry, type))

    def test_entry_subclass(self):
        class MyEntry(Entry):
            pass
        self.assertTrue(issubclass(MyEntry, Entry))
        self.assertIsInstance(MyEntry(), Entry)


class TestArgument(unittest.TestCase):

    def test_construction_positional_args(self):
        a = Argument(1, 2, 3)
        self.assertEqual(a.args, [1, 2, 3])
        self.assertEqual(a.kwargs, {})

    def test_construction_keyword_args(self):
        a = Argument(foo='bar', baz=42)
        self.assertEqual(a.args, [])
        self.assertEqual(a.kwargs, {'foo': 'bar', 'baz': 42})

    def test_construction_mixed_args(self):
        a = Argument('x', 'y', key='val')
        self.assertEqual(a.args, ['x', 'y'])
        self.assertEqual(a.kwargs, {'key': 'val'})

    def test_rmatmul_invokes_function(self):
        def func(a, b, kw=None):
            return (a, b, kw)
        a = Argument(1, 2, kw='hello')
        result = func @ a
        self.assertEqual(result, (1, 2, 'hello'))

    def test_rmatmul_with_no_args(self):
        def func():
            return 'called'
        a = Argument()
        result = func @ a
        self.assertEqual(result, 'called')

    def test_repr_with_normal_values(self):
        a = Argument(1, 'hello')
        r = repr(a)
        self.assertEqual(r, "1, 'hello'")

    def test_repr_with_kwargs(self):
        a = Argument(key=42)
        r = repr(a)
        self.assertEqual(r, "key=42")

    def test_repr_mixed(self):
        a = Argument('pos', key='val')
        r = repr(a)
        self.assertEqual(r, "'pos', key='val'")

    def test_repr_with_named_object(self):
        class FakeCallable:
            __name__ = 'my_func'
            def __repr__(self):
                return '<FakeCallable>'
        a = Argument(key=FakeCallable())
        r = repr(a)
        self.assertIn('my_func', r)

    def test_repr_with_class_name_fallback(self):
        class WeirdObject:
            def __repr__(self):
                return '<weird>'
        obj = WeirdObject()
        # Remove __name__ to make sure it falls through to __class__.__name__
        self.assertFalse(hasattr(obj, '__name__'))
        a = Argument(key=obj)
        r = repr(a)
        self.assertIn('WeirdObject', r)

    def test_repr_normal_value_not_using_name(self):
        # Normal repr (not starting with '<') should just use repr()
        a = Argument(key=42)
        r = repr(a)
        self.assertEqual(r, 'key=42')

    def test_repr_empty(self):
        a = Argument()
        r = repr(a)
        self.assertEqual(r, '')


class TestArgSentinels(unittest.TestCase):

    def test_delete_is_a_type(self):
        self.assertTrue(isinstance(Arg.delete, type))

    def test_omit_is_a_type(self):
        self.assertTrue(isinstance(Arg.omit, type))

    def test_delete_and_omit_are_distinct(self):
        self.assertIsNot(Arg.delete, Arg.omit)


class TestArgInit(unittest.TestCase):

    def test_omit_values_are_filtered(self):
        a = Arg('--test', help='some help')
        self.assertIn('help', a.kwargs)
        self.assertEqual(a.kwargs['help'], 'some help')
        # Other omitted kwargs should not be in kwargs
        self.assertNotIn('action', a.kwargs)
        self.assertNotIn('choices', a.kwargs)
        self.assertNotIn('const', a.kwargs)
        self.assertNotIn('default', a.kwargs)
        self.assertNotIn('dest', a.kwargs)
        self.assertNotIn('metavar', a.kwargs)
        self.assertNotIn('nargs', a.kwargs)
        self.assertNotIn('required', a.kwargs)
        self.assertNotIn('type', a.kwargs)

    def test_all_kwargs_provided(self):
        a = Arg('--flag',
            action='store_true',
            choices=[1, 2],
            const=True,
            default=False,
            dest='flag_dest',
            help='flag help',
            metavar='F',
            nargs='?',
            required=True,
            type=int,
        )
        self.assertEqual(a.kwargs['action'], 'store_true')
        self.assertEqual(a.kwargs['choices'], [1, 2])
        self.assertEqual(a.kwargs['const'], True)
        self.assertEqual(a.kwargs['default'], False)
        self.assertEqual(a.kwargs['dest'], 'flag_dest')
        self.assertEqual(a.kwargs['help'], 'flag help')
        self.assertEqual(a.kwargs['metavar'], 'F')
        self.assertEqual(a.kwargs['nargs'], '?')
        self.assertEqual(a.kwargs['required'], True)
        self.assertEqual(a.kwargs['type'], int)

    def test_args_are_stored(self):
        a = Arg('--verbose', '-v', help='increase verbosity')
        self.assertEqual(a.args, ['--verbose', '-v'])

    def test_group_is_stored(self):
        a = Arg('--opt', group='advanced')
        self.assertEqual(a.group, 'advanced')

    def test_group_defaults_to_none(self):
        a = Arg('data')
        self.assertIsNone(a.group)

    def test_guessed_defaults_to_empty_set(self):
        a = Arg('data')
        self.assertEqual(a.guessed, set())

    def test_guessed_is_converted_to_set(self):
        a = Arg('data', guessed={'help', 'type'})
        self.assertEqual(a.guessed, {'help', 'type'})


class TestArgDelete(unittest.TestCase):

    def test_delete_returns_arg_with_nargs_delete(self):
        d = Arg.Delete()
        self.assertIsInstance(d, Arg)
        self.assertIs(d.kwargs['nargs'], Arg.delete)

    def test_delete_has_no_args(self):
        d = Arg.Delete()
        self.assertEqual(d.args, [])


class TestArgCounts(unittest.TestCase):

    def test_counts_basic(self):
        a = Arg.Counts('-v', '--verbose', help='verbosity')
        self.assertIsInstance(a, Arg)
        self.assertEqual(a.kwargs['action'], 'count')
        self.assertEqual(a.args, ['-v', '--verbose'])
        self.assertEqual(a.kwargs['help'], 'verbosity')

    def test_counts_minimal(self):
        a = Arg.Counts('-q')
        self.assertEqual(a.kwargs['action'], 'count')
        self.assertEqual(a.args, ['-q'])

    def test_counts_with_group(self):
        a = Arg.Counts('-v', group='debug')
        self.assertEqual(a.group, 'debug')

    def test_counts_with_dest(self):
        a = Arg.Counts('-v', dest='verbosity')
        self.assertEqual(a.kwargs['dest'], 'verbosity')


class TestArgSwitch(unittest.TestCase):

    def test_switch_default_on(self):
        a = Arg.Switch('--enable', help='enable feature')
        self.assertEqual(a.kwargs['action'], 'store_true')

    def test_switch_off(self):
        a = Arg.Switch('--disable', off=True)
        self.assertEqual(a.kwargs['action'], 'store_false')

    def test_switch_with_group(self):
        a = Arg.Switch('--flag', group='options')
        self.assertEqual(a.group, 'options')

    def test_switch_with_dest(self):
        a = Arg.Switch('-s', dest='switch_var')
        self.assertEqual(a.kwargs['dest'], 'switch_var')


class TestArgAsOption(unittest.TestCase):

    class Color(enum.Enum):
        RED = 1
        GREEN = 2
        BLUE = 3

    class MixedCase(enum.Enum):
        CamelCase = 'cc'
        lower_case = 'lc'
        UPPER_CASE = 'uc'

    def test_none_returns_none(self):
        result = Arg.AsOption(None, self.Color)
        self.assertIsNone(result)

    def test_already_instance_returns_unchanged(self):
        val = self.Color.RED
        result = Arg.AsOption(val, self.Color)
        self.assertIs(result, val)

    def test_exact_name_lookup(self):
        result = Arg.AsOption('RED', self.Color)
        self.assertEqual(result, self.Color.RED)

    def test_case_insensitive_name_lookup(self):
        result = Arg.AsOption('green', self.Color)
        self.assertEqual(result, self.Color.GREEN)

    def test_mixed_case_insensitive_lookup(self):
        result = Arg.AsOption('camelcase', self.MixedCase)
        self.assertEqual(result, self.MixedCase.CamelCase)

    def test_value_based_lookup(self):
        result = Arg.AsOption(2, self.Color)
        self.assertEqual(result, self.Color.GREEN)

    def test_invalid_value_raises_value_error(self):
        with self.assertRaises(ValueError) as cm:
            Arg.AsOption('PURPLE', self.Color)
        msg = str(cm.exception)
        self.assertIn('choices', msg.lower() or msg)

    def test_invalid_value_error_contains_member_names(self):
        with self.assertRaises(ValueError) as cm:
            Arg.AsOption('INVALID', self.Color)
        msg = str(cm.exception)
        # The error message should contain the member names
        self.assertIn('RED', msg)


class TestArgAsRegExp(unittest.TestCase):

    def test_string_regex_compiled(self):
        pattern = Arg.AsRegExp('utf-8', r'\d+')
        self.assertIsNotNone(pattern.match(b'123'))
        self.assertIsNone(pattern.match(b'abc'))

    def test_bytes_regex_compiled(self):
        pattern = Arg.AsRegExp('utf-8', b'\\d+')
        self.assertIsNotNone(pattern.match(b'456'))

    def test_string_encoded_with_codec(self):
        # Test with a latin-1 specific character
        pattern = Arg.AsRegExp('latin-1', 'caf\xe9')
        self.assertIsNotNone(pattern.match(b'caf\xe9'))

    def test_flags_are_passed_through(self):
        pattern = Arg.AsRegExp('utf-8', b'test', flags=re.IGNORECASE)
        self.assertIsNotNone(pattern.match(b'TEST'))

    def test_returns_compiled_pattern(self):
        pattern = Arg.AsRegExp('utf-8', 'hello')
        self.assertIsInstance(pattern, re.Pattern)

    def test_bytearray_input(self):
        pattern = Arg.AsRegExp('utf-8', bytearray(b'hello'))
        self.assertIsNotNone(pattern.match(b'hello'))


class TestArgFsPath(unittest.TestCase):

    def test_fspath_with_option_sets_metavar_B(self):
        a = Arg.FsPath('--path', help='a file path')
        self.assertEqual(a.kwargs['metavar'], 'B')

    def test_fspath_positional_no_metavar_override(self):
        a = Arg.FsPath('filepath', help='a file path')
        # When no '-' in args, metavar remains omitted (not set)
        self.assertNotIn('metavar', a.kwargs)

    def test_fspath_explicit_metavar_not_overridden(self):
        a = Arg.FsPath('--path', metavar='PATH')
        self.assertEqual(a.kwargs['metavar'], 'PATH')

    def test_fspath_uses_pathvar_type(self):
        from refinery.lib.argformats import pathvar
        a = Arg.FsPath('--path')
        self.assertIs(a.kwargs['type'], pathvar)

    def test_fspath_with_group(self):
        a = Arg.FsPath('--path', group='io')
        self.assertEqual(a.group, 'io')


class TestArgUpdateHelp(unittest.TestCase):

    def test_format_default_integer(self):
        a = Arg('count', help='The count is {default}', default=42)
        a.update_help()
        self.assertEqual(a.kwargs['help'], 'The count is 42')

    def test_format_default_string(self):
        a = Arg('name', help='Default name is {default}', default='foo')
        a.update_help()
        self.assertEqual(a.kwargs['help'], 'Default name is foo')

    def test_format_default_empty_list(self):
        a = Arg('items', help='Default is {default}', default=[])
        a.update_help()
        self.assertEqual(a.kwargs['help'], 'Default is empty')

    def test_format_default_single_element_list(self):
        a = Arg('items', help='Default is {default}', default=[7])
        a.update_help()
        self.assertEqual(a.kwargs['help'], 'Default is 7')

    def test_format_default_single_element_set(self):
        a = Arg('items', help='Default is {default}', default={'only'})
        a.update_help()
        self.assertEqual(a.kwargs['help'], 'Default is only')

    def test_format_default_bytes_alnum(self):
        a = Arg('data', help='Default is {default}', default=b'hello')
        a.update_help()
        self.assertEqual(a.kwargs['help'], 'Default is hello')

    def test_format_default_bytes_non_alnum(self):
        a = Arg('data', help='Default is {default}', default=b'\x00\xff')
        a.update_help()
        self.assertEqual(a.kwargs['help'], 'Default is H:00ff')

    def test_format_default_slice(self):
        a = Arg('bounds', help='Default is {default}', default=slice(1, 10))
        a.update_help()
        self.assertIn('1', a.kwargs['help'])
        self.assertIn('10', a.kwargs['help'])

    def test_format_default_slice_with_step(self):
        a = Arg('bounds', help='Default is {default}', default=slice(0, 10, 2))
        a.update_help()
        self.assertIn('0', a.kwargs['help'])
        self.assertIn('10', a.kwargs['help'])
        self.assertIn('2', a.kwargs['help'])

    def test_format_choices(self):
        a = Arg('mode', help='Choices: {choices}', choices=['a', 'b', 'c'])
        a.update_help()
        self.assertEqual(a.kwargs['help'], 'Choices: a, b, c')

    def test_format_varname_with_metavar(self):
        a = Arg('data', help='Variable name is {varname}', metavar='DATA')
        a.update_help()
        self.assertEqual(a.kwargs['help'], 'Variable name is DATA')

    def test_format_varname_falls_back_to_destination(self):
        a = Arg('data', help='Variable name is {varname}')
        a.update_help()
        self.assertEqual(a.kwargs['help'], 'Variable name is data')

    def test_no_help_does_not_crash(self):
        a = Arg('data')
        # Should not raise
        a.update_help()

    def test_rmatmul_calls_update_help(self):
        """Arg.__rmatmul__ should call update_help before invoking the method."""
        called = []

        def method(*args, help=None, default=None, **kwargs):
            called.append(help)

        a = Arg('--test', help='value is {default}', default=5)
        method @ a
        self.assertTrue(called)
        self.assertEqual(called[0], 'value is 5')


class TestArgIsSubclassOfArgument(unittest.TestCase):

    def test_arg_is_subclass_of_argument(self):
        self.assertTrue(issubclass(Arg, Argument))

    def test_arg_instance_is_argument(self):
        a = Arg('test')
        self.assertIsInstance(a, Argument)


class TestArgDestination(unittest.TestCase):

    def test_positional_destination(self):
        a = Arg('mydata')
        self.assertEqual(a.destination, 'mydata')

    def test_option_with_dest(self):
        a = Arg('--verbose', dest='verbosity')
        self.assertEqual(a.destination, 'verbosity')

    def test_option_infers_from_long_flag(self):
        a = Arg('--my-option')
        dest = a.destination
        self.assertTrue(dest.isidentifier())


if __name__ == '__main__':
    unittest.main()
