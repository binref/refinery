"""
Provides a customized argument parser that is used by all refinery `refinery.units.Unit`s.
"""
from __future__ import annotations

from argparse import (
    Action,
    ArgumentError,
    ArgumentParser,
    ArgumentTypeError,
    RawDescriptionHelpFormatter,
)
from typing import TYPE_CHECKING, Any, Sequence, cast

if TYPE_CHECKING:
    from _typeshed import SupportsWrite

import sys

from refinery.lib.tools import get_terminal_size, terminalfit


class ArgparseError(ValueError):
    """
    This custom exception type is thrown from the custom argument parser of
    `refinery.units.Unit` rather than terminating program execution immediately.
    The `parser` parameter is a reference to the argument parser that threw
    the original argument parsing exception with the given `message`.
    """
    def __init__(self, parser, message):
        self.parser = parser
        super().__init__(message)


class LineWrapRawTextHelpFormatter(RawDescriptionHelpFormatter):
    """
    The refinery help text formatter uses the full width of the terminal and prints argument
    options only once after the long name of the option.
    """

    def __init__(self, prog, indent_increment=2, max_help_position=30, width=None):
        super().__init__(prog, indent_increment, max_help_position, width=get_terminal_size())

    def add_text(self, text):
        if isinstance(text, str):
            text = terminalfit(text, width=get_terminal_size())
        return super().add_text(text)

    def _format_action_invocation(self, action):
        if not action.option_strings:
            metavar, = self._metavar_formatter(action, action.dest)(1)
            return metavar
        parts = []
        if action.nargs == 0:
            parts.extend(action.option_strings)
        else:
            default = action.dest.upper()
            args_string = self._format_args(action, default)
            for option_string in action.option_strings:
                parts.append(str(option_string))
            parts[-1] += F' {args_string}'
        switches = ', '.join(parts)
        if all(opt.startswith('--') for opt in action.option_strings):
            switches = '\x20' * 4 + switches
        return switches


class ArgumentParserWithKeywordHooks(ArgumentParser):
    """
    The refinery argument parser remembers the order of arguments in the property `order`.
    Furthermore, the parser can be initialized with a given set of keywords which will be
    parsed as if they had been passed as keyword arguments on the command line.
    """

    order: list[str]
    keywords: dict[str, Any]

    class RememberOrder:
        __wrapped__: Action

        def __init__(self, action: Action):
            super().__setattr__('__wrapped__', action)

        def __setattr__(self, name, value):
            return setattr(self.__wrapped__, name, value)

        def __getattr__(self, name):
            return getattr(self.__wrapped__, name)

        def __call__(self, parser: ArgumentParserWithKeywordHooks, *args, **kwargs):
            destination = self.__wrapped__.dest
            if destination not in parser.order:
                parser.order.append(destination)
            return self.__wrapped__(parser, *args, **kwargs)

    def __init__(self, keywords, prog=None, description=None, add_help=True):
        super().__init__(
            prog=prog,
            description=description,
            add_help=add_help,
            formatter_class=LineWrapRawTextHelpFormatter,
        )
        if sys.version_info >= (3, 14):
            self.color = False
        self.keywords = keywords
        self.order = []

    def print_help(self, file: SupportsWrite[str] | None = None) -> None:
        out = file or sys.stderr
        super().print_help(file=out)
        if file is None:
            sys.stdout.close()

    def _add_action(self, action: Action):
        keywords = self.keywords
        if action.dest in keywords:
            action.required = False
            try:
                atype = action.type
            except AttributeError:
                atype = None
            if callable(atype):
                value = keywords[action.dest]
                if value is not None and isinstance(value, str) and atype is not str:
                    keywords[action.dest] = atype(keywords[action.dest])
        return super()._add_action(
            cast(Action, self.RememberOrder(action)))

    def _parse_optional(self, arg_string):
        if isinstance(arg_string, str):
            return super()._parse_optional(arg_string)

    def error_commandline(self, message):
        super().error(message)

    def error(self, message):
        raise ArgparseError(self, message)

    def parse_args_with_nesting(self, args: Sequence[str], namespace=None):
        self.order = []
        args = list(args)
        keywords = self.keywords
        if args and args[~0] and isinstance(args[~0], str):
            nestarg = args[~0]
            nesting = len(nestarg)
            if nestarg.startswith('[]'):
                self.set_defaults(squeeze=True)
                nestarg = nestarg[2:]
                nesting = nesting - 2
            if nestarg == ']' * nesting:
                self.set_defaults(nesting=-nesting)
                del args[~0:]
            elif nestarg == '[' * nesting:
                self.set_defaults(nesting=nesting)
                del args[~0:]
        self.set_defaults(**self.keywords)
        try:
            parsed = self.parse_args(args=args, namespace=namespace)
        except (ArgumentError, ArgumentTypeError, ArgparseError) as e:
            self.error(str(e))
        except Exception as e:
            self.error(F'Failed to parse arguments: {args!r}, {e}, {type(e).__name__}')
        for name in keywords:
            param = getattr(parsed, name, None)
            if param != keywords[name]:
                self.error(
                    F'parameter "{name}" duplicated with conflicting '
                    F'values {param} and {keywords[name]}'
                )
        for name in vars(parsed):
            if name not in self.order:
                self.order.append(name)
        return parsed
