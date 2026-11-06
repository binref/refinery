"""
SECURITY: `before_and_after` and every other helper here that reports what an engine makes of a
program runs Node on it. Give them only programs a test writes out by hand, never anything from the
sample corpus.
"""
from __future__ import annotations

import inspect
import unittest

from collections import Counter
from enum import Enum, auto
from typing import Any, Callable, Iterable, Iterator, Mapping, NamedTuple, TypeVar

from test.lib.scripts.js.analysis.differential import (
    behavior,
    deobfuscate_source,
    host_behavior,
)

from refinery.lib.scripts import is_well_formed
from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.lexer import JsLexer
from refinery.lib.scripts.js.options import ExecutionModel
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer
from refinery.lib.scripts.js.token import JsTokenKind
from refinery.units.scripting.djs import djs

NL = chr(10)


def a_program(text: str) -> str:
    return inspect.cleandoc(text) + NL


def on_separate_lines(*texts: str) -> str:
    return NL.join(texts)


def well_formed(source: str) -> bool:
    return is_well_formed(JsParser(source).parse())


class _Spelled(NamedTuple):
    text: str
    is_comment: bool


def _without_whitespace(text: str) -> str:
    return ''.join(character for character in text if not character.isspace())


def _spelled_in(text: str) -> Iterator[_Spelled]:
    cut = 0
    for token in JsLexer(text).tokenize():
        if token.kind is not JsTokenKind.COMMENT:
            continue
        for character in text[cut:token.offset]:
            if not character.isspace():
                yield _Spelled(character, False)
        yield _Spelled(token.value, True)
        cut = token.offset + len(token.value)
    for character in text[cut:]:
        if not character.isspace():
            yield _Spelled(character, False)


def dropped_source_characters(source: str, printed: str) -> str:
    """
    The characters of *source* that *printed* does not account for, whitespace aside, or the empty
    string where it accounts for all of them. Code has to stand in *printed* in the order *source*
    wrote it, while a comment may stand anywhere.
    """
    written = list(_spelled_in(printed))
    code = ''.join(part.text for part in written if not part.is_comment)
    comments = Counter(_without_whitespace(part.text) for part in written if part.is_comment)
    missing: list[str] = []
    cursor = 0
    for part in _spelled_in(source):
        spelling = _without_whitespace(part.text)
        if part.is_comment and comments[spelling] > 0:
            comments[spelling] -= 1
            continue
        position = cursor
        for character in spelling:
            position = code.find(character, position)
            if position < 0:
                break
            position += 1
        if position < 0:
            missing.append(part.text)
        else:
            cursor = position
    return ''.join(missing)


def each_well_formed(programs: Iterable[str]) -> dict[str, bool]:
    return {program: well_formed(program) for program in programs}


def printed(source: str) -> str:
    return JsSynthesizer().convert(JsParser(source).parse())


def folded(
    source: str,
    *,
    module: bool = False,
    environment: HostEnvironment = HostEnvironment.universal,
) -> str:
    return source.encode('utf8') | djs(module=module, strict=True, environment=environment.name) | str


def evaluated_in_a_body(receiver: str, read: str, installs: str = '') -> str:
    body = F'function f() {{ var v = {receiver}; return {read}; }}\nconsole.log(f());\n'
    return F'{installs}\n{body}' if installs else body


def returned_from_a_body(body: str) -> str:
    return F'function f() {{ {body} }}\nconsole.log(f());\n'


def a_walk_of(receiver: str, installs: str = '') -> str:
    """
    The names are concatenated rather than joined, so a row that changes `Array.prototype` asks only
    whether the walk is answered, not whether a `join` is.
    """
    walk = F"var t = ''; for (var k in {receiver}) t += k; return t;"
    body = returned_from_a_body(walk)
    return F'{installs}\n{body}' if installs else body


def an_accessor_at(prototype: str, key: str) -> str:
    return (
        F"Object.defineProperty({prototype}, '{key}', "
        F"{{get: function () {{ return 'G'; }}}});"
    )


def before_and_after(
    source: str,
    *,
    module: bool = False,
    execution: ExecutionModel = ExecutionModel.module,
    environment: HostEnvironment = HostEnvironment.universal,
) -> tuple[tuple[str, str | None], tuple[str, str | None]]:
    """
    What Node makes of *source* and of its deobfuscation, each run as a CommonJS file, or as an ES
    module where *module* is set.
    """
    return (
        behavior(source, module=module),
        deobfuscated_behavior(source, module=module, execution=execution, environment=environment),
    )


def deobfuscated_behavior(
    source: str,
    *,
    module: bool = False,
    execution: ExecutionModel = ExecutionModel.module,
    environment: HostEnvironment = HostEnvironment.universal,
) -> Behavior:
    return behavior(deobfuscate_source(source, execution=execution, environment=environment), module=module)


def before_and_after_in_a_host(
    source: str,
    environment: HostEnvironment = HostEnvironment.universal,
) -> tuple[tuple[str, str | None], tuple[str, str | None]]:
    """
    What Node makes of *source* and of its deobfuscation, each run as a classic global script.
    """
    return (host_behavior(source), deobfuscated_host_behavior(source, environment))


def deobfuscated_host_behavior(
    source: str,
    environment: HostEnvironment = HostEnvironment.universal,
) -> Behavior:
    return host_behavior(folded(source, environment=environment))


#: The attributes of a browser window the entries observe, installed on the global object with the
#: behavior the HTML standard gives each.
WINDOW_ATTRIBUTES = a_program("""
    (function () {
      Object.setPrototypeOf(globalThis, Object.create(Object.getPrototypeOf(globalThis), {
        TEMPORARY: { value: 0, enumerable: true }
      }));
      Object.defineProperty(globalThis, 'window', {
        get: function () { return globalThis; }
      });
      Object.defineProperty(globalThis, 'top', {
        get: function () { return globalThis; }
      });
      var history = { length: 1 };
      Object.defineProperty(globalThis, 'history', {
        get: function () { return history; },
        configurable: true
      });
      var name = '';
      var status = '';
      var onload = null;
      Object.defineProperty(globalThis, 'name', {
        get: function () { return name; },
        set: function (v) { name = String(v); },
        configurable: true
      });
      Object.defineProperty(globalThis, 'status', {
        get: function () { return status; },
        set: function (v) { status = String(v); },
        configurable: true
      });
      Object.defineProperty(globalThis, 'location', {
        get: function () {
          return { href: 'https://example.test/', toString: function () { return this.href; } };
        },
        set: function (v) { console.log('navigate ' + String(v)); }
      });
      Object.defineProperty(globalThis, 'onload', {
        get: function () { return onload; },
        set: function (v) { onload = typeof v === 'function' ? v : null; },
        configurable: true
      });
    })();
    """)


def window_behavior(source: str) -> Behavior:
    return host_behavior(source, calls=('onload',), prelude=WINDOW_ATTRIBUTES)


def each_program_still_prints(
    programs: dict[str, str],
) -> dict[str, tuple[tuple[str, str | None], tuple[str, str | None]]]:
    return {
        source: ((prints, None), (prints, None))
        for source, prints in programs.items()
    }


Behavior = tuple[str, str | None]


class Reading(Enum):
    """
    How an engine runs a program and what its deobfuscation is told about it. `MODULE` runs it as a
    CommonJS file and deobfuscates it for a module of either kind, `COMMONJS` tells the
    deobfuscation it is a CommonJS file, `ES_MODULE` runs it as an ES module, `SCRIPT` as a classic
    global script, and `WINDOW` as a classic script in a browser window.
    """
    MODULE = auto()
    COMMONJS = auto()
    ES_MODULE = auto()
    SCRIPT = auto()
    WINDOW = auto()

    def read(
        self,
        source: str,
        environment: HostEnvironment = HostEnvironment.universal,
    ) -> tuple[Behavior, Behavior]:
        return (self.behaves(source), self.deobfuscated(source, environment))

    def behaves(self, source: str) -> Behavior:
        if self is Reading.SCRIPT:
            return host_behavior(source)
        if self is Reading.WINDOW:
            return window_behavior(source)
        return behavior(source, module=self is Reading.ES_MODULE)

    def deobfuscated(
        self,
        source: str,
        environment: HostEnvironment = HostEnvironment.universal,
    ) -> Behavior:
        if self is Reading.SCRIPT:
            return deobfuscated_host_behavior(source, environment)
        if self is Reading.WINDOW:
            return window_behavior(folded(source, environment=environment))
        if self is Reading.COMMONJS:
            return deobfuscated_behavior(source, execution=ExecutionModel.commonjs, environment=environment)
        return deobfuscated_behavior(source, module=self is Reading.ES_MODULE, environment=environment)


class Program(NamedTuple):
    text: str
    prints: Behavior
    reading: Reading = Reading.MODULE
    environment: HostEnvironment = HostEnvironment.universal

    def read(self) -> tuple[Behavior, Behavior]:
        return self.reading.read(self.text, self.environment)

    def behaves(self) -> Behavior:
        return self.reading.behaves(self.text)

    def deobfuscated(self) -> Behavior:
        return self.reading.deobfuscated(self.text, self.environment)

    def required(self) -> tuple[Behavior, Behavior]:
        return (self.prints, self.prints)


class FileProgram(NamedTuple):
    text: str
    as_commonjs: Behavior
    as_an_es_module: Behavior
    environment: HostEnvironment = HostEnvironment.universal

    def read_as(self, reading: Reading) -> Program:
        if reading is Reading.ES_MODULE:
            return Program(self.text, self.as_an_es_module, reading, self.environment)
        return Program(self.text, self.as_commonjs, reading, self.environment)


def as_classic_scripts(rows: Mapping[str, FileProgram]) -> dict[str, Program]:
    """
    *rows* read as classic global scripts that print what each row prints as a CommonJS file, which
    holds only for sloppy code reading no name the CommonJS wrapper binds and no top-level `this`.
    """
    return {
        label: Program(row.text, row.as_commonjs, Reading.SCRIPT, row.environment) for label, row in rows.items()
    }


def node_prints_what_each_row_pins(test: unittest.TestCase, rows: Mapping[str, FileProgram]):
    for label, row in rows.items():
        for reading in (Reading.COMMONJS, Reading.ES_MODULE):
            program = row.read_as(reading)
            with test.subTest(label=label, reading=reading.name):
                test.assertEqual(program.behaves(), program.prints)


def each_reading_still_prints(
    test: unittest.TestCase,
    rows: Mapping[str, FileProgram],
    readings: tuple[Reading, ...],
):
    for label, row in rows.items():
        for reading in readings:
            program = row.read_as(reading)
            with test.subTest(label=label, reading=reading.name):
                test.assertEqual(program.read(), program.required())


def prints(*lines: str) -> Behavior:
    return (''.join(line + NL for line in lines), None)


def one_expected_failure_per_program(
    rows: Mapping[str, Program],
    marker: Callable[[Callable[..., Any]], Callable[..., Any]],
) -> Callable[[type], type]:
    """
    A class decorator installing two tests for each of *rows*, named after its label: one marked
    with *marker* that asserts the deobfuscation behaves as the row pins, and one that asserts the
    program itself does.
    """
    def install(entry: type) -> type:
        for label, row in rows.items():
            slug = label.replace(' ', '_').replace('-', '_')

            def test(self, row=row):
                self.assertEqual(row.deobfuscated(), row.prints)
            test.__name__ = F'test_{slug}_still_behaves_so'
            if hasattr(entry, test.__name__):
                raise AssertionError(F'{entry.__name__} already holds {test.__name__}')
            setattr(entry, test.__name__, marker(test))

            def anchored(self, row=row):
                self.assertEqual(row.behaves(), row.prints)
            anchored.__name__ = F'test_{slug}_prints_what_is_pinned'
            if hasattr(entry, anchored.__name__):
                raise AssertionError(F'{entry.__name__} already holds {anchored.__name__}')
            setattr(entry, anchored.__name__, anchored)
        return entry
    return install


_Entry = TypeVar('_Entry', bound=Callable[..., Any])


def wontfix(reason: str) -> Callable[[_Entry], _Entry]:
    """
    Skip a test whose defect will not be fixed because only a shape made up for that defect reaches
    it: no obfuscator emits it and no program is written that way. No fix is to be written for it
    and no design decision made on its account.

    *reason* says why no real input reaches the shape; it is printed wherever the test is reported
    as skipped.
    """
    if not reason.strip():
        raise ValueError('an entry is marked as not to be fixed only for a stated reason')
    return unittest.skip(F'will not be fixed: {reason}')
