"""
The instruments the two JavaScript defect ledgers are written with.

`test.lib.scripts.js.test_release_blockers` holds the defects a release is held for and
`test.lib.scripts.js.test_unfixed_defects` holds the rest, so an entry moves from one file to the
other when what it costs is reassessed rather than when it is understood differently. Both are
written against the same few questions, which live here so that neither file can answer one of them
its own way and read as disagreeing with the other about a defect they both pin.

Nothing here executes anything from the sample corpus: `before_and_after` runs Node, and every
program it is ever given is one an entry wrote out by hand.
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
    """
    A program as a file holds it: *text* with the indentation it is written with in the entry that
    holds it stripped, and its last line ending in the break every line of a file ends in.
    """
    return inspect.cleandoc(text) + NL


def well_formed(source: str) -> bool:
    return is_well_formed(JsParser(source).parse())


class _Spelled(NamedTuple):
    """
    One thing a file spells that this oracle can see: a single character of code, or the whole text
    of one comment. Whitespace is none of them, layout being the printer's to choose.
    """
    text: str
    is_comment: bool


def _without_whitespace(text: str) -> str:
    return ''.join(character for character in text if not character.isspace())


def _spelled_in(text: str) -> Iterator[_Spelled]:
    """
    Every character of code and every comment *text* spells, in the order it writes them.

    The comments are the ones `refinery.lib.scripts.js.lexer.JsLexer` reads rather than every run
    of characters between a pair of delimiters, since a delimiter standing inside a string or a
    template opens no comment and its characters are code.
    """
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
    The characters of *source* that *printed* does not account for, whitespace aside, in the order
    *source* writes them; the empty string where every one of them is accounted for.

    Code and comments are asked for separately, because the printer may move a comment and may not
    move code. Each character of code has to stand in *printed* in the order *source* wrote it, and
    each comment *source* holds has to be one *printed* holds too, wherever in the file it now
    stands. A comment *printed* does not hold as a comment is looked for as code where it stands.
    A file spelling `x = / /* c` needs that: the `/*` in it stands inside a regular expression and
    opens no comment, and only a text that writes those two characters together reads as though it
    did.

    So the layout the printer chooses is accepted, and so is a comment moved to a statement
    boundary. A character of code that went missing is reported, so is one that came back in
    another place, and so is a comment that went missing.
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
    """
    The text `refinery.djs` writes for *source* with no pass run over it, which is what the parser
    read spelled back out. An entry about what a file comes back as reads this; one about what a
    program does reads `before_and_after`.
    """
    return JsSynthesizer().convert(JsParser(source).parse())


def folded(
    source: str,
    *,
    module: bool = False,
    environment: HostEnvironment = HostEnvironment.universal,
) -> str:
    """
    The text `refinery.djs` writes for *source* under the strict model, which is the one whose
    output is semantically equivalent to its input — the claim every entry reading this makes. The
    unit's own default is the trusting model, which folds more and guarantees nothing; a test of
    that model asks for it by name. *environment* is the host the unit is told the script runs in.
    """
    return source.encode('utf8') | djs(module=module, strict=True, environment=environment.name) | str


def evaluated_in_a_body(receiver: str, read: str, installs: str = '') -> str:
    """
    A script that runs *installs*, then prints what *read* answers for a local holding *receiver*.

    The local inside a function is what puts the read where the tool answers it at all. Written at
    the top of the file the same read is left standing, so a program that only writes it there
    reports nothing about how it would have been answered.
    """
    body = F'function f() {{ var v = {receiver}; return {read}; }}\nconsole.log(f());\n'
    return F'{installs}\n{body}' if installs else body


def returned_from_a_body(body: str) -> str:
    """
    A script whose one function runs *body* and prints what it returned.

    A question asked inside a function is what puts it where the tool answers it at all, for the
    reason `evaluated_in_a_body` gives. The body is written out whole here, which a receiver built
    by statements rather than by one literal needs.
    """
    return F'function f() {{ {body} }}\nconsole.log(f());\n'


def a_walk_of(receiver: str, installs: str = '') -> str:
    """
    A script that runs *installs* and then prints the names a `for-in` over *receiver* reaches, in
    the order it reaches them. The walk is written inside a function body, which is what puts it
    where the tool answers it at all: the same loop at the top level is left standing.

    The names are joined by appending to a string rather than through `Array.prototype.join`, so
    that a row installing something on `Array.prototype` asks only about the walk. Called through
    `join`, such a row comes back unreduced because the call cannot fold, and would report the walk
    as refused wherever it was in fact answered.
    """
    walk = F"var t = ''; for (var k in {receiver}) t += k; return t;"
    body = returned_from_a_body(walk)
    return F'{installs}\n{body}' if installs else body


def an_accessor_at(prototype: str, key: str) -> str:
    """
    A statement installing a getter at *key* on *prototype* that answers `'G'`. A read the prototype
    chain decides is not merely a read of some other value: where the chain holds an accessor, the
    read runs the program's own code, and answering it off the receiver drops that code unrun.
    """
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
    What Node makes of *source* and what it makes of the text `refinery.djs` deobfuscates it to,
    reported together because the law is that the two agree. The deobfuscation assumes the host
    *environment*, which Node is unless it is the browser.

    *module* reads the source as an ECMAScript module rather than as a script, which an entry
    pinning an `import` or `export` declaration has to ask for: no script spells one, and the answer
    such a declaration is wrong in is the linker's rather than the parser's.

    It selects the file the oracle writes and nothing else. The deobfuscation is asked for under
    *execution*, by default `refinery.lib.scripts.js.options.ExecutionModel.module`, which holds for
    an ES module and a CommonJS file alike, so either file the oracle can write runs a text written
    for it. `ExecutionModel.commonjs` asks what the tool does knowing the file is a CommonJS file,
    sloppy code where it says nothing. Asking for it under the script model instead would rewrite
    the source for a host the answer is never taken from, which reads as the tool having changed a
    program it only moved.
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
    """
    What Node makes of the text `refinery.djs` deobfuscates *source* to: the second half of what
    `before_and_after` reports, without running *source* itself.
    """
    return behavior(deobfuscate_source(source, execution=execution, environment=environment), module=module)


def before_and_after_in_a_host(
    source: str,
    environment: HostEnvironment = HostEnvironment.universal,
) -> tuple[tuple[str, str | None], tuple[str, str | None]]:
    """
    What a host running *source* as a classic global script makes of it, and what it makes of the
    text `refinery.djs` writes for it, reported together because the law is that the two agree.

    `before_and_after` reads both under the module execution model, in which a top-level declaration
    is scoped to the file and reaches no global object. A question about what a name reaches through
    `this`, through `globalThis`, or from outside the file is one that model cannot be asked at all,
    and this is the reading that answers it. The deobfuscation here is the strict one
    `refinery.djs` writes under `-s`, the only model whose output is equivalent to its input; the
    unit's own default is the trusting model, which folds more and guarantees nothing.
    """
    return (host_behavior(source), deobfuscated_host_behavior(source, environment))


def deobfuscated_host_behavior(
    source: str,
    environment: HostEnvironment = HostEnvironment.universal,
) -> Behavior:
    """
    What a host running a classic global script makes of the text `refinery.djs` writes for
    *source*: the second half of what `before_and_after_in_a_host` reports, without running *source*
    itself.
    """
    return host_behavior(folded(source, environment=environment))


def each_program_still_prints(
    programs: dict[str, str],
) -> dict[str, tuple[tuple[str, str | None], tuple[str, str | None]]]:
    """
    The pair `before_and_after` has to give for each program in *programs*: the text the program
    prints, printed by the deobfuscation too, with neither of the two throwing.
    """
    return {
        source: ((prints, None), (prints, None))
        for source, prints in programs.items()
    }


#: What an engine made of a program: everything it wrote to standard output, and the type of the
#: error that ended it where one did.
Behavior = tuple[str, str | None]


class Reading(Enum):
    """
    The execution model a program is read under, which is also the model the deobfuscation it is
    compared against is written for.

    They disagree about two things, and every entry naming one names it for one of them. The first
    is what a top-level declaration is. Under `MODULE`, `COMMONJS` and `ES_MODULE` it is scoped to
    the file and reaches no global object, so a question about what a name reaches through `this`,
    through `globalThis`, or from outside the file cannot be asked at all. `SCRIPT` is the classic
    global script, where it can. The second is whether code is strict where it says nothing.
    `ES_MODULE` is strict code with no directive saying so, and the only reading an `import` or
    `export` declaration may appear in. `MODULE` runs the program as a CommonJS file but has it
    deobfuscated for a module of either kind, a text that must hold for the strict reading too;
    `COMMONJS` runs it as a CommonJS file and tells the deobfuscation so.
    """
    MODULE = auto()
    COMMONJS = auto()
    ES_MODULE = auto()
    SCRIPT = auto()

    def read(
        self,
        source: str,
        environment: HostEnvironment = HostEnvironment.universal,
    ) -> tuple[Behavior, Behavior]:
        """
        What an engine makes of *source* under this model and what it makes of the text
        `refinery.djs` deobfuscates it to for the host *environment*, reported together because the
        law is that the two agree.
        """
        return (self.behaves(source), self.deobfuscated(source, environment))

    def behaves(self, source: str) -> Behavior:
        """
        What an engine makes of *source* alone under this model — the first half of what `read`
        returns, computed without deobfuscating. It is the engine-anchor for a pinned behavior: a
        program's own behavior is a fact about the program and not about the tool, so a ledger entry
        that misstates it is wrong however the tool behaves, and asserting it outside expected
        failure is what turns that mistake into a failure rather than one more tracked divergence.
        """
        if self is Reading.SCRIPT:
            return host_behavior(source)
        return behavior(source, module=self is Reading.ES_MODULE)

    def deobfuscated(
        self,
        source: str,
        environment: HostEnvironment = HostEnvironment.universal,
    ) -> Behavior:
        """
        What an engine makes under this model of the text `refinery.djs` deobfuscates *source* to
        for the host *environment* — the second half of what `read` returns, computed without
        running *source* itself.
        """
        if self is Reading.SCRIPT:
            return deobfuscated_host_behavior(source, environment)
        if self is Reading.COMMONJS:
            return deobfuscated_behavior(source, execution=ExecutionModel.commonjs, environment=environment)
        return deobfuscated_behavior(source, module=self is Reading.ES_MODULE, environment=environment)


class Program(NamedTuple):
    """
    One program a ledger entry pins, the behavior an engine gives it, and the model that reading is
    taken under.

    The behavior is the whole of what the entry has to be told, because the law every entry asserts
    is the same one: the deobfuscation of a program behaves the way the program does. Writing it
    here rather than in the prose of the test that asserts it is what keeps the two from drifting
    apart, since only this one is executed. The deobfuscation is asked for under the host
    *environment*.
    """
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
    """
    A program Node runs as a file, with what it makes of it run as a CommonJS file and run as an ES
    module. `read_as` gives the `Program` of one reading: `Reading.ES_MODULE` runs the file as an ES
    module, and every other reading runs it as a CommonJS file. The deobfuscation is asked for under
    the host *environment*.
    """
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
    *rows* read as classic global scripts, for programs a host runs the way Node runs them as a
    CommonJS file: sloppy code that reads no name the CommonJS wrapper binds and no top-level
    `this`.
    """
    return {
        label: Program(row.text, row.as_commonjs, Reading.SCRIPT, row.environment) for label, row in rows.items()
    }


def node_prints_what_each_row_pins(test: unittest.TestCase, rows: Mapping[str, FileProgram]):
    """
    Assert that Node prints, for each of *rows* run as a CommonJS file and run as an ES module, what
    the row pins: the anchor that makes a misstated row a failure rather than a divergence.
    """
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
    """
    Assert that the deobfuscation of each of *rows* under each of *readings* behaves the way the
    program does.
    """
    for label, row in rows.items():
        for reading in readings:
            program = row.read_as(reading)
            with test.subTest(label=label, reading=reading.name):
                test.assertEqual(program.read(), program.required())


def prints(*lines: str) -> Behavior:
    """
    The behavior of a program that writes *lines* and ends without an error, each line ending in the
    break `console.log` adds.
    """
    return (''.join(line + NL for line in lines), None)


def one_expected_failure_per_program(
    rows: Mapping[str, Program],
) -> Callable[[type], type]:
    """
    Install on the class one expected-failure test per program of *rows*, each named for the shape
    its key labels and each asserting the one law every ledger entry asserts: the deobfuscation of
    a program behaves the way the program does. Next to it goes a test that the program itself
    behaves as pinned, so the expected failure runs only the deobfuscation.
    """
    def install(entry: type) -> type:
        for label, row in rows.items():
            slug = label.replace(' ', '_').replace('-', '_')

            def test(self, row=row):
                self.assertEqual(row.deobfuscated(), row.prints)
            test.__name__ = F'test_{slug}_still_behaves_so'
            if hasattr(entry, test.__name__):
                raise AssertionError(F'{entry.__name__} already holds {test.__name__}')
            setattr(entry, test.__name__, unittest.expectedFailure(test))

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
    Mark a ledger entry whose defect will not be fixed. The entry pins a real defect, but only a
    shape made up for that defect reaches it: no obfuscator emits it and no program is written
    that way. Fixing it would spend development time on a bug no input holds and could bend the
    design around it, so the entry is kept only to acknowledge that the defect exists. It never
    runs, no fix is to be written for it, and no design decision is to be made on its account.
    *reason* says why no real input reaches the shape; it is printed wherever the entry is reported
    as skipped.
    """
    if not reason.strip():
        raise ValueError('an entry is marked as not to be fixed only for a stated reason')
    return unittest.skip(F'will not be fixed: {reason}')
