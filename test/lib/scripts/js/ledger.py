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
from typing import Callable, Iterable, Mapping, NamedTuple

from test.lib.scripts.js.analysis.differential import (
    behavior,
    deobfuscate_source,
    host_behavior,
)

from refinery.lib.scripts import is_well_formed
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer
from refinery.units.scripting.js import js

NL = chr(10)


def a_program(text: str) -> str:
    """
    A program as a file holds it: *text* with the indentation it is written with in the entry that
    holds it stripped, and its last line ending in the break every line of a file ends in.
    """
    return inspect.cleandoc(text) + NL


def well_formed(source: str) -> bool:
    return is_well_formed(JsParser(source).parse())


def dropped_source_characters(source: str, printed: str) -> str:
    """
    The characters of *source* that *printed* does not account for, whitespace aside. Layout is the
    printer's to choose, so only a character that went missing is reported.
    """
    available = Counter(character for character in printed if not character.isspace())
    missing: list[str] = []
    for character in source:
        if character.isspace():
            continue
        if available[character] > 0:
            available[character] -= 1
        else:
            missing.append(character)
    return ''.join(missing)


def each_well_formed(programs: Iterable[str]) -> dict[str, bool]:
    """
    `well_formed` asked of each of *programs*, keyed by the program.
    """
    return {program: well_formed(program) for program in programs}


def printed(source: str) -> str:
    """
    The text `refinery.js` writes for *source* with no pass run over it, which is what the parser
    read spelled back out. An entry about what a file comes back as reads this; one about what a
    program does reads `before_and_after`.
    """
    return JsSynthesizer().convert(JsParser(source).parse())


def folded(source: str, *, module: bool = False) -> str:
    return source.encode('utf8') | js(module=module) | str


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
) -> tuple[tuple[str, str | None], tuple[str, str | None]]:
    """
    What Node makes of *source* and what it makes of the text `refinery.js` deobfuscates it to,
    reported together because the law is that the two agree.

    *module* reads the source as an ECMAScript module rather than as a script, which an entry
    pinning an `import` or `export` declaration has to ask for: no script spells one, and the answer
    such a declaration is wrong in is the linker's rather than the parser's.

    It selects the file the oracle writes and nothing else. Both files the oracle can write are the
    module execution model as
    `refinery.lib.scripts.js.options.DeobfuscationOptions` means it, an ES module and
    a CommonJS file being alike in the one thing that model decides: a top-level declaration is
    scoped to the file and never reaches the global object. So the deobfuscation is always asked
    for under that model, and asking for it under the script model instead would rewrite the source
    for a host the answer is never taken from, which reads as the tool having changed a program it
    only moved.
    """
    return (
        behavior(source, module=module),
        behavior(deobfuscate_source(source, module=True), module=module),
    )


def before_and_after_in_a_host(
    source: str,
) -> tuple[tuple[str, str | None], tuple[str, str | None]]:
    """
    What a host running *source* as a classic global script makes of it, and what it makes of the
    text `refinery.js` writes for it, reported together because the law is that the two agree.

    `before_and_after` reads both under the module execution model, in which a top-level declaration
    is scoped to the file and reaches no global object. A question about what a name reaches through
    `this`, through `globalThis`, or from outside the file is one that model cannot be asked at all,
    and this is the reading that answers it. The deobfuscation here is the one `refinery.js` writes
    by default, the script model, so that the text read is the text an analyst deobfuscating a
    classic script is handed.
    """
    return (host_behavior(source), host_behavior(folded(source)))


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

    The three disagree about one thing, and every entry naming one names it for that reason: what
    a top-level declaration is. Under `MODULE` and `ES_MODULE` it is scoped to the file and reaches
    no global object, so a question about what a name reaches through `this`, through `globalThis`,
    or from outside the file cannot be asked at all. `SCRIPT` is the classic global script, where it
    can. `ES_MODULE` differs from `MODULE` in being strict code with no directive saying so, and in
    being the only one of the three an `import` or `export` declaration may appear in.
    """
    MODULE = auto()
    ES_MODULE = auto()
    SCRIPT = auto()

    def read(self, source: str) -> tuple[Behavior, Behavior]:
        """
        What an engine makes of *source* under this model and what it makes of the text
        `refinery.js` deobfuscates it to, reported together because the law is that the two agree.
        """
        if self is Reading.SCRIPT:
            return before_and_after_in_a_host(source)
        return before_and_after(source, module=self is Reading.ES_MODULE)


class Program(NamedTuple):
    """
    One program a ledger entry pins, the behavior an engine gives it, and the model that reading is
    taken under.

    The behavior is the whole of what the entry has to be told, because the law every entry asserts
    is the same one: the deobfuscation of a program behaves the way the program does. Writing it
    here rather than in the prose of the test that asserts it is what keeps the two from drifting
    apart, since only this one is executed.
    """
    text: str
    prints: Behavior
    reading: Reading = Reading.MODULE

    def read(self) -> tuple[Behavior, Behavior]:
        return self.reading.read(self.text)

    def required(self) -> tuple[Behavior, Behavior]:
        return (self.prints, self.prints)


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
    a program behaves the way the program does.
    """
    def install(entry: type) -> type:
        for label, row in rows.items():
            def test(self, row=row):
                self.assertEqual(row.read(), row.required())
            test.__name__ = F'test_{label.replace(" ", "_").replace("-", "_")}_still_behaves_so'
            if hasattr(entry, test.__name__):
                raise AssertionError(F'{entry.__name__} already holds {test.__name__}')
            setattr(entry, test.__name__, unittest.expectedFailure(test))
        return entry
    return install
