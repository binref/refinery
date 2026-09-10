from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.analysis.environment import (
    GUARANTEED_GLOBALS,
    HostEnvironment,
)
from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.model import JsIdentifier
from refinery.lib.scripts.js.parser import JsParser

_HOST_CONDITIONAL_ALIASES = ('window', 'self', 'top', 'frames', 'global')


def _bare_read_may_throw(source: str, name: str, environment: HostEnvironment) -> bool:
    """
    Whether the model, pinned to *environment*, answers that the one bare read of *name* in *source*
    may throw a `ReferenceError`. The name is expected to occur exactly once as a reference, so that a
    program deleting the name off the global object can spell it in the delete's member position
    without that key counting as a read.
    """
    ast = JsParser(source).parse()
    model = build_semantic_model(ast, environment)
    reads = [
        model.read_may_throw(node)
        for node in ast.walk_in_order()
        if isinstance(node, JsIdentifier) and node.name == name and model.is_reference(node)
    ]
    if len(reads) != 1:
        raise AssertionError(F'expected one read of {name!r}, found {len(reads)}')
    return reads[0]


class TestTheUniversalEnvironmentIsTheLanguageFloor(TestBase):
    """
    The default `universal` environment asserts exactly the globals the ECMAScript specification
    mandates, so an unpinned deobfuscation is judged as it always was. A pinned host only ever adds
    names, never removes one the language guarantees.
    """

    def test_universal_provides_every_guaranteed_global(self):
        for name in GUARANTEED_GLOBALS:
            with self.subTest(name=name):
                self.assertTrue(HostEnvironment.universal.provides(name))

    def test_universal_provides_no_host_conditional_alias(self):
        for name in _HOST_CONDITIONAL_ALIASES:
            with self.subTest(name=name):
                self.assertFalse(HostEnvironment.universal.provides(name))

    def test_every_host_keeps_the_whole_language_floor(self):
        for environment in HostEnvironment:
            for name in GUARANTEED_GLOBALS:
                with self.subTest(environment=environment.name, name=name):
                    self.assertTrue(environment.provides(name))

    def test_a_language_mandated_name_is_never_withheld_on_delete(self):
        for environment in HostEnvironment:
            for name in GUARANTEED_GLOBALS:
                with self.subTest(environment=environment.name, name=name):
                    self.assertFalse(environment.withholds_on_delete(name))


class TestABareGlobalReadIsJudgedAgainstThePinnedHost(TestBase):
    """
    A bare read of a name the program never declares reaches the host's global object, and whether it
    resolves or raises a `ReferenceError` is the host's fact: `global` exists under Node and not in a
    browser, `window` and `self` the other way around, and `self` is a worker's own global alias while
    `window` is not. The default `universal` environment resolves neither, so both are kept.
    """

    def test_node_resolves_its_own_alias_and_still_throws_a_browser_alias(self):
        self.assertFalse(_bare_read_may_throw('global;', 'global', HostEnvironment.node))
        self.assertTrue(_bare_read_may_throw('window;', 'window', HostEnvironment.node))

    def test_a_browser_resolves_window_and_still_throws_the_node_alias(self):
        self.assertFalse(_bare_read_may_throw('window;', 'window', HostEnvironment.browser))
        self.assertTrue(_bare_read_may_throw('global;', 'global', HostEnvironment.browser))

    def test_a_worker_resolves_self_but_not_window(self):
        self.assertFalse(_bare_read_may_throw('self;', 'self', HostEnvironment.worker))
        self.assertTrue(_bare_read_may_throw('window;', 'window', HostEnvironment.worker))

    def test_the_default_environment_keeps_every_host_conditional_alias(self):
        for name in _HOST_CONDITIONAL_ALIASES:
            with self.subTest(name=name):
                self.assertTrue(_bare_read_may_throw(F'{name};', name, HostEnvironment.universal))


class TestDeletingAHostGlobalWithholdsItsPinnedPresence(TestBase):
    """
    A host-conditional global is a deletable property of the global object, so a program that deletes
    one off a global-object alias makes a later bare read of it throw. The pin withholds the name's
    presence program-wide once such a delete appears, keeping the read's throw rather than dropping it;
    a language-mandated name is never withheld, and a delete off a shadowed alias — a local of the same
    name — deletes nothing off the global object and so withholds nothing.
    """

    def test_a_bare_read_resolves_when_the_host_defines_the_name(self):
        self.assertFalse(_bare_read_may_throw('Buffer;', 'Buffer', HostEnvironment.node))

    def test_deleting_the_name_off_the_global_object_withholds_it(self):
        source = 'delete globalThis.Buffer; Buffer;'
        self.assertTrue(_bare_read_may_throw(source, 'Buffer', HostEnvironment.node))

    def test_a_computed_delete_key_withholds_the_name_it_spells(self):
        source = "delete globalThis['Buffer']; Buffer;"
        self.assertTrue(_bare_read_may_throw(source, 'Buffer', HostEnvironment.node))

    def test_a_delete_through_a_cross_realm_alias_withholds_conservatively(self):
        source = 'delete top.Buffer; Buffer;'
        self.assertTrue(_bare_read_may_throw(source, 'Buffer', HostEnvironment.node))

    def test_deleting_a_language_mandated_name_withholds_nothing(self):
        source = 'delete globalThis.String; String;'
        self.assertFalse(_bare_read_may_throw(source, 'String', HostEnvironment.node))

    def test_a_delete_off_a_shadowed_alias_withholds_nothing(self):
        source = 'var globalThis = 0; delete globalThis.Buffer; Buffer;'
        self.assertFalse(_bare_read_may_throw(source, 'Buffer', HostEnvironment.node))
