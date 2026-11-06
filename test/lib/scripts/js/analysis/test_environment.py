from __future__ import annotations

import inspect
import json
import unittest

from test import TestBase, backlog
from test.lib.scripts.js.analysis.differential import behavior, node_executable

from refinery.lib.scripts.js.analysis.environment import (
    _NODE_ABSENT,
    _SPECS,
    GUARANTEED_GLOBALS,
    NODE_BUILTIN_MODULES,
    HostEnvironment,
    Presence,
    node_require_runs_no_code,
    typeof_of_global,
)
from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.model import JsIdentifier
from refinery.lib.scripts.js.parser import JsParser

_HOST_CONDITIONAL_ALIASES = ('window', 'self', 'top', 'frames', 'global')

_LANGUAGE_CONSTANTS = frozenset({'NaN', 'Infinity', 'undefined'})

_A_READOUT_OF_THE_GLOBAL_OBJECT = inspect.cleandoc("""
    const describe = Object.getOwnPropertyDescriptor;
    const print = console.log.bind(console);
    const kinds = {};
    for (const k of Object.getOwnPropertyNames(globalThis).sort()) {
      const d = describe(globalThis, k);
      kinds[k] = 'value' in d ? (d.writable ? 'value' : 'constant') : (d.set ? 'setter' : 'getter');
    }
    for (const k of Object.keys(kinds)) {
      if (kinds[k] !== 'setter') continue;
      let outcome = 'stored';
      for (const v of [null, {}]) {
        try {
          globalThis[k] = v;
        } catch (e) {
          outcome = 'threw';
          break;
        }
        if (globalThis[k] !== v) outcome = 'own';
      }
      kinds[k] = 'setter:' + outcome;
    }
    print(JSON.stringify(kinds));
    """)

_A_READOUT_OF_WHAT_THE_GLOBAL_OBJECT_INHERITS = inspect.cleandoc("""
    const describe = Object.getOwnPropertyDescriptor;
    const print = console.log.bind(console);
    const kinds = Object.create(null);
    for (let p = Object.getPrototypeOf(globalThis); p !== null && p !== Object.prototype; p = Object.getPrototypeOf(p)) {
      for (const k of Object.getOwnPropertyNames(p).sort()) {
        if (Object.prototype.hasOwnProperty.call(globalThis, k) || k in kinds) continue;
        const d = describe(p, k);
        kinds[k] = 'value' in d ? (d.writable ? 'value' : 'constant') : (d.set ? 'setter' : 'getter');
      }
    }
    print(JSON.stringify(kinds));
    """)


def _bare_read_may_throw(source: str, name: str, environment: HostEnvironment) -> bool:
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

    def test_a_language_constant_is_never_withheld_on_delete(self):
        for environment in HostEnvironment:
            for name in _LANGUAGE_CONSTANTS:
                with self.subTest(environment=environment.name, name=name):
                    self.assertFalse(environment.withholds_on_delete(name))

    @backlog
    def test_a_delete_withholds_every_language_mandated_name_that_is_not_a_constant(self):
        for environment in HostEnvironment:
            for name in GUARANTEED_GLOBALS - _LANGUAGE_CONSTANTS:
                with self.subTest(environment=environment.name, name=name):
                    self.assertTrue(environment.withholds_on_delete(name))


class TestTheUniversalHostCallsEveryHandlerAPinnedHostCalls(TestBase):

    def test_every_handler_a_pinned_host_calls_is_called_without_a_pin(self):
        for environment in HostEnvironment:
            for name in _SPECS[environment].handlers:
                with self.subTest(environment=environment.name, name=name):
                    self.assertTrue(HostEnvironment.universal.calls_handler(name))

    def test_every_stored_value_a_pinned_host_reads_is_read_without_a_pin(self):
        for environment in HostEnvironment:
            for name in _SPECS[environment].read_on_store:
                with self.subTest(environment=environment.name, name=name):
                    self.assertTrue(HostEnvironment.universal.reads_stored_value(name))


class TestAHostReadsTheValueStoredWhereItCallsAHandler(TestBase):

    def test_every_handler_a_host_calls_is_a_property_whose_stored_value_it_reads(self):
        for environment in HostEnvironment:
            for name in _SPECS[environment].handlers:
                with self.subTest(environment=environment.name, name=name):
                    self.assertTrue(environment.reads_stored_value(name))


class TestAHostHoldsEveryPropertyItHasAPartIn(TestBase):

    def test_every_property_whose_stored_value_a_window_reads_is_one_it_holds(self):
        spec = _SPECS[HostEnvironment.browser]
        for name in spec.handlers | spec.read_on_store:
            with self.subTest(name=name):
                self.assertTrue(HostEnvironment.browser.holds(name))

    def test_every_property_a_pinned_host_holds_is_held_without_a_pin(self):
        for environment in HostEnvironment:
            for name in _SPECS[environment].global_objects.held:
                with self.subTest(environment=environment.name, name=name):
                    self.assertTrue(HostEnvironment.universal.holds(name))
                    if environment.keeps_its_own_value(name):
                        self.assertTrue(HostEnvironment.universal.keeps_its_own_value(name))

    def test_every_host_keeps_its_own_value_in_the_constants_of_the_language(self):
        for environment in HostEnvironment:
            for name in ('NaN', 'Infinity', 'undefined'):
                with self.subTest(environment=environment.name, name=name):
                    self.assertTrue(environment.keeps_its_own_value(name))

    def test_a_property_no_host_holds_keeps_no_value_of_its_own(self):
        for environment in HostEnvironment:
            with self.subTest(environment=environment.name):
                self.assertFalse(environment.holds('zzz'))
                self.assertFalse(environment.keeps_its_own_value('zzz'))
                self.assertFalse(environment.inherits_a_property_keeping_its_own_value('zzz'))


class TestAHostInheritsPropertiesItsGlobalObjectDoesNotHold(TestBase):
    """
    A dedicated worker inherits `self`, a getter without a setter, from the prototype of its global
    object, and a window inherits the constant `TEMPORARY`; a store into either name keeps nothing.
    """

    def test_a_worker_inherits_its_self_keeping_a_value_of_its_own(self):
        self.assertFalse(HostEnvironment.worker.holds('self'))
        self.assertTrue(HostEnvironment.worker.inherits_a_property_keeping_its_own_value('self'))

    def test_a_window_inherits_temporary_keeping_a_value_of_its_own(self):
        self.assertFalse(HostEnvironment.browser.holds('TEMPORARY'))
        self.assertTrue(HostEnvironment.browser.inherits_a_property_keeping_its_own_value('TEMPORARY'))

    def test_a_writable_value_a_host_inherits_takes_a_store(self):
        self.assertFalse(HostEnvironment.browser.inherits_a_property_keeping_its_own_value('addEventListener'))
        self.assertTrue(HostEnvironment.browser.has_a_global('addEventListener'))

    def test_every_property_a_pinned_host_inherits_keeping_its_own_value_is_inherited_without_a_pin(self):
        for environment in HostEnvironment:
            for name in _SPECS[environment].global_objects.inherited_keeping_their_own_value:
                with self.subTest(environment=environment.name, name=name):
                    self.assertTrue(HostEnvironment.universal.inherits_a_property_keeping_its_own_value(name))


class TestAGlobalIsANameSomeHostHasAPropertyUnder(TestBase):

    def test_every_name_a_host_provides_or_holds_is_a_global_of_it(self):
        for environment in HostEnvironment:
            spec = _SPECS[environment]
            for name in spec.provided | spec.global_objects.held:
                with self.subTest(environment=environment.name, name=name):
                    self.assertTrue(environment.has_a_global(name))

    def test_every_global_of_a_pinned_host_is_a_global_without_a_pin(self):
        for environment in HostEnvironment:
            for name in _SPECS[environment].global_objects.named:
                with self.subTest(environment=environment.name, name=name):
                    self.assertTrue(HostEnvironment.universal.has_a_global(name))

    def test_what_every_object_inherits_is_a_global_of_every_host(self):
        for environment in HostEnvironment:
            for name in ('toString', 'hasOwnProperty', 'constructor', '__proto__'):
                with self.subTest(environment=environment.name, name=name):
                    self.assertTrue(environment.has_a_global(name))

    def test_a_name_only_a_browser_has_is_no_global_of_node(self):
        self.assertTrue(HostEnvironment.browser.has_a_global('document'))
        self.assertFalse(HostEnvironment.node.has_a_global('document'))

    def test_a_name_no_host_has_is_no_global(self):
        for environment in HostEnvironment:
            with self.subTest(environment=environment.name):
                self.assertFalse(environment.has_a_global('zzz'))


class TestABareGlobalReadIsJudgedAgainstThePinnedHost(TestBase):

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


class TestPresenceIsThreeValued(TestBase):

    def test_presence_present_agrees_with_provides(self):
        for environment in HostEnvironment:
            for name in ('String', 'Buffer', 'window', 'global', 'zzz'):
                with self.subTest(environment=environment.name, name=name):
                    self.assertEqual(
                        environment.presence(name) is Presence.PRESENT,
                        environment.provides(name),
                    )

    def test_present_and_absent_are_disjoint(self):
        for environment in HostEnvironment:
            spec = _SPECS[environment]
            with self.subTest(environment=environment.name):
                self.assertEqual(spec.provided & spec.absent, frozenset())

    def test_the_universal_host_is_certain_of_no_absence(self):
        for name in ('Buffer', 'window', 'global', 'process', 'require', 'self'):
            with self.subTest(name=name):
                self.assertIs(HostEnvironment.universal.presence(name), Presence.UNKNOWN)

    def test_node_provides_navigator_and_never_calls_it_absent(self):
        self.assertTrue(HostEnvironment.node.provides('navigator'))
        self.assertIs(HostEnvironment.node.presence('navigator'), Presence.PRESENT)

    def test_a_dedicated_worker_does_not_call_request_animation_frame_absent(self):
        """
        A dedicated worker has `requestAnimationFrame`, as a window does.
        """
        self.assertIsNot(HostEnvironment.worker.presence('requestAnimationFrame'), Presence.ABSENT)
        self.assertIsNone(typeof_of_global('requestAnimationFrame', HostEnvironment.worker))


class TestTypeofFoldsOnlyWhereTheHostSettlesIt(TestBase):

    def test_a_universal_typeof_folds_in_every_host(self):
        for environment in HostEnvironment:
            with self.subTest(environment=environment.name):
                self.assertEqual(typeof_of_global('String', environment), 'function')
                self.assertEqual(typeof_of_global('Math', environment), 'object')
                self.assertEqual(typeof_of_global('escape', environment), 'function')

    def test_a_host_conditional_typeof_abstains_without_a_pin(self):
        for name in ('Buffer', 'console', 'setTimeout', 'atob', 'window', 'process'):
            with self.subTest(name=name):
                self.assertIsNone(typeof_of_global(name, HostEnvironment.universal))

    def test_a_present_host_conditional_typeof_folds_to_its_type(self):
        self.assertEqual(typeof_of_global('Buffer', HostEnvironment.node), 'function')
        self.assertEqual(typeof_of_global('process', HostEnvironment.node), 'object')
        self.assertEqual(typeof_of_global('window', HostEnvironment.browser), 'object')

    def test_an_absent_host_conditional_typeof_folds_to_undefined(self):
        self.assertEqual(typeof_of_global('Buffer', HostEnvironment.browser), 'undefined')
        self.assertEqual(typeof_of_global('window', HostEnvironment.node), 'undefined')
        self.assertEqual(typeof_of_global('global', HostEnvironment.browser), 'undefined')

    def test_what_a_page_gets_from_a_library_it_loads_is_absent_under_node_only(self):
        for name in ('define', 'angular'):
            with self.subTest(name=name):
                self.assertEqual(typeof_of_global(name, HostEnvironment.node), 'undefined')
                self.assertIsNone(typeof_of_global(name, HostEnvironment.browser))
                self.assertIsNone(typeof_of_global(name, HostEnvironment.universal))

    def test_every_provided_host_conditional_name_has_a_typeof(self):
        for environment in HostEnvironment:
            for name in _SPECS[environment].provided - GUARANTEED_GLOBALS:
                with self.subTest(environment=environment.name, name=name):
                    self.assertIsNotNone(typeof_of_global(name, environment))


class TestDeletingAHostGlobalWithholdsItsPinnedPresence(TestBase):
    """
    A host-conditional global is a deletable property of the global object, and so is every
    language-mandated one except the constants `NaN`, `Infinity` and `undefined`; a bare read of a
    deleted name throws.
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

    def test_deleting_a_language_constant_withholds_nothing(self):
        source = 'delete globalThis.NaN; NaN;'
        self.assertFalse(_bare_read_may_throw(source, 'NaN', HostEnvironment.node))

    @backlog
    def test_deleting_a_language_mandated_name_that_is_not_a_constant_withholds_it(self):
        source = 'delete globalThis.String; String;'
        self.assertTrue(_bare_read_may_throw(source, 'String', HostEnvironment.node))

    def test_a_delete_off_a_shadowed_alias_withholds_nothing(self):
        source = 'var globalThis = 0; delete globalThis.Buffer; Buffer;'
        self.assertFalse(_bare_read_may_throw(source, 'Buffer', HostEnvironment.node))


class TestARequireOfABuiltinModuleRunsNoCode(TestBase):

    def test_a_builtin_module_runs_no_code_with_or_without_the_prefix(self):
        for specifier in ('fs', 'node:fs', 'fs/promises', 'node:fs/promises', 'child_process', 'node:http2'):
            with self.subTest(specifier=specifier):
                self.assertTrue(node_require_runs_no_code(specifier))

    def test_a_module_node_loads_only_under_its_prefix_runs_no_code_under_it(self):
        for specifier in ('node:test', 'node:sea', 'node:sqlite'):
            with self.subTest(specifier=specifier):
                self.assertTrue(node_require_runs_no_code(specifier))

    def test_without_its_prefix_such_a_name_is_a_package(self):
        for specifier in ('test', 'sea', 'sqlite'):
            with self.subTest(specifier=specifier):
                self.assertFalse(node_require_runs_no_code(specifier))

    def test_a_builtin_module_that_runs_source_text_runs_code(self):
        for specifier in ('vm', 'node:vm', 'module', 'repl', 'inspector', 'node:inspector/promises'):
            with self.subTest(specifier=specifier):
                self.assertFalse(node_require_runs_no_code(specifier))

    def test_a_file_or_a_package_runs_code(self):
        for specifier in ('./setup.js', '../package', '/abs/path.js', 'lodash', 'node:lodash'):
            with self.subTest(specifier=specifier):
                self.assertFalse(node_require_runs_no_code(specifier))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodeAgreesWithTheEnvironment(TestBase):

    def test_the_builtin_modules_are_the_ones_node_lists(self):
        out, error = behavior('console.log(JSON.stringify(require("module").builtinModules));')
        self.assertIsNone(error)
        self.assertEqual(set(json.loads(out)), NODE_BUILTIN_MODULES)

    def test_every_name_absent_under_node_has_type_undefined_there(self):
        names = sorted(_NODE_ABSENT)
        out, error = behavior('console.log(JSON.stringify([' + ', '.join(F'typeof {name}' for name in names) + ']));')
        self.assertIsNone(error)
        self.assertEqual(dict(zip(names, json.loads(out))), {name: 'undefined' for name in names})

    def test_node_defines_no_property_whose_stored_value_another_host_reads(self):
        names = sorted(_SPECS[HostEnvironment.universal].read_on_store)
        out, error = behavior(F'console.log(JSON.stringify({json.dumps(names)}.filter(name => name in globalThis)));')
        self.assertIsNone(error)
        self.assertEqual(json.loads(out), [])

    def test_node_defines_no_handler_another_host_calls(self):
        names = sorted(_SPECS[HostEnvironment.universal].handlers)
        out, error = behavior(F'console.log(JSON.stringify({json.dumps(names)}.filter(name => name in globalThis)));')
        self.assertIsNone(error)
        self.assertEqual(json.loads(out), [])

    def test_node_holds_no_property_the_environment_does_not_know(self):
        out, error = behavior(_A_READOUT_OF_THE_GLOBAL_OBJECT)
        self.assertIsNone(error)
        kinds: dict[str, str] = json.loads(out)
        unknown = [name for name in kinds if not HostEnvironment.node.holds(name)]
        keeping_their_own_value_unknown = [
            name
            for name, kind in kinds.items()
            if kind not in ('value', 'setter:stored')
            and not HostEnvironment.node.keeps_its_own_value(name)
        ]
        self.assertEqual(unknown, [])
        self.assertEqual(keeping_their_own_value_unknown, [])

    def test_node_inherits_no_property_the_environment_does_not_know(self):
        out, error = behavior(_A_READOUT_OF_WHAT_THE_GLOBAL_OBJECT_INHERITS)
        self.assertIsNone(error)
        kinds: dict[str, str] = json.loads(out)
        unknown = [name for name in kinds if not HostEnvironment.node.has_a_global(name)]
        keeping_their_own_value_unknown = [
            name
            for name, kind in kinds.items()
            if kind != 'value'
            and not HostEnvironment.node.inherits_a_property_keeping_its_own_value(name)
        ]
        self.assertEqual(unknown, [])
        self.assertEqual(keeping_their_own_value_unknown, [])
