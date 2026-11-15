from __future__ import annotations

import inspect

from test import TestBase

from refinery.lib.scripts.ps1.analysis.callgraph import build_call_graph
from refinery.lib.scripts.ps1.analysis.world import Ps1TypeWorld, build_closed_world
from refinery.lib.scripts.ps1.options import Ps1DeobfuscationOptions
from refinery.lib.scripts.ps1.parser import Ps1Parser

_CLOSED_WORLD = Ps1TypeWorld(True, frozenset())


class TestPs1CallGraphReadability(TestBase):

    @staticmethod
    def _graph(source: str):
        return build_call_graph(Ps1Parser(source).parse(), _CLOSED_WORLD)

    def test_a_script_whose_calls_and_definitions_meet_is_readable(self):
        self.assertTrue(self._graph(inspect.cleandoc("""
            function Qzmr { 'P' }
            Qzmr
        """)).is_readable)

    def test_a_module_qualified_call_onto_a_defined_name_is_not(self):
        self.assertFalse(self._graph(inspect.cleandoc("""
            function Qzmr { 'P' }
            & 'MyModule\\Qzmr'
        """)).is_readable)

    def test_the_bare_spelling_of_that_call_is_not_either(self):
        self.assertFalse(self._graph(inspect.cleandoc("""
            function Qzmr { 'P' }
            & MyModule\\Qzmr
        """)).is_readable)

    def test_the_definition_may_be_written_below_the_call(self):
        self.assertFalse(self._graph(inspect.cleandoc("""
            & 'MyModule\\Qzmr'
            function Qzmr { 'P' }
        """)).is_readable)

    def test_an_aliased_call_onto_a_defined_name_is_not_readable(self):
        self.assertFalse(
            self._graph(inspect.cleandoc("""
                function Invoke-Expression { 'P' }
                iex 'x'
            """)).is_readable)

    def test_a_scope_qualified_call_is_readable_because_the_key_already_matches(self):
        self.assertTrue(self._graph(inspect.cleandoc("""
            function Qzmr { 'P' }
            & 'global:Qzmr'
        """)).is_readable)

    def test_an_executable_invoked_by_path_is_readable(self):
        self.assertTrue(self._graph(inspect.cleandoc("""
            function j { 1 }
            j
            & 'C:\\tools\\stage2.exe'
        """)).is_readable)

    def test_an_executable_invoked_by_unc_path_is_readable(self):
        self.assertTrue(self._graph(inspect.cleandoc("""
            function j { 1 }
            j
            & '\\\\host\\share\\p.exe'
        """)).is_readable)

    def test_an_executable_whose_stem_names_a_definition_is_not(self):
        self.assertFalse(
            self._graph(inspect.cleandoc("""
                function stage2.exe { 'P' }
                & 'C:\\tools\\stage2.exe'
            """)).is_readable)

    def test_a_qualified_call_onto_a_name_nothing_defines_is_readable(self):
        self.assertTrue(self._graph(inspect.cleandoc("""
            function Qzmr { 'P' }
            & 'MyModule\\Other'
        """)).is_readable)

    def test_a_bare_noun_whose_retry_lands_on_a_definition_keeps_that_definition(self):
        graph = self._graph(inspect.cleandoc("""
            function Get-Item { 'P' }
            item env:zzq
        """))
        self.assertFalse(graph.is_readable)
        self.assertEqual(graph.reachable_names(), frozenset({'get-item', 'item'}))

    def test_a_bare_noun_the_script_defines_itself_is_readable(self):
        graph = self._graph(inspect.cleandoc("""
            function item { 'P' }
            item env:zzq
        """))
        self.assertTrue(graph.is_readable)
        self.assertEqual(graph.reachable_names(), frozenset({'item'}))

    def test_a_dashed_call_does_not_reach_the_definition_of_its_prefixed_spelling(self):
        for source, called in (
            (inspect.cleandoc("""
                function Get-Zq-Frob { 'P' }
                Zq-Frob
            """), 'zq-frob'),
            (inspect.cleandoc("""
                function Get-Get-Zqfrob { 'P' }
                Get-Zqfrob
            """), 'get-zqfrob'),
        ):
            with self.subTest(source):
                graph = self._graph(source)
                self.assertTrue(graph.is_readable)
                self.assertEqual(graph.reachable_names(), frozenset({called}))

    def test_a_bare_noun_the_script_defines_leaves_its_prefixed_definition_unreached(self):
        for source in (
            inspect.cleandoc("""
                function Get-Zqfrob { 'P' }
                function Zqfrob { 'Q' }
                Zqfrob
            """),
            inspect.cleandoc("""
                function Zqfrob { 'Q' }
                function Get-Zqfrob { 'P' }
                Zqfrob
            """),
        ):
            with self.subTest(source):
                graph = self._graph(source)
                self.assertTrue(graph.is_readable)
                self.assertEqual(sorted(graph.defined_names), ['get-zqfrob', 'zqfrob'])
                self.assertEqual(graph.reachable_names(), frozenset({'zqfrob'}))

    def test_a_module_qualified_export_is_still_read_as_an_export(self):
        graph = self._graph(
            inspect.cleandoc("""
                & 'Microsoft.PowerShell.Core\\Export-ModuleMember' -Function f
                function f { 'P' }
            """))
        self.assertTrue(graph.exports_a_name)
        self.assertFalse(graph.is_readable)

_COMMAND_NAMESPACE_OPENERS = (
    ". '.\\stage2.ps1'",
    'Invoke-Expression $code',
    'Import-Module .\\m.psm1',
    'New-Module { }',
    'Invoke-Command -ScriptBlock $s',
    'Start-Job -ScriptBlock $s',
    'Set-Alias q $t',
    'New-Alias q Write-Output',
    'Import-Alias .\\a.csv',
    '& $dispatch',
    '[ScriptBlock]::Create($c)',
    '$ExecutionContext.InvokeCommand.InvokeScript($c)',
    'Set-Item alias:q Write-Output',
    '${function:Qzmr} = $b',
)


class TestPs1CallGraphReadabilityAnswersOverAMeasuredWorld(TestBase):

    @staticmethod
    def _graph(source: str):
        root = Ps1Parser(source).parse()
        return build_call_graph(root, build_closed_world(root))

    def _readability_beside(self, opener: str) -> bool:
        return self._graph(inspect.cleandoc(F"""
            function Qzmr {{ }}
            Qzmr
            {opener}
        """)).is_readable

    def test_a_script_that_opens_no_world_is_readable(self):
        self.assertTrue(self._readability_beside("Write-Host 'A'"))

    def test_every_command_namespace_opener_makes_the_graph_unreadable(self):
        for opener in _COMMAND_NAMESPACE_OPENERS:
            with self.subTest(opener):
                self.assertFalse(self._readability_beside(opener))

    def test_a_class_definition_leaves_the_graph_readable(self):
        self.assertTrue(self._readability_beside('class C { }'))

    def test_an_enum_definition_leaves_the_graph_readable(self):
        self.assertTrue(self._readability_beside('enum E { A }'))

    def test_add_type_leaves_the_graph_readable(self):
        self.assertTrue(self._readability_beside("Add-Type -TypeDefinition 'public class Z {}'"))

    def test_update_type_data_leaves_the_graph_readable(self):
        self.assertTrue(self._readability_beside(
            'Update-TypeData -Force -TypeName System.String -MemberName Q -Value 1'))

    def test_a_type_accelerator_mutation_leaves_the_graph_readable(self):
        self.assertTrue(self._readability_beside(
            "[System.Management.Automation.PSObject+TypeAccelerators]::Add('z', [int])"))

    def test_a_psobject_member_mutation_leaves_the_graph_readable(self):
        self.assertTrue(self._readability_beside('$o.PSObject.Members.Add($m)'))

    def test_add_member_leaves_the_graph_readable(self):
        self.assertTrue(self._readability_beside(
            'Add-Member -InputObject $o -Name Q -Value 1 -MemberType NoteProperty'))

    def test_a_type_mutation_leaves_an_uncalled_helper_reached_by_nobody(self):
        graph = self._graph(
            inspect.cleandoc("""
                function Zqhelper { 'P' }
                Add-Type -TypeDefinition 'public class Z {}'
            """))
        self.assertTrue(graph.is_readable)
        self.assertNotIn('zqhelper', graph.reachable_names())

    def test_a_command_table_opener_keeps_that_same_helper_reachable(self):
        graph = self._graph(inspect.cleandoc("""
            function Zqhelper { 'P' }
            Import-Module .\\m.psm1
        """))
        self.assertFalse(graph.is_readable)
        self.assertIn('zqhelper', graph.reachable_names())


class TestPs1ACallUnderAConstantNameInParenthesesCallsThatName(TestBase):

    def test_a_parenthesised_constant_name_is_a_call_site_of_the_function(self):
        for call in ("& ('f1')", "& $('f1')", ". ('f1')"):
            with self.subTest(call=call):
                graph = build_call_graph(Ps1Parser(inspect.cleandoc(F"""
                    function f1 {{ 'a' }}
                    {call}
                """)).parse(), _CLOSED_WORLD)
                self.assertEqual(len(graph.call_sites('f1')), 1)


class TestPs1ACallTheGraphCannotAttributeIsListed(TestBase):

    def test_every_call_running_unreadable_code_is_listed_under_either_reading(self):
        for call in ('& $n', 'iex $c', '$ExecutionContext.InvokeCommand.InvokeScript($s)'):
            for trust_eval in (False, True):
                with self.subTest(call=call, trust_eval=trust_eval):
                    root = Ps1Parser(inspect.cleandoc(F"""
                        function f1 {{ 'a' }}
                        {call}
                    """)).parse()
                    graph = build_call_graph(root, build_closed_world(root), Ps1DeobfuscationOptions(trust_eval=trust_eval))
                    self.assertEqual(len(graph.unattributed_sites), 1)

    def test_a_call_naming_a_function_is_not_listed(self):
        root = Ps1Parser(inspect.cleandoc("""
            function f1 { 'a' }
            f1
        """)).parse()
        self.assertEqual(len(build_call_graph(root, build_closed_world(root)).unattributed_sites), 0)


class TestPs1AFunctionTheScriptHandsOutIsReachedWithoutACall(TestBase):

    @staticmethod
    def _graph(source: str):
        return build_call_graph(Ps1Parser(source).parse(), _CLOSED_WORLD)

    def test_each_way_of_handing_a_function_out_hands_it_out(self):
        for use in (
            '$b = $function:f1',
            '$b = (Get-Command f1).ScriptBlock',
            "$b = (Get-Item 'function:f1').ScriptBlock",
            "function f1 { $MyInvocation.MyCommand.ScriptBlock }",
        ):
            with self.subTest(use=use):
                graph = self._graph(inspect.cleandoc(F"""
                    function f1 {{ 'a' }}
                    {use}
                """))
                self.assertTrue(graph.hands_out('f1'))
                self.assertIn('f1', graph.reachable_names())

    def test_a_lookup_that_cannot_name_the_function_hands_out_every_function(self):
        for use in ('Get-Command', 'Get-Command f*', "Get-ChildItem 'function:'"):
            with self.subTest(use=use):
                self.assertTrue(self._graph(inspect.cleandoc(F"""
                    function f1 {{ 'a' }}
                    {use}
                """)).hands_out('f1'))

    def test_a_lookup_selecting_by_anything_but_a_name_hands_out_every_function(self):
        for use in (
            'Get-Command -CommandType Function',
            'gcm -Type Function',
            'Get-Command -Module m',
            "$p = @{ CommandType = 'Function' }; Get-Command @p",
        ):
            with self.subTest(use=use):
                self.assertTrue(self._graph(inspect.cleandoc(F"""
                    function f1 {{ 'a' }}
                    $c = {use}
                """)).hands_out('f1'))

    def test_a_lookup_by_name_hands_out_that_function_alone(self):
        graph = self._graph(inspect.cleandoc("""
            function f1 { 'a' }
            function f2 { 'b' }
            $c = Get-Command -Name f1 -CommandType Function
        """))
        self.assertEqual([graph.hands_out('f1'), graph.hands_out('f2')], [True, False])

    def test_reading_the_name_of_a_lookup_hands_out_what_it_lists(self):
        for source, name in (
            (inspect.cleandoc("""
                function f1 { 'a' }
                (Get-Command f1).Name
            """), 'f1'),
            (inspect.cleandoc("""
                function wrnte { 'a' }
                (Get-Command 'wrn`te').Name
            """), 'wrnte'),
            (inspect.cleandoc("""
                function wrnte { 'a' }
                (Get-Command ???t?).Name
            """), 'wrnte'),
        ):
            with self.subTest(source):
                self.assertTrue(self._graph(source).hands_out(name))

    def test_a_discarded_lookup_that_cannot_raise_hands_nothing_out(self):
        self.assertFalse(self._graph(inspect.cleandoc("""
            function f1 { 'a' }
            $Null = (Get-Command f*).Name
        """)).hands_out('f1'))

    def test_a_narrowed_listing_hands_out_what_the_narrowing_passes(self):
        graph = self._graph(
            inspect.cleandoc("""
                function f1 { 'a' }
                function g1 { 'b' }
                $c = Get-Command | Where-Object { $_.Name -like 'f*' }
            """))
        self.assertEqual([graph.hands_out('f1'), graph.hands_out('g1')], [True, False])
