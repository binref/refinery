from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.ps1.analysis.callgraph import build_call_graph
from refinery.lib.scripts.ps1.analysis.world import Ps1TypeWorld, build_closed_world
from refinery.lib.scripts.ps1.parser import Ps1Parser

#: A world with nothing shadowed and nothing imported, so that `is_readable` answers on the rows
#: this file is about rather than on a world that was open to begin with.
_CLOSED_WORLD = Ps1TypeWorld(True, frozenset())


class TestPs1CallGraphReadability(TestBase):

    @staticmethod
    def _graph(source: str):
        return build_call_graph(Ps1Parser(source).parse(), _CLOSED_WORLD)

    def test_a_script_whose_calls_and_definitions_meet_is_readable(self):
        self.assertTrue(self._graph("function Qzmr { 'P' }\nQzmr").is_readable)

    def test_a_module_qualified_call_onto_a_defined_name_is_not(self):
        self.assertFalse(self._graph("function Qzmr { 'P' }\n& 'MyModule\\Qzmr'").is_readable)

    def test_the_bare_spelling_of_that_call_is_not_either(self):
        self.assertFalse(self._graph("function Qzmr { 'P' }\n& MyModule\\Qzmr").is_readable)

    def test_the_definition_may_be_written_below_the_call(self):
        self.assertFalse(self._graph("& 'MyModule\\Qzmr'\nfunction Qzmr { 'P' }").is_readable)

    def test_an_aliased_call_onto_a_defined_name_is_not_readable(self):
        self.assertFalse(
            self._graph("function Invoke-Expression { 'P' }\niex 'x'").is_readable)

    def test_a_scope_qualified_call_is_readable_because_the_key_already_matches(self):
        self.assertTrue(self._graph("function Qzmr { 'P' }\n& 'global:Qzmr'").is_readable)

    def test_an_executable_invoked_by_path_is_readable(self):
        self.assertTrue(self._graph("function j { 1 }\nj\n& 'C:\\tools\\stage2.exe'").is_readable)

    def test_an_executable_invoked_by_unc_path_is_readable(self):
        self.assertTrue(self._graph("function j { 1 }\nj\n& '\\\\host\\share\\p.exe'").is_readable)

    def test_an_executable_whose_stem_names_a_definition_is_not(self):
        self.assertFalse(
            self._graph("function stage2.exe { 'P' }\n& 'C:\\tools\\stage2.exe'").is_readable)

    def test_a_qualified_call_onto_a_name_nothing_defines_is_readable(self):
        self.assertTrue(self._graph("function Qzmr { 'P' }\n& 'MyModule\\Other'").is_readable)

    def test_a_bare_noun_whose_retry_lands_on_a_definition_keeps_that_definition(self):
        """
        Measured on 5.1: `function Get-Item { Write-Output 'from-function' }; item env:zzq` writes
        `from-function`, so the call reaches the definition although it spells another name. Read by
        the written key alone the definition is called by nobody, and deleting it takes out the body
        that runs.
        """
        graph = self._graph("function Get-Item { 'P' }\nitem env:zzq")
        self.assertFalse(graph.is_readable)
        self.assertEqual(graph.reachable_names(), frozenset({'get-item', 'item'}))

    def test_a_bare_noun_the_script_defines_itself_is_readable(self):
        graph = self._graph("function item { 'P' }\nitem env:zzq")
        self.assertTrue(graph.is_readable)
        self.assertEqual(graph.reachable_names(), frozenset({'item'}))

    def test_a_dashed_call_does_not_reach_the_definition_of_its_prefixed_spelling(self):
        for source, called in (
            ("function Get-Zq-Frob { 'P' }\nZq-Frob", 'zq-frob'),
            ("function Get-Get-Zqfrob { 'P' }\nGet-Zqfrob", 'get-zqfrob'),
        ):
            with self.subTest(source):
                graph = self._graph(source)
                self.assertTrue(graph.is_readable)
                self.assertEqual(graph.reachable_names(), frozenset({called}))

    def test_a_bare_noun_the_script_defines_leaves_its_prefixed_definition_unreached(self):
        for source in (
            "function Get-Zqfrob { 'P' }\nfunction Zqfrob { 'Q' }\nZqfrob",
            "function Zqfrob { 'Q' }\nfunction Get-Zqfrob { 'P' }\nZqfrob",
        ):
            with self.subTest(source):
                graph = self._graph(source)
                self.assertTrue(graph.is_readable)
                self.assertEqual(sorted(graph.defined_names), ['get-zqfrob', 'zqfrob'])
                self.assertEqual(graph.reachable_names(), frozenset({'zqfrob'}))

    def test_a_module_qualified_export_is_still_read_as_an_export(self):
        graph = self._graph(
            "& 'Microsoft.PowerShell.Core\\Export-ModuleMember' -Function f\nfunction f { 'P' }")
        self.assertTrue(graph.exports_a_name)
        self.assertFalse(graph.is_readable)

#: Every construct `refinery.lib.scripts.ps1.analysis.world` counts as opening the world, one per
#: reason it gives. The first group can put a command into this script's tables under a name no
#: statement here spells; the second cannot reach the command namespace at all, and reads as an
#: opener only because the call graph is seeded from the type world's verdict.
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
    """
    The rows above are quantified over a world stated by hand, so the one `build_call_graph` is
    actually seeded from — `world.closed_for_the_whole_run` — is answered by nothing there. These
    ask it over the world a real script measures.

    A construct that mutates the type system binds no command name: a `class` puts a type into the
    session, `Add-Type` compiles one, and `Update-TypeData` and `Add-Member` re-point members of one.
    None of them can make a bareword run something else, so none of them says this tree is not the
    whole story about what a command name denotes.
    """

    @staticmethod
    def _graph(source: str):
        root = Ps1Parser(source).parse()
        return build_call_graph(root, build_closed_world(root))

    def _readability_beside(self, opener: str) -> bool:
        return self._graph(F'function Qzmr {{ }}\nQzmr\n{opener}').is_readable

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
            "function Zqhelper { 'P' }\nAdd-Type -TypeDefinition 'public class Z {}'")
        self.assertTrue(graph.is_readable)
        self.assertNotIn('zqhelper', graph.reachable_names())

    def test_a_command_table_opener_keeps_that_same_helper_reachable(self):
        graph = self._graph("function Zqhelper { 'P' }\nImport-Module .\\m.psm1")
        self.assertFalse(graph.is_readable)
        self.assertIn('zqhelper', graph.reachable_names())
