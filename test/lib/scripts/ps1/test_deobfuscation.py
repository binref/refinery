from __future__ import annotations

from inspect import cleandoc

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.pipeline import DeobfuscationTimeout
from refinery.lib.scripts.ps1.deobfuscation import deobfuscate
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer


class TestPs1ParserModeRescan(TestPs1):

    def test_paren_command_static_member_resolved(self):
        result = self._deobfuscate(
            '$Y = [Net.SecurityProtocolType];'
            ' [Net.ServicePointManager]::SecurityProtocol = (Get-Variable Y -ValueOnly)::Tls'
        )
        self.assertIn('::Tls', result)
        self.assertIn('SecurityProtocolType', result)
        self.assertNotIn('Get-Variable', result)

    def test_paren_command_invoke_member_resolved(self):
        result = self._deobfuscate(
            '$X = [Convert];'
            ' (Get-Variable X -ValueOnly)::FromBase64String("AAAA")'
        )
        self.assertIn('0x00', result)
        self.assertNotIn('Get-Variable', result)
        self.assertNotIn('FromBase64String', result)

    def test_member_name_case_normalization(self):
        result = self._deobfuscate(
            '[Net.ServicePointManager]::sEcUrItYpRoToCoL'
        )
        self.assertIn('SecurityProtocol', result)
        self.assertNotIn('sEcUrItYpRoToCoL', result)

    def test_member_name_default_credentials(self):
        result = self._deobfuscate(
            '[Net.CredentialCache]::dEfAuLtCrEdEnTiAlS'
        )
        self.assertIn('DefaultCredentials', result)

    def test_invocation_operator_type_literal_in_method_args(self):
        result = self._deobfuscate(
            '(. $a."B"($c."D"($x,$y,$z),[int]::Max) Arg); $z=1'
        )
        self.assertIn('Max', result)
        self.assertIn('Arg', result)

    def test_dotted_command_name(self):
        result = self._deobfuscate(
            'deVICEcREdEnTiaLDEPlOYmENt.eXe ; Write-Host hello'
        )
        self.assertIn('deVICEcREdEnTiaLDEPlOYmENt.eXe', result)

    def test_wildcard_argument_not_split(self):
        ast = Ps1Parser("gcm ???t?")
        result = Ps1Synthesizer().convert(ast.parse())
        self.assertEqual(result, 'gcm ???t?')

    def test_member_dash_operator_not_absorbed(self):
        ast = Ps1Parser("$_.Name-like'*test*'")
        result = Ps1Synthesizer().convert(ast.parse())
        self.assertIn('-like', result)
        self.assertNotIn('Name-like', result)

    def test_array_type_in_param_block(self):
        result = self._deobfuscate(
            'function f { Param([byte[]]$x, [string]$y) ; $x }'
        )
        self.assertIn('[byte[]]', result)
        self.assertIn('[string]', result)

    def test_digit_starting_token_does_not_break_expression(self):
        result = self._deobfuscate('$x = 1 + 2')
        self.assertIn('3', result)

    def test_a_payload_in_a_typed_catch_after_a_command_try_body_survives(self):
        """
        The type name is read in whatever mode the try body left behind, and a command leaves
        argument mode, where a bare token does not end at `]`. The name then swallowed the handler
        and the rest of the script, so the payload reached no pass at all and the tail of the file
        came back out as the handler body.
        """
        result = self._deobfuscate_iterative(
            "try { Get-Process } catch [System.Exception] { Start-Process calc }\n"
            "Write-Host 'keep'")
        self.assertEqual(result, cleandoc(
            '''
            try {
              Get-Process
            } catch [System.Exception] {
              Start-Process calc
            }
            Write-Host 'keep'
            '''
        ))

    def test_an_empty_typed_catch_after_a_command_try_body_dissolves_alone(self):
        result = self._deobfuscate_iterative("try { foo =5 } catch [A] {}\nWrite-Host 'keep'")
        self.assertEqual(result, "Write-Host 'keep'")


class TestPs1ClassEnum(TestPs1):

    def test_class_basic_round_trip(self):
        result = self._deobfuscate('class Foo { [string]$Name }')
        self.assertIn('class Foo', result)
        self.assertIn('$Name', result)

    def test_class_with_inheritance(self):
        result = self._deobfuscate('class Derived : Base { [int]$X }')
        self.assertIn('class Derived : Base', result)
        self.assertIn('$X', result)

    def test_class_static_method(self):
        result = self._deobfuscate_iterative(
            'class B { static [int] A([string]$xWdH){return $xWdH[0]}}'
        )
        self.assertIn('class B', result)
        self.assertIn('static', result)
        self.assertIn('[int]', result)
        self.assertIn('A(', result)
        self.assertIn('$xWdH', result)

    def test_class_method_with_body(self):
        result = self._deobfuscate(
            'class Foo : Bar { [void] Greet() { Write-Host "hello" } }'
        )
        self.assertIn('class Foo : Bar', result)
        self.assertIn('Greet()', result)
        self.assertIn('Write-Host', result)

    def test_class_hidden_property(self):
        result = self._deobfuscate('class H { hidden [int]$Secret = 42 }')
        self.assertIn('hidden', result)
        self.assertIn('$Secret', result)
        self.assertIn('42', result)

    def test_class_constructor(self):
        result = self._deobfuscate(
            'class C { C([int]$n) { $this.N = $n } ; [int]$N }'
        )
        self.assertIn('class C', result)
        self.assertIn('$n', result)
        self.assertIn('$This.N', result)

    def test_class_method_params_not_null_inlined(self):
        result = self._deobfuscate_iterative(
            'class B { static [int] A([string]$xWdH){return $xWdH[0]}}'
        )
        self.assertNotIn('$Null', result)
        self.assertIn('$xWdH[0]', result)

    def test_class_preserved_alongside_outer_code(self):
        result = self._deobfuscate_iterative(
            '$x = 1; class C { [int]$N }; Write-Host $x'
        )
        self.assertIn('class C', result)
        self.assertIn('Write-Host', result)

    def test_enum_basic(self):
        result = self._deobfuscate('enum Color { Red; Green; Blue }')
        self.assertIn('enum Color', result)
        self.assertIn('Red', result)
        self.assertIn('Green', result)
        self.assertIn('Blue', result)

    def test_enum_with_values(self):
        result = self._deobfuscate('enum Flags { None = 0; Read = 1; Write = 2 }')
        self.assertIn('enum Flags', result)
        self.assertIn('Read = 1', result)
        self.assertIn('Write = 2', result)

    def test_enum_with_underlying_type(self):
        result = self._deobfuscate('enum Size : byte { Small; Large }')
        self.assertIn('enum Size : byte', result)
        self.assertIn('Small', result)
        self.assertIn('Large', result)


class TestPs1Integration(TestPs1):

    def test_type_variable_inlined(self):
        result = self._deobfuscate(
            "$x = [Type]'Convert'; $x::FromBase64String('dGVzdA==')"
        )
        self.assertNotIn("'Convert'", result)
        self.assertIn('0x74', result)

    def test_gcm_unwrap(self):
        data = "& (gcm 'Set-Variable') foo 42"
        result = self._deobfuscate(data)
        self.assertIn('$foo', result)
        self.assertIn('42', result)
        self.assertNotIn('gcm', result)

    def test_method_argument_binary_expressions(self):
        result = self._deobfuscate(
            "$x=$a.GetType('Sys'+'tem.Int32');"
            "$y=$b.Replace('#','');"
            "$z=$c.Foo('A'+'B','C'+'D')"
        )
        self.assertIn("GetType('System.Int32')", result)
        self.assertIn("Replace('#', '')", result)
        self.assertIn("Foo('AB', 'CD')", result)

    def test_tostring_multiindex_join(self):
        data = "& ('SilentlyContinue'.ToString()[1, 3] + 'x' -Join '')"
        result = self._deobfuscate(data)
        self.assertIn('invoke-expression', result.lower())

    def test_index_in_method_arg(self):
        result = self._deobfuscate('$x.Method($a[0,1])')
        self.assertIn('[0, 1]', result)

    def test_scriptblock_comma_in_method_arg(self):
        result = self._deobfuscate('$x.Where({$_ -in 1,2,3})', remove_junk=False)
        self.assertIn('1, 2, 3', result)

    def test_shl_operator(self):
        result = self._deobfuscate('$y = $env:V\n$x = $y -shl 2')
        self.assertIn('-shl', result.lower())

    def test_shr_operator(self):
        result = self._deobfuscate('$y = $env:V\n$x = $y -shr 3')
        self.assertIn('-shr', result.lower())

    def test_exit_negative_literal(self):
        result = self._deobfuscate('exit -65536')
        self.assertIn(' -65536', result)

    def test_range_expression_chained(self):
        result = self._deobfuscate('$x = 1..5..2')
        self.assertIn('1..5..2', result)

    def test_dash_operator_as_parameter_in_command(self):
        code = '$x = ((gwmi win32_process -F ProcessId=${PID}).CommandLine) -split [char]34'
        result = self._deobfuscate(code)
        self.assertIn('-split', result.lower())
        self.assertIn('.commandline', result.lower())
        for line in result.strip().splitlines():
            self.assertNotEqual(line.strip(), ')')

    def test_binary_expression_in_command_argument(self):
        result = self._deobfuscate("Set-Item Variable:x ($env:temp + '\\foo.exe')")
        self.assertIn('${env:Temp}', result)
        self.assertIn('\\foo.exe', result)

    def test_semicolons_are_statement_separators(self):
        result = self._deobfuscate('; Get-Item foo ;; Get-Item bar ;')
        self.assertNotIn(';', result)
        self.assertIn('Get-Item foo', result)
        self.assertIn('Get-Item bar', result)

    def test_assignment_if_expression(self):
        result = self._deobfuscate('$d = if ($x) { 1 } else { 2 }')
        self.assertIn('$d = if', result)

    def test_assignment_for_expression(self):
        result = self._deobfuscate('$r = for ($i = 0; $i -LT 5; $i++) { $i }')
        self.assertIn('$r = for', result)

    def test_expandable_here_string_inlining_not_stale(self):
        # The constant inlined into the expandable here-string must reach the output, and the
        # source assignment is then removed cleanly (no dangling $v).
        result = self._deobfuscate_iterative(cleandoc("""
            $v = 'SECRET'
            $h = @"
            value: $v end
            "@
            Write-Host $h
        """))
        self.assertEqual(result, cleandoc("""
            $h = "value: SECRET end"
            Write-Host $h
        """))

    def test_step_budget_enforced_across_phases(self):
        # A step budget smaller than the total work must raise rather than letting phase 2 run
        # unbounded once phase 1 has consumed the budget.
        source = cleandoc("""
            $a = 1 + 2
            $b = 'x' + 'y'
            $unused = 'dead'
            Write-Host $a $b
        """)
        ast = Ps1Parser(source).parse()
        with self.assertRaises(DeobfuscationTimeout):
            deobfuscate(ast, max_steps=1)

    def test_a_group_that_cannot_settle_within_the_budget_raises_instead_of_hanging(self):
        """
        No naturally non-converging input is known to remain, so the enduring contract — that a
        transformer group which cannot settle within the step budget fails loudly rather than
        looping forever — is exercised by starving a convergent input of budget. This script
        settles in three change-producing passes; a budget of two must raise.
        """
        ast = Ps1Parser(cleandoc("""
            $a = 1 + 2 + 3 + 4 + 5
            $b = 'x' + 'y' + 'z'
            $c = $a
            Write-Host $a $b $c
        """)).parse()
        with self.assertRaises(DeobfuscationTimeout):
            deobfuscate(ast, max_steps=2)

    def test_string_equality_guard_prunes_dead_branch(self):
        # A folded string comparison must cascade into dead-branch elimination across the pipeline.
        result = self._deobfuscate(
            "if ('m' -eq 'z') { Write-Output 'dead' } else { Write-Output 'live' }")
        self.assertEqual(result, "Write-Output 'live'")

    def test_logical_guard_prunes_dead_branch(self):
        # A folded boolean `-and` guard must likewise cascade into dead-branch elimination.
        result = self._deobfuscate(
            "if ($true -and $false) { Write-Output 'dead' } else { Write-Output 'live' }")
        self.assertEqual(result, "Write-Output 'live'")

    def test_junk_function_cascade(self):
        result = self._deobfuscate(
            "function j { $Null = 915 }\nj\nWrite-Host 'payload'")
        self.assertEqual(result, "Write-Host 'payload'")

    def test_empty_for_dead_variable_cascade(self):
        result = self._deobfuscate(
            "for ($i = 0; $i -LT 41; $i++) {}\nWrite-Host 'payload'")
        self.assertEqual(result, "Write-Host 'payload'")

    def test_empty_for_live_variable_terminal_kept(self):
        result = self._deobfuscate(
            'for ($i = 0; $i -LT 41; $i++) {}\nWrite-Host $i')
        self.assertEqual(result, 'Write-Host 41')

    def test_tier2_full_cascade(self):
        src = cleandoc("""
            for ($i = 0; $i -LT 41; $i++) {}
            function j { $Null = 915 }
            j
            trap { continue }
            try {} catch {}
            Write-Host 'payload'
        """)
        result = self._deobfuscate(src)
        self.assertEqual(result, "Write-Host 'payload'")

    def test_tier3_try_bareword_cascade(self):
        src = cleandoc("""
            try { foo =5 } catch {}
            try { bar =3 } catch {}
            Write-Host 'payload'
        """)
        result = self._deobfuscate(src)
        self.assertEqual(result, "Write-Host 'payload'")

    def test_tier3_dead_store_cascade(self):
        src = "$i = 33\n$i = 44\nfor ($i = 0; $i -LT 3; $i++) { Write-Host $i }"
        result = self._deobfuscate(src)
        self.assertNotIn('$i = 33', result)
        self.assertNotIn('$i = 44', result)
        self.assertIn('for', result)

    def test_tier3_full(self):
        src = cleandoc("""
            try { MEI26Qtd2AKx =9188720 } catch {}
            $i = 33
            try { kfkeJNjkCnmbK =3750696 } catch {}
            $i = 44
            Write-Host 'payload'
        """)
        result = self._deobfuscate(src)
        self.assertEqual(result, "Write-Host 'payload'")


class TestPs1ClosedWorld(TestPs1):
    """
    A probe on Windows PowerShell confirmed that `Update-TypeData -Force` can shadow a native member
    with a code-running ScriptProperty, so a member read after any type-system or command-identity
    mutation — or after opaque code that could perform one — is not junk and must survive
    deobfuscation. Each case runs the same read with and without an opener and checks it is deleted
    only in a closed world.
    """

    def test_a_pure_read_is_deleted_only_in_a_closed_world(self):
        anchor = "$Null = [Environment]::UserName\nWrite-Output 'anchor'\n"
        self.assertNotIn('UserName', self._deobfuscate_iterative(anchor))
        openers = (
            'Update-TypeData -TypeName System.String -MemberName M '
            '-MemberType ScriptProperty -Value { 1 }\n',
            'Set-Item alias:utd Update-TypeData\n',
            'iex $x\n',
        )
        for opener in openers:
            with self.subTest(opener):
                self.assertIn('UserName', self._deobfuscate_iterative(opener + anchor))

    def test_a_temporary_mutator_is_deleted_only_in_a_closed_world(self):
        # The in-place mutator on a temporary is pure — but the grant is a present-member grant, so it
        # gates on the world too, the case both critic rounds caught.
        anchor = "$Null = [Array]::Reverse('ab'.ToCharArray())\nWrite-Output 'anchor'\n"
        self.assertNotIn('Reverse', self._deobfuscate_iterative(anchor))
        self.assertIn('Reverse', self._deobfuscate_iterative('iex $x\n' + anchor))


class TestPs1CommandRedefinition(TestPs1):
    """
    A script-local `function`/`filter` (or a `${function:X}=` assignment) shadows a same-named
    command, so it no longer runs what the metadata describes. The analysis must not delete a read,
    discard, or pipeline sink of a shadowed command as if it were the inert built-in — every form
    below runs a real `Start-Process` through the shadowing definition and must survive.

    A scope qualifier selects which scope table the definition lands in and is not part of the name,
    so every qualified spelling has to shadow what the unqualified call resolves to.
    """

    def test_a_shadowed_commands_effect_survives_every_deletion_form(self):
        anchor = "\nWrite-Output 'keep'\n"
        forms = {
            'member-read': "function Get-Date { Start-Process calc }\n$Null = (Get-Date).Ticks",
            'bare-discard': "function Get-Date { Start-Process calc }\n$Null = Get-Date",
            'out-null-sink': "function Out-Null { Start-Process calc }\n1 | Out-Null",
            'foreach-void-sink':
                "function ForEach-Object { Start-Process calc }\n1 | ForEach-Object { [Void]$_ }",
            'noise-bareword-try': "function Zzz { Start-Process calc }\ntry { Zzz =5 } catch {}",
            'function-scope-assign':
                "${function:Get-Date} = { Start-Process calc }\n$Null = Get-Date",
            'new-object': "function New-Object { Start-Process calc }\n$Null = New-Object Version",
            'global-function':
                "function global:Get-Date { Start-Process calc }\n$Null = (Get-Date).Ticks",
            'private-filter': "filter private:Out-Null { Start-Process calc }\n1 | Out-Null",
        }
        for name, body in forms.items():
            with self.subTest(name):
                self.assertIn('Start-Process', self._deobfuscate_iterative(body + anchor))

    def test_a_multi_assignment_redefinition_keeps_the_call_it_shadows(self):
        # The payload text survives inside the assignment whatever happens, so asserting on it would
        # prove nothing here. What the shadow set has to save is the *call*, which is what runs it —
        # and matching one target shape against one variable never saw this form at all.
        out = self._deobfuscate_iterative(
            "${function:Get-Date}, $y = { Start-Process calc }, 2\n"
            "$Null = (Get-Date).Ticks\n"
            "Write-Output 'keep'\n")
        self.assertIn('Ticks', out)
        self.assertIn('Start-Process', out)

    def test_an_unshadowed_pure_read_is_still_deleted(self):
        # The guard is name-keyed, not blanket: a script that defines an unrelated function still has
        # its genuinely-pure junk removed.
        out = self._deobfuscate_iterative(
            "function Helper { 'x' }\n$Null = (Get-Date).Ticks\nWrite-Output 'keep'\n")
        self.assertNotIn('Get-Date', out)

    def test_a_cast_to_a_script_defined_type_keeps_the_constructor_it_runs(self):
        # PowerShell converts a string to a custom type by invoking a one-argument constructor, so
        # the cast is the call. The type is defined in this very script and the constructor body is
        # standing in the tree, and the conversion was still deleted.
        out = self._deobfuscate_iterative(cleandoc(
            """
            class Loader { Loader([String]$s) { [IO.File]::WriteAllText('C:\\p.txt', $s) } }
            $Null = [Loader]'payload'
            Write-Host 'keep'
            """
        ))
        self.assertIn('[Loader]', out)

    def test_a_name_is_inert_only_when_every_definition_of_it_is(self):
        # Call sites are attributed to the name, not to one of its definitions, so dropping them
        # because one definition is empty silences the other: the calls go first, then the surviving
        # definition reads as never called and follows on the next round. Which definition a call
        # actually reaches is order and scope information no pass here has, so both are kept.
        for second in ('function f { }', 'function global:f { }'):
            with self.subTest(second):
                out = self._deobfuscate_iterative(
                    F"function f {{ Start-Process calc }}\n{second}\nf\nWrite-Host 'keep'")
                self.assertIn('Start-Process', out)


class TestPs1ErrorHandlerSurvival(TestPs1):
    """
    Moving the real work into a `catch` and making the `try` fail on purpose is a standard
    anti-analysis shape, and nothing in this pipeline decides whether a statement throws. A `try`
    body therefore reads as harmless whether it truly is or merely looks it, and once the body is
    gone the handler beside it is provably unreachable — so the payload goes too, and the deletion
    is silent.

    The refusal is placed on dropping the handler rather than on emptying the body, because the
    routes to an empty body are many and each new pass adds another. A body left empty is an
    artifact of this pipeline: it is evidence about the pass that produced it, never about whether
    the code as written could raise.
    """

    def test_a_payload_in_a_catch_survives_a_throwing_try_body(self):
        # Nothing here can tell that `[Int]'abc'` throws — it emits nothing, so the cleanup passes
        # removed it, and the emptied body then made the handler unreachable.
        for body in ("$Null = [Int]'abc'", "$x = [Int]'abc'", "[Int]'abc'", "[Guid]'nope'"):
            with self.subTest(body):
                out = self._deobfuscate_iterative(
                    F"try {{ {body} }} catch {{ Start-Process calc }}\nWrite-Host 'keep'")
                self.assertIn('Start-Process', out)

    def test_a_payload_in_a_catch_survives_a_try_body_another_pass_emptied(self):
        # The same over-deletion reached by every other route: an inert function inlined away, a
        # definition-only body, a constant-false branch, a bare literal, a trap, an empty loop.
        scripts = (
            "function f { $Null = [Int]'abc' }\ntry { f } catch { Start-Process calc }",
            "try { function g { 'z' } } catch { Start-Process calc }\nWrite-Host (g)",
            "try { if ($false) { 1 } } catch { Start-Process calc }",
            "try { 42 } catch { Start-Process calc }",
            "try { trap { continue } } catch { Start-Process calc }",
            "try { do { } while ($false) } catch { Start-Process calc }",
        )
        for script in scripts:
            with self.subTest(script):
                out = self._deobfuscate_iterative(F"{script}\nWrite-Host 'keep'")
                self.assertIn('Start-Process', out)

    def test_an_empty_catch_lets_a_noise_bareword_go_and_keeps_what_may_emit(self):
        # An empty `catch` licenses *deleting* a statement that raises, and licenses nothing wider.
        # `[Int]'abc'` is the case where the two halves of that disagree: measured on PowerShell
        # 5.1, the construct prints nothing when the cast fails and prints `5` when it succeeds, so
        # it can be neither deleted nor moved out, and the whole of it stays. The bareword goes on
        # the separate guess that nothing defines it.
        out = self._deobfuscate_iterative(
            "try { foo =5 } catch {}\ntry { [Int]'abc' } catch {}\nWrite-Host 'keep'")
        self.assertEqual(out, "try {\n  [Int]'abc'\n} catch {}\nWrite-Host 'keep'")


class TestPs1NameTrustSurvivesRewriting(TestPs1):
    """
    A rename pass and a pruning pass agree on a name only while they read the same facts about it.
    Every case here is a rewrite that erased the evidence the later pass needed: the name it renamed
    was one the script had taken over, or the operator it dropped was the world's only signal that
    off-tree code runs.
    """

    def test_a_dot_source_of_a_script_keeps_its_operator(self):
        # Regression: the dot was dropped for any bare-safe name, so `. helper` became `helper` and
        # the world, rebuilt from the stripped tree, read closed and granted every purity check.
        out = self._deobfuscate_iterative(cleandoc(
            """
            . 'profile-loader'
            $Null = (Get-Date).Ticks
            Write-Host 'keep'
            """
        ))
        self.assertIn('. profile-loader', out)
        self.assertIn('Get-Date', out)

    def test_a_dot_on_a_cmdlet_is_still_dropped(self):
        # A compiled cmdlet has no body to run in the caller's scope, so the dot carries nothing.
        out = self._deobfuscate_iterative("$c = . New-Object 'Net.WebClient'\nWrite-Host $c")
        self.assertNotIn('. New-Object', out)

    def test_a_provider_redefinition_is_kept_while_the_bare_call_resolves_to_the_alias(self):
        # `${function:gci} = { ... }` is an identity-binding assignment that keeps the world
        # conservative, so the payload is retained; and because a default alias beats a function,
        # the bare `gci` resolves to the alias Get-ChildItem. Verified against 5.1: with the
        # provider assignment in scope, `gci` still runs Get-ChildItem.
        out = self._deobfuscate_iterative(cleandoc(
            """
            ${function:gci} = { Start-Process calc }
            gci
            Write-Host done
            """
        ))
        self.assertIn('Start-Process calc', out)
        self.assertIn('Get-ChildItem', out)

    def test_a_regex_match_that_populates_matches_is_kept(self):
        # Regression: `-match` writes the automatic `$Matches`, which is a store to engine state and
        # not a value the expression merely yields, so deleting the match left the payload read on
        # the next line looking at an unset variable.
        out = self._deobfuscate_iterative(cleandoc(
            """
            $c = 'aaa<<calc>>bbb'
            $z = $c -match '<<(.*)>>'
            Invoke-Expression $Matches[1]
            """
        ))
        self.assertIn('-Match', out)

    def test_a_scope_qualified_redefinition_is_not_constant_folded(self):
        # Regression: the evaluator keyed definitions by their written spelling and kept the last
        # one, so `function F` was folded into the call that `function global:F` had replaced, and
        # the payload definition then read as never called.
        out = self._deobfuscate_iterative(cleandoc(
            """
            function F { 'A' }
            function global:F { Start-Process calc; 'B' }
            Write-Host (F)
            """
        ))
        self.assertIn('Start-Process calc', out)
