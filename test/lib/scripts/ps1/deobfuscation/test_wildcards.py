from __future__ import annotations

from inspect import cleandoc

from test import backlog, wontfix
from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.deobfuscation import Ps1WildcardResolution


class TestPs1VariableDriveResolution(TestPs1):

    def test_get_item_variable_value_resolved(self):
        result = self._deobfuscate("(Get-Item 'Variable:E*t').Value.InvokeCommand")
        self.assertEqual(result.strip(), '$ExecutionContext.InvokeCommand')

    def test_get_variable_value_resolved(self):
        result = self._deobfuscate('(Get-Variable ExecutionContext).Value')
        self.assertEqual(result.strip(), '$ExecutionContext')

    def test_get_item_variable_without_value_preserved(self):
        result = self._deobfuscate("(Get-Item 'Variable:E*t')")
        self.assertNotIn('$ExecutionContext', result)

    def test_member_alias_resolved(self):
        result = self._deobfuscate('$x | Member')
        self.assertIn('Get-Member', result)

    def test_variable_alias_resolved(self):
        result = self._deobfuscate('Variable ExecutionContext')
        self.assertIn('Get-Variable', result)

    def test_variable_drive_path_separator_stripped(self):
        result = self._deobfuscate('(Get-Item Variable:/hb).Value')
        self.assertIn('$hb', result)
        self.assertNotIn('/', result)

    def test_set_item_variable_becomes_assignment(self):
        result = self._deobfuscate("Set-Item Variable:/G7E 'hello'")
        self.assertEqual(result.strip(), "$G7E = 'hello'")

    def test_set_item_variable_with_a_joined_value_becomes_an_assignment(self):
        self.assertEqual(
            self._deobfuscate("Set-Item Variable:/G7E $env:Temp'\\NGLClient.exe'"),
            '$G7E = "${env:Temp}\\NGLClient.exe"',
        )

    def test_set_variable_becomes_assignment(self):
        result = self._deobfuscate("Set-Variable foo 42")
        self.assertEqual(result.strip(), '$foo = 42')

    def test_set_variable_named_params(self):
        result = self._deobfuscate("Set-Variable -Name foo -Value 'bar'")
        self.assertEqual(result.strip(), "$foo = 'bar'")

    def test_set_variable_with_integer_name(self):
        result = self._deobfuscate(cleandoc("""
            Set-Variable 0 'hello'
            $0
        """))
        self.assertIn('hello', result)
        self.assertNotIn('Set-Variable', result)

    def test_get_variable_value_only_resolved(self):
        result = self._deobfuscate('Get-Variable ExecutionContext -ValueOnly')
        self.assertEqual(result.strip(), '$ExecutionContext')

    def test_get_variable_value_only_abbreviated(self):
        result = self._deobfuscate('Write-Output (Get-Variable Cf -ValueO)')
        self.assertEqual(result.strip(), 'Write-Output ($Cf)')

    def test_get_variable_value_abbreviated_short(self):
        for switch in ('-V', '-Va', '-Val', '-Valu', '-Value', '-ValueO', '-ValueOn', '-ValueOnl', '-ValueOnly'):
            with self.subTest(switch=switch):
                result = self._deobfuscate(F'Write-Output (Get-Variable Cf {switch})')
                self.assertEqual(result.strip(), 'Write-Output ($Cf)')

    def test_get_childitem_variable_drive_resolved(self):
        result = self._deobfuscate("(Get-ChildItem 'Variable:ExecutionContext').Value")
        self.assertEqual(result.strip(), '$ExecutionContext')

    def test_gci_variable_drive_resolved(self):
        result = self._deobfuscate("(gci 'Variable:X').Value")
        self.assertIn('$X', result)
        self.assertNotIn('gci', result)

    def test_get_variable_value_only_member_access(self):
        result = self._deobfuscate(
            '(Get-Variable ExecutionContext -ValueOnly).InvokeCommand'
        )
        self.assertIn('$ExecutionContext', result)
        self.assertIn('InvokeCommand', result)
        self.assertNotIn('Get-Variable', result)

    def test_where_object_wildcard_paren_wrapped_pipeline(self):
        result = self._deobfuscate(
            '(((New-Object Net.WebClient) | Get-Member) | ? { $_.Name -ilike \'Do*e\' }).Name'
        )
        self.assertEqual(result, "'DownloadFile'")

    def test_a_get_member_index_over_a_new_object_names_the_member_at_that_index(self):
        source = '(New-Object Net.WebClient | Get-Member)[6].Name'
        self._assertDeobfuscatesToOneOf(source, source, "'OpenWriteCompleted'")

    def test_where_object_wildcard_variable_type_inferred(self):
        code = (
            "$x = New-Object Net.WebClient;"
            " (($x | Get-Member) | ? { $_.Name -ilike 'Do*e' }).Name"
        )
        result = self._deobfuscate(code, remove_junk=False)
        self.assertEqual(result, cleandoc("""
            $x = New-Object Net.WebClient
            'DownloadFile'
        """))

    def test_where_object_wildcard_matches_the_members_of_its_own_bodys_write(self):
        result = self._apply(cleandoc("""
            function f {
              $q = New-Object Net.WebClient
              ($q | Get-Member | Where-Object {
                $_.Name -ilike 'Downl*g'
              }).Name
            }
        """), Ps1WildcardResolution)
        self.assertEqual(result, cleandoc("""
            function f {
              $q = New-Object Net.WebClient
              'DownloadString'
            }
        """))

    def test_where_object_wildcard_ignores_a_type_the_write_below_it_establishes(self):
        self._assertUnchanged(cleandoc("""
            ($q | Get-Member | Where-Object {
              $_.Name -ilike 'Downl*g'
            }).Name
            $q = New-Object Net.WebClient
        """), Ps1WildcardResolution)

    def test_where_object_wildcard_ignores_a_type_written_in_another_scope(self):
        self._assertUnchanged(cleandoc("""
            function f {
              $q = New-Object Net.WebClient
            }
            ($q | Get-Member | Where-Object {
              $_.Name -ilike 'Downl*g'
            }).Name
        """), Ps1WildcardResolution)


class TestPs1AWildcardIsNotMatchedPastABlockThatWritesItsCallersName(TestPs1):

    def test_a_write_a_caller_scope_block_replaces_does_not_decide_the_member_list(self):
        for source in [
            cleandoc("""
                $q = New-Object Net.WebClient
                . {
                  $q = 5
                }
                ($q | Get-Member | Where-Object {
                  $_.Name -ilike 'Downl*g'
                }).Name
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                1..3 | ForEach-Object {
                  $q = 5
                }
                ($q | Get-Member | Where-Object {
                  $_.Name -ilike 'Downl*g'
                }).Name
            """),
        ]:
            with self.subTest(source):
                self._assertUnchanged(source, Ps1WildcardResolution)

    def test_a_block_that_writes_no_such_name_leaves_the_wildcard_resolvable(self):
        result = self._apply(cleandoc("""
            $q = New-Object Net.WebClient
            . { $z = 5 }
            ($q | Get-Member | Where-Object {
              $_.Name -ilike 'Downl*g'
            }).Name
        """), Ps1WildcardResolution)
        self.assertEqual(result, cleandoc("""
            $q = New-Object Net.WebClient
            . {
              $z = 5
            }
            'DownloadString'
        """))

    def test_a_block_opening_a_scope_of_its_own_leaves_the_wildcard_resolvable(self):
        result = self._apply(cleandoc("""
            $q = New-Object Net.WebClient
            & { $q = 5 }
            ($q | Get-Member | Where-Object {
              $_.Name -ilike 'Downl*g'
            }).Name
        """), Ps1WildcardResolution)
        self.assertEqual(result, cleandoc("""
            $q = New-Object Net.WebClient
            & {
              $q = 5
            }
            'DownloadString'
        """))


class TestPs1WildcardResolution(TestPs1):

    def test_wildcard_variable_get_item(self):
        result = self._deobfuscate("(Get-Item Variable:E*t).Value")
        self.assertIn('$ExecutionContext', result)
        self.assertNotIn('Variable:', result)

    def test_wildcard_variable_ambiguous(self):
        result = self._deobfuscate("Get-Item Variable:P*")
        self.assertIn('Variable:P*', result)

    def test_wildcard_cmdlet_getcmdlets(self):
        result = self._deobfuscate(
            "& ($ExecutionContext.InvokeCommand.GetCmdlets('*w-*ct')) Net.WebClient"
        )
        self.assertEqual(result, 'New-Object Net.WebClient')

    def test_wildcard_cmdlet_invoke(self):
        result = self._deobfuscate(
            "& ($ExecutionContext.InvokeCommand.GetCmdlets.Invoke('*w-*ct')) Net.WebClient"
        )
        self.assertEqual(result, 'New-Object Net.WebClient')

    def test_invoke_on_a_script_block_runs_the_block_rather_than_naming_a_cmdlet(self):
        source = cleandoc("""
            $f = { param($n) & $n }
            $r = $f.Invoke('Get-Date')
            Write-Host ($r[0] -is [datetime])
        """)
        self._assertDeobfuscatesToOneOf(
            source,
            source,
            """
                $f = {
                  Param($n)
                  & $n
                }
                $r = $f.Invoke('Get-Date')
                Write-Host ($r[0] -Is [datetime])
            """,
        )

    @wontfix(
        'a working script never pipes a bare type literal into Get-Member to look up an instance '
        'method, because on 5.1 that finds nothing'
    )
    def test_a_member_filter_over_a_type_literal_does_not_match_the_instance_members(self):
        result = self._deobfuscate("[IO.StreamReader] | Get-Member | ? { $_.Name -ilike 'ReadT*d' }")
        self.assertNotIn('ReadToEnd', result)

    @backlog
    def test_a_member_filter_matches_the_events_get_member_lists(self):
        self._assertKept("""
            $wc = New-Object Net.WebClient
            Write-Host ($wc | Get-Member | Where-Object { $_.Name -like 'Dispos*' }).Name
        """)

    def test_a_member_filter_over_a_string_does_not_match_its_static_methods(self):
        self._assertKept("Write-Host ('abc' | Get-Member | Where-Object { $_.Name -like 'Jo*' }).Name")

    def test_wildcard_member_filter_no_space_before_operator(self):
        result = self._deobfuscate(
            cleandoc("""
                $w = New-Object Net.WebClient
                $w.(($w | Get-Member | ? { $_.Name-ilike'Downl*g' }).Name)
            """)
        )
        self.assertEqual(result, cleandoc("""
            $w = New-Object Net.WebClient
            $w.DownloadString
        """))

    def test_wildcard_where_get_command(self):
        self.assertEqual(
            self._apply("Get-Command | ? { $_.Name -ilike '*w-*ct' }", Ps1WildcardResolution),
            "Get-Command 'New-Object'",
        )

    def test_wildcard_where_unknown_source(self):
        result = self._deobfuscate("$obj | ? { $_.Name -ilike '*ts' }", remove_junk=False)
        self.assertNotIn('Exists', result)
        self.assertIn("'*ts'", result)

    def test_getcommandname_wildcard_resolved(self):
        result = self._deobfuscate(
            "$ExecutionContext.InvokeCommand.GetCommandName('*w-*ct', $True, $True)"
        )
        self.assertIn('New-Object', result)
        self.assertNotIn('GetCommandName', result)

    def test_a_command_lookup_of_a_pattern_finds_nothing(self):
        self._assertUnchanged(
            "$ExecutionContext.InvokeCommand.GetCommand('*w-*ct', 'All')", Ps1WildcardResolution)

    def test_a_command_lookup_whose_value_is_written_out_writes_the_command_and_not_its_name(self):
        self._assertUnchanged(
            "$ExecutionContext.InvokeCommand.GetCommand('New-Object', 'Cmdlet')", Ps1WildcardResolution)

    def test_childitem_variable_resolved(self):
        result = self._deobfuscate(
            "$Y = 'hello'; (ChildItem Variable:\\Y).Value"
        )
        self.assertNotIn('ChildItem', result)
        self.assertNotIn('Variable:', result)

    def test_get_variable_name_wildcard(self):
        result = self._deobfuscate("(Get-Variable '*mdr*').Name")
        self.assertIn('MaximumDriveCount', result)
        self.assertNotIn('Get-Variable', result)

    def test_get_variable_name_wildcard_indexed_join(self):
        result = self._deobfuscate_iterative(
            "(Get-Variable '*mdr*').Name[3, 11, 2] -Join ''"
        )
        self.assertIn('iex', result.lower())
        self.assertNotIn('Get-Variable', result)


class TestPs1WildcardExtra(TestPs1):

    def test_where_object_wildcard_not_over_resolved(self):
        data = "$obj.PSObject.Methods | ? { $_.Name -ilike '*ts' }"
        result = self._deobfuscate(data, remove_junk=False)
        self.assertNotIn('Exists', result)
        self.assertIn("'*ts'", result)


class TestPs1WildcardRedirections(TestPs1):

    def test_a_redirected_variable_read_is_not_rewritten_to_the_variable(self):
        self._assertUnchanged(
            'Get-Variable ExecutionContext -ValueOnly > C:\\out.txt', Ps1WildcardResolution)

    def test_a_redirected_variable_write_is_not_rewritten_to_an_assignment(self):
        self._assertUnchanged("Set-Variable x 'v' > C:\\out.txt", Ps1WildcardResolution)

    def test_an_unredirected_variable_read_is_still_rewritten(self):
        self.assertEqual(
            self._apply('Get-Variable ExecutionContext -ValueOnly', Ps1WildcardResolution),
            '$ExecutionContext',
        )

    def test_a_refused_rewrite_leaves_every_parent_pointer_true(self):
        source = 'Get-Variable ExecutionContext -ValueOnly > C:\\out.txt'
        self._assertTreeIsIntact(source, source, Ps1WildcardResolution)

    def test_a_refused_variable_write_leaves_every_parent_pointer_true(self):
        source = "Set-Variable x 'v' > C:\\out.txt"
        self._assertTreeIsIntact(source, source, Ps1WildcardResolution)


class TestPs1AWildcardRewriteKeepsAReadTheEnvironmentOwns(TestPs1):
    """
    Every rewrite above drops the arguments of the command it resolves, so a read spelled as one
    of those arguments is a read the rewrite takes with it. Under the preserving model each
    spelling below declines the rewrite; under the folding model the read folds and the rewrite
    happens, which is what says the refusal is the model's and not an inability to resolve.
    """

    def test_a_value_read_with_a_stored_argument_stays_a_command(self):
        source = """
            $env:d = 'Stop'
            $x = 1
            Write-Output (Get-Variable -Name x -ErrorAction $env:d).Value
        """
        self._assertKept(source, preserve_environment=True)
        self._assertDeobfuscatesTo(source, 'Write-Output 1')

    def test_an_item_read_with_a_stored_argument_stays_a_command(self):
        source = """
            $x = 1
            $env:d = 'Stop'
            Write-Output (Get-Item -Path variable:x -ErrorAction $env:d).Value
        """
        self._assertKept(source, preserve_environment=True)
        self._assertDeobfuscatesTo(source, 'Write-Output 1')

    def test_a_value_only_read_with_a_stored_argument_stays_a_command(self):
        source = """
            $env:d = 'Stop'
            $x = 1
            Write-Output (Get-Variable -Name x -ValueOnly -ErrorAction $env:d)
        """
        self._assertKept(source, preserve_environment=True)
        self._assertDeobfuscatesTo(source, 'Write-Output 1')

    def test_a_command_name_lookup_with_a_stored_argument_stays_a_call(self):
        source = """
            $env:d = $true
            & ($ExecutionContext.InvokeCommand.GetCommandName('New-Object', $env:d, $true)) Net.WebClient
        """
        self._assertDeobfuscatesTo(
            source,
            """
                $env:d = $True
                & ($ExecutionContext.InvokeCommand.GetCommandName('New-Object', $env:d, $True)) Net.WebClient
            """,
            preserve_environment=True,
        )
        self._assertDeobfuscatesTo(source, 'New-Object Net.WebClient')

    def test_a_set_variable_with_a_stored_argument_stays_a_command(self):
        source = """
            $env:d = 'Stop'
            Set-Variable foo 42 -ErrorAction $env:d
            Write-Output $foo
        """
        self._assertKept(source, preserve_environment=True)
        self._assertDeobfuscatesTo(source, 'Write-Output 42')

    def test_a_where_object_wildcard_over_a_stored_name_stays_a_pipeline(self):
        source = """
            $env:zq = 'ab'
            Remove-Item env:*
            Write-Output ($env:zq | Get-Member | Where-Object { $_.Name -like 'ToSt*' }).Name
        """
        self._assertDeobfuscatesTo(
            source,
            """
                $env:zq = 'ab'
                Remove-Item env:*
                Write-Output ($env:zq | Get-Member | Where-Object {
                  $_.Name -Like 'ToSt*'
                }).Name
            """,
            preserve_environment=True,
        )


class TestPs1VariableCommandScope(TestPs1):

    def test_a_scope_the_language_can_name_is_carried_onto_the_reference(self):
        for scope, rendered in (
            ('Global', '$global:y'),
            ('Script', '$script:y'),
            ('Private', '$private:y'),
            ('Local', '$y'),
        ):
            with self.subTest(scope):
                self.assertEqual(
                    self._apply(F"Set-Variable y 'b' -Scope {scope}", Ps1WildcardResolution),
                    F"{rendered} = 'b'")

    def test_a_scope_no_qualifier_reaches_declines_the_rewrite(self):
        for scope in ('1', 'Foo', '$s'):
            with self.subTest(scope):
                self._assertUnchanged(F"Set-Variable y 'b' -Scope {scope}", Ps1WildcardResolution)

    def test_a_name_written_before_the_scope_is_still_the_name(self):
        self.assertEqual(
            self._apply("Set-Variable -Scope Global y 'b'", Ps1WildcardResolution),
            "$global:y = 'b'")

    def test_the_value_of_a_parameter_is_not_part_of_the_value_assigned(self):
        self.assertEqual(
            self._apply("Set-Variable y 'b' -Scope Local", Ps1WildcardResolution),
            "$y = 'b'")

    def test_a_parameter_an_assignment_cannot_carry_declines_the_rewrite(self):
        for source in (
            "Set-Variable y 'b' -Option ReadOnly",
            "Set-Variable y 'b' -Option Constant",
            "Set-Variable y 'b' -Force",
            "Set-Variable y 'b' -PassThru",
            "Set-Variable y 'b' -Visibility Private",
            "Set-Variable y 'b' -Description 'd'",
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1WildcardResolution)

    def test_a_qualified_name_beside_a_scope_declines_the_rewrite(self):
        self._assertUnchanged("Set-Variable global:y 'b' -Scope Script", Ps1WildcardResolution)

    def test_a_read_carries_its_scope_and_declines_what_it_cannot_name(self):
        self.assertEqual(
            self._apply('$v = Get-Variable -Scope Global y -ValueOnly', Ps1WildcardResolution),
            '$v = $global:y')
        self._assertUnchanged('$v = Get-Variable y -ValueOnly -Scope 1', Ps1WildcardResolution)

    def test_the_value_property_carries_the_scope_the_ValueOnly_spelling_does(self):
        self.assertEqual(
            self._apply('(Get-Variable y -Scope Global).Value', Ps1WildcardResolution),
            '$global:y')
        self._assertUnchanged('(Get-Variable y -Scope 1).Value', Ps1WildcardResolution)

    @backlog
    def test_the_name_property_of_a_variable_the_caller_may_lack_is_not_resolved(self):
        self._assertUnchanged('(Get-Variable y -Scope 1).Name', Ps1WildcardResolution)

    def test_a_subject_bound_by_name_is_read_like_a_positional_one(self):
        for source, expected in (
            ('$v = Get-Variable -Name y -ValueOnly', '$v = $y'),
            ('(Get-Variable -Name y).Value', '$y'),
            ('(Get-Item -Path Variable:y).Value', '$y'),
            ("Set-Item -Path Variable:y -Value 'b'", "$y = 'b'"),
            ("Set-Item Variable:y -Value 'b'", "$y = 'b'"),
            ("Set-Item -Path Variable:y 'b'", "$y = 'b'"),
        ):
            with self.subTest(source):
                self.assertEqual(self._apply(source, Ps1WildcardResolution), expected)


class TestPs1NumberedVariableNames(TestPs1):

    def test_a_read_spelled_the_way_the_name_was_written_resolves(self):
        for written in ('007', '0x10', '1_000'):
            with self.subTest(written):
                result = self._deobfuscate(cleandoc(F"""
                    Set-Variable {written} 'payload'
                    ${written}
                """), remove_junk=False)
                self.assertEqual(result.strip(), "'payload'")

    def test_a_read_spelled_as_the_value_the_number_denotes_does_not_resolve(self):
        for written, denoted in (('007', '7'), ('0x10', '16'), ('1_000', '1000')):
            with self.subTest(written):
                result = self._deobfuscate(cleandoc(F"""
                    Set-Variable {written} 'payload'
                    ${denoted}
                """), remove_junk=False)
                self.assertEqual(result.strip(), F'${denoted}')

    def test_the_assignment_a_write_becomes_targets_the_text_the_number_was_written_as(self):
        for source, expected in (
            ("Set-Variable 007 'v'", "$007 = 'v'"),
            ("Set-Variable 0x10 'v'", "$0x10 = 'v'"),
            ("Set-Variable 1_000 'v'", "$1_000 = 'v'"),
            ("Set-Variable -Name 0x10 -Value 'v'", "$0x10 = 'v'"),
            ("Set-Item Variable:0x10 'v'", "$0x10 = 'v'"),
        ):
            with self.subTest(source):
                self.assertEqual(self._apply(source, Ps1WildcardResolution), expected)

    def test_the_reference_a_read_becomes_names_the_text_the_number_was_written_as(self):
        for source, expected in (
            ('$v = Get-Variable 007 -ValueOnly', '$v = $007'),
            ('$v = Get-Variable 0x10 -ValueOnly', '$v = $0x10'),
            ('$v = Get-Variable 1_000 -ValueOnly', '$v = $1_000'),
            ('(Get-Item Variable:0x10).Value', '$0x10'),
        ):
            with self.subTest(source):
                self.assertEqual(self._apply(source, Ps1WildcardResolution), expected)

    def test_the_value_property_names_what_the_ValueOnly_spelling_names(self):
        self.assertEqual(
            self._apply('$v = Get-Variable 0x10 -ValueOnly', Ps1WildcardResolution), '$v = $0x10')
        self.assertEqual(
            self._apply('(Get-Variable 0x10).Value', Ps1WildcardResolution), '$0x10')

    def test_the_name_property_is_the_text_the_number_was_written_as(self):
        self.assertEqual(
            self._apply(cleandoc("""
                Set-Variable 0x10 'v'
                (Get-Variable 0x10).Name
            """), Ps1WildcardResolution),
            cleandoc("""
                $0x10 = 'v'
                '0x10'
            """),
        )

    def test_a_pattern_matching_two_variables_stays_a_command(self):
        self._assertUnchanged(
            cleandoc("""
                $Et = 5
                Write-Output (Get-Item 'Variable:E*t').Value
            """), Ps1WildcardResolution)


class TestPs1GetCommandNameResolution(TestPs1):

    def test_the_reported_case_folds(self):
        self._assertDeobfuscatesTo(
            'Write-Output (Get-Command ???t?).Name',
            "Write-Output 'write'",
        )

    def test_one_name_value_folds_to_its_unique_vocabulary_match(self):
        for source, expected in (
            ("(gcm 'wr?te').Name", "'write'"),
            ('(gcm WRITE).Name', "'write'"),
            ('(gcm Get-Item).Name', "'Get-Item'"),
            ("(gcm -Name 'wr?te').Name", "'write'"),
        ):
            with self.subTest(source):
                self.assertEqual(self._apply(source, Ps1WildcardResolution), expected)

    def test_an_ambiguous_or_unmatched_name_stays(self):
        for source in ("(gcm '*-Item').Name", '(gcm NoSuch).Name'):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1WildcardResolution)

    def test_an_entry_beyond_the_name_binding_stays(self):
        for source in (
            "(gcm -Name 'wr?te' -CommandType Alias).Name",
            '(gcm write -CommandType Alias).Name',
            '(gcm -Verb Get).Name',
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1WildcardResolution)

    def test_a_takeover_matching_the_pattern_stays(self):
        self._assertUnchanged(cleandoc("""
            function wrnte {}
            (gcm ???t?).Name
        """), Ps1WildcardResolution)

    def test_a_takeover_of_the_lookup_command_stays(self):
        for source in (
            cleandoc("""
                function Get-Command {}
                (gcm 'wr?te').Name
            """),
            cleandoc("""
                function Get-Command {}
                (Get-Command 'wr?te').Name
            """),
            cleandoc("""
                function Get-Command {
                  'x'
                }
                & (gcm 'write') 'a'
            """),
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1WildcardResolution)

    def test_a_bound_name_no_statement_calls_still_opens_the_table(self):
        self._assertUnchanged(
            cleandoc("""
                Set-Alias wrnte Get-Date
                (gcm ???t?).Name
            """), Ps1WildcardResolution)

    def test_an_opener_before_the_read_stays(self):
        self._assertUnchanged(cleandoc("""
            iex $x
            (gcm ???t?).Name
        """), Ps1WildcardResolution)

    def test_an_opener_after_the_read_folds(self):
        self.assertEqual(
            self._apply(cleandoc("""
                (gcm ???t?).Name
                iex $x
            """), Ps1WildcardResolution),
            cleandoc("""
                'write'
                iex $x
            """),
        )

    def test_a_pure_type_mutation_does_not_open_the_command_table(self):
        self.assertEqual(
            self._apply(cleandoc("""
                (gcm ???t?).Name
                Add-Type -AssemblyName System.Xml
            """), Ps1WildcardResolution),
            cleandoc("""
                'write'
                Add-Type -AssemblyName System.Xml
            """),
        )

    def test_a_class_refuses_only_the_type_axis(self):
        self.assertEqual(
            self._apply(cleandoc("""
                class C {}
                (gcm 'wr?te').Name
                iex $x
            """), Ps1WildcardResolution),
            cleandoc("""
                class C {}
                'write'
                iex $x
            """),
        )


class TestPs1WhereObjectOverAGetCommandSource(TestPs1):

    def test_the_pattern_argument_of_the_source_filters_the_candidates(self):
        self._assertUnchanged(
            cleandoc("""
                Get-Command set-* | ? {
                  $_.Name -ilike 'g*t-item'
                }
            """), Ps1WildcardResolution)

    def test_a_value_piped_into_the_source_binds_the_name_parameter(self):
        self._assertUnchanged(
            cleandoc("""
                'set-*' | Get-Command | ? {
                  $_.Name -ilike 'g*t-item'
                }
            """), Ps1WildcardResolution)

    def test_a_shaping_parameter_on_the_source_stays(self):
        self._assertUnchanged(cleandoc("""
            Get-Command -CommandType Cmdlet 'wr?te' | ? {
              $_.Name -ilike 'wr?te'
            }
        """), Ps1WildcardResolution)

    def test_a_narrowing_one_engine_command_survives_names_it_to_the_source(self):
        for source, expected in (
            ("Get-Command | ? { $_.Name -ilike '*w-*ct' }", "Get-Command 'New-Object'"),
            ("Get-Command | ? { $_.Name -clike 'New-O*' }", "Get-Command 'New-Object'"),
            ("Get-Command | ? { $_.Name -ilike 'A?' }", "Get-Command 'A:'"),
            ("(Get-Command | ? { $_.Name -ilike '*w-*ct' }).Name", "'New-Object'"),
        ):
            with self.subTest(source):
                self.assertEqual(self._apply(source, Ps1WildcardResolution), expected)

    def test_the_command_a_narrowing_names_is_kept_as_an_object(self):
        self.assertEqual(
            self._apply(
                cleandoc("""
                    $c = Get-Command | ? { $_.Name -ilike '*w-*ct' }
                    $c.CommandType
                """),
                Ps1WildcardResolution,
            ),
            cleandoc("""
                $c = Get-Command 'New-Object'
                $c.CommandType
            """),
        )

    def test_a_listing_without_a_name_leaves_the_aliases_no_module_defines_out(self):
        for source in (
            cleandoc("""
                (Get-Command | ? {
                  $_.Name -ilike 'wr?te'
                }).Name
            """),
            cleandoc("""
                (Get-Command | ? {
                  $_.Name -clike 'new-o*'
                }).Name
            """),
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1WildcardResolution)

    def test_a_source_that_lists_one_name_twice_stays(self):
        self._assertUnchanged(
            cleandoc("""
                Get-Command wr* | ? {
                  $_.Name -ilike '*filesys*'
                }
            """), Ps1WildcardResolution)

    def test_a_takeover_of_the_source_command_stays(self):
        self._assertUnchanged(
            cleandoc("""
                function Get-Command {}
                Get-Command | ? {
                  $_.Name -ilike '*w-*ct'
                }
            """),
            Ps1WildcardResolution,
        )

    def test_a_computed_provider_path_leaves_the_table_unreadable(self):
        self._assertUnchanged(cleandoc("""
            $p = 'function:' + 'wrnte'
            Set-Item $p {
              1
            }
            (gcm ???t?).Name
        """), Ps1WildcardResolution)

    def test_a_type_mutation_before_a_get_member_source_stays(self):
        self._assertUnchanged(cleandoc("""
            Update-TypeData -TypeName Net.WebClient -MemberName DownloadString
            $q = New-Object Net.WebClient
            ($q | Get-Member | ? {
              $_.Name -ilike 'Downl*g'
            }).Name
        """), Ps1WildcardResolution)


class TestPs1ACommandLookupFoldsOnlyWhatTheSessionListsOnce(TestPs1):

    def test_a_pattern_the_session_lists_more_or_less_than_once_stays(self):
        for source in (
            "(Get-Command 'hel?*').Name",
            "(Get-Command 'gt?').Name",
            "(Get-Command 'a?').Name",
            "(Get-Command '[!x]rite').Name",
            "(Get-Command 'curl*').Name",
            "(Get-Command 'Write-FileSystemCach?').Name",
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1WildcardResolution)

    def test_a_pattern_one_engine_command_matches_folds(self):
        for source, expected in (
            ("(gcm 'mor?').Name", "'more'"),
            ("(gcm 'w`rite').Name", "'write'"),
            ("(gcm 'mkdi?').Name", "'mkdir'"),
        ):
            with self.subTest(source):
                self.assertEqual(self._apply(source, Ps1WildcardResolution), expected)

    def test_an_ambiguous_parameter_stays(self):
        self._assertUnchanged("(Get-Command -N 'wr?te').Name", Ps1WildcardResolution)

    def test_a_piped_name_stays(self):
        self._assertUnchanged("('wrnte' | Get-Command).Name", Ps1WildcardResolution)

    def test_a_lookup_run_by_the_call_operator_runs_the_command_it_lists(self):
        self.assertEqual(self._apply("& (gcm 'wr?te') 'a'", Ps1WildcardResolution), "& 'write' 'a'")
        self._assertDeobfuscatesTo("& (gcm 'wr?te') 'a'", "Write-Output 'a'")

    def test_a_lookup_run_by_the_call_operator_that_lists_nothing_stays(self):
        self._assertUnchanged("& (gcm 'zzq')", Ps1WildcardResolution)


class TestPs1AWriterOfTheCommandTableKeepsTheListingBelowIt(TestPs1):

    _READ = '(Get-Command ???t?).Name'

    _WRITERS = (
        cleandoc("""
            $a = @('functi', 'on:wr', 'nte')
            $p = $a -join ''
            Set-Item $p {
              1
            }
        """),
        cleandoc("""
            $a = @('functi', 'on:wr', 'nte')
            $p = $a -join ''
            Set-Content $p {
              1
            }
        """),
        cleandoc("""
            $a = @('functi', 'on:wr', 'nte')
            $p = $a -join ''
            Remove-Item $p
        """),
        cleandoc("""
            $a = @('ali', 'as:wr', 'nte')
            $p = $a -join ''
            Set-Content $p 'Get-Date'
        """),
        cleandoc("""
            $a = @('functi', 'on:x')
            $p = $a -join ''
            Get-Item $p | Rename-Item -NewName wrnte
        """),
        "New-PSDrive Q Function '' | Out-Null",
        "New-PSDrive -Name Q -PSProvider Alias -Root '' | Out-Null",
        "New-PSDrive -Name Q -PSProvider Microsoft.PowerShell.Core\\Function -Root '' | Out-Null",
        cleandoc("""
            $a = @('func', 'tion:')
            Set-Location ($a -join '')
        """),
        cleandoc("""
            $a = @('func', 'tion:')
            Push-Location ($a -join '')
        """),
        'Set-Location function:',
        cleandoc("""
            $ExecutionContext.InvokeProvider.Item.New('function:', 'wrnte', 'Function', {
              1
            }) | Out-Null
        """),
        cleandoc("""
            $ExecutionContext.SessionState.InvokeProvider.Item.Set('function:wrnte', {
              1
            })
        """),
        cleandoc("""
            $ExecutionContext.SessionState.PSVariable.Set('function:wrnte', {
              1
            })
        """),
        cleandoc("""
            $a = @('function:wr', 'nte')
            $ExecutionContext.SessionState.PSVariable.Set(($a -join ''), {
              1
            })
        """),
        cleandoc("""
            $s = $ExecutionContext.SessionState
            $s.InvokeProvider.Item.Set('function:wrnte', {
              1
            })
        """),
        "$env:PSModulePath = 'C:\\m;' + $env:PSModulePath",
        "[Environment]::SetEnvironmentVariable('PSModulePath', 'C:\\m;' + $env:PSModulePath)",
        "Set-Content -PSPath env:PSModulePath 'C:\\m'",
    )

    def test_a_writer_that_ran_before_the_listing_keeps_it(self):
        for writer in self._WRITERS:
            with self.subTest(writer):
                self._assertUnchanged(F'{writer}\n{self._READ}', Ps1WildcardResolution)

    def test_a_writer_that_runs_after_the_listing_does_not_keep_it(self):
        for writer in self._WRITERS:
            with self.subTest(writer):
                self.assertEqual(
                    self._apply(F'{self._READ}\n{writer}', Ps1WildcardResolution),
                    F"'write'\n{writer}",
                )

    def test_a_writer_that_takes_the_lookup_command_over_keeps_the_lookup(self):
        self._assertUnchanged(
            cleandoc("""
                $ExecutionContext.InvokeProvider.Item.Set('function:Get-Command', {
                  'x'
                })
                (Get-Command 'write').Name
            """),
            Ps1WildcardResolution,
        )

    def test_a_literal_location_in_the_function_drive_keeps_the_listing_when_eval_is_trusted(self):
        self._assertDeobfuscatesTo(
            """
                Set-Location function:
                Set-Item wrnte { 1 }
                Set-Location C:\\
                Write-Output (Get-Command ???t?).Name
            """,
            """
                Set-Location function:
                Set-Item wrnte {
                  1
                }
                Set-Location C:\\
                Write-Output (Get-Command ???t?).Name
            """,
            trust_eval=True,
        )


class TestPs1AnIntrinsicLookupFoldsWhereItsResultActsAsItsName(TestPs1):

    def test_a_lookup_whose_result_is_kept_as_an_object_stays(self):
        for source in (
            cleandoc("""
                $c = $ExecutionContext.InvokeCommand.GetCmdlets('*w-*ct')
                $c.CommandType
            """),
            cleandoc("""
                $c = $ExecutionContext.InvokeCommand.GetCommandName('*w-*ct', $True, $True)
                $c.GetType().Name
            """),
            "$ExecutionContext.InvokeCommand.GetCmdlets('*w-*ct')",
            "$ExecutionContext.InvokeCommand.GetCmdlet('New-Object')",
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1WildcardResolution)

    def test_a_lookup_that_lists_nothing_one_can_name_stays(self):
        for source in (
            "& ($ExecutionContext.InvokeCommand.GetCmdlet('New-Obj*')) Net.WebClient",
            "& ($ExecutionContext.InvokeCommand.GetCommandName('*w-*ct', $False, $True)) Net.WebClient",
            "& ($ExecutionContext.InvokeCommand.GetCommandName('*w-*ct', 0, $True)) Net.WebClient",
            cleandoc("""
                function zzNew-Object {}
                $ExecutionContext.InvokeCommand.GetCommandName('*w-*ct', $True, $True)
            """),
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1WildcardResolution)

    def test_a_lookup_run_named_or_named_again_folds_to_the_name(self):
        for source, expected in (
            (
                "& ($ExecutionContext.InvokeCommand.GetCmdlets('*w-*ct')) Net.WebClient",
                "& ('New-Object') Net.WebClient",
            ),
            (
                ". ($ExecutionContext.InvokeCommand.GetCmdlets('*w-*ct')) Net.WebClient",
                ". ('New-Object') Net.WebClient",
            ),
            (
                "Write-Output $ExecutionContext.InvokeCommand.GetCmdlet('New-Object').Name",
                "Write-Output 'New-Object'",
            ),
            (
                "$ExecutionContext.InvokeCommand.GetCmdlet("
                "$ExecutionContext.InvokeCommand.GetCommandName('*w-*ct', 1, 1)).Name",
                "'New-Object'",
            ),
            (
                "$ExecutionContext.InvokeCommand.GetCommandName('*w-*ct', '0', $True)",
                "'New-Object'",
            ),
        ):
            with self.subTest(source):
                self.assertEqual(self._apply(source, Ps1WildcardResolution), expected)

    def test_a_lookup_handed_to_a_callee_runs_the_command_it_names(self):
        self._assertDeobfuscatesTo(
            "& ($ExecutionContext.InvokeCommand.GetCmdlet("
            "$ExecutionContext.InvokeCommand.GetCommandName('*w-*ct', 1, 1))) Net.WebClient",
            'New-Object Net.WebClient',
        )


class TestPs1AMemberListingFoldsOnlyUnderANameRead(TestPs1):

    def test_a_listing_whose_objects_are_kept_stays(self):
        self._assertUnchanged(
            cleandoc("""
                $m = [string] | Get-Member -Static | ? {
                  $_.Name -ilike 'Conc?t'
                }
                $m.MemberType
            """),
            Ps1WildcardResolution,
        )

    def test_a_listing_the_view_does_not_hold_stays(self):
        for source in (
            cleandoc("""
                ('abc' | Get-Member | ? {
                  $_.Name -ilike 'Conc?t'
                }).Name
            """),
            cleandoc("""
                ('abc'.psobject.Methods | ? {
                  $_.Name -ilike 'Conc?t'
                }).Name
            """),
            cleandoc("""
                ('abc' | Get-Member -MemberType Property | ? {
                  $_.Name -ilike 'Clo?e'
                }).Name
            """),
            cleandoc("""
                ('abc' | Get-Member -Static:$false | ? {
                  $_.Name -ilike 'Conc?t'
                }).Name
            """),
            cleandoc("""
                ('abc' | Get-Member -MemberType 'Method, Property' | ? {
                  $_.Name -ilike 'Clo?e'
                }).Name
            """),
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1WildcardResolution)

    def test_a_name_read_off_a_listing_folds_to_the_member_the_view_lists_once(self):
        for source, expected in (
            ("([string] | Get-Member -Static | ? { $_.Name -ilike 'Conc?t' }).Name", "'Concat'"),
            ("('abc' | Get-Member -MemberType Method | ? { $_.Name -ilike 'Clo?e' }).Name", "'Clone'"),
            ("([datetime] | Get-Member -Static | ? { $_.Name -ilike 'MaxV*' }).Name", "'MaxValue'"),
            ("('abc'.psobject.Methods | ? { $_.Name -ilike 'get_Len*' }).Name", "'get_Length'"),
        ):
            with self.subTest(source):
                self.assertEqual(self._apply(source, Ps1WildcardResolution), expected)

    @backlog
    def test_a_property_listing_leaves_the_indexer_out(self):
        self._assertUnchanged(
            cleandoc("""
                ('abc'.psobject.Properties | ? {
                  $_.Name -ilike 'Ch*'
                }).Name
            """), Ps1WildcardResolution)

    @backlog
    def test_a_property_listing_by_member_type_leaves_the_indexer_out(self):
        self._assertUnchanged(
            cleandoc("""
                ('abc' | Get-Member -MemberType Property | ? {
                  $_.Name -ilike 'Ch*'
                }).Name
            """),
            Ps1WildcardResolution,
        )


class TestPs1AVariableListingFoldsWhereNothingWroteAMatchingName(TestPs1):

    def test_a_name_the_script_writes_before_the_listing_keeps_it(self):
        for source in (
            cleandoc("""
                $Et = 5
                Write-Output (Get-Item 'Variable:E*t').Value
            """),
            cleandoc("""
                $Et = 5
                Write-Output (Get-Variable 'E*t').Name
            """),
            cleandoc("""
                foreach ($Et in 1) {}
                Write-Output (Get-Item 'Variable:E*t').Value
            """),
            cleandoc("""
                New-Variable Et 5
                Write-Output (Get-Item 'Variable:E*t').Value
            """),
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1WildcardResolution)

    def test_a_name_the_script_writes_after_the_listing_or_in_a_function_does_not_keep_it(self):
        for source, expected in (
            (
                cleandoc("""
                    Write-Output (Get-Item 'Variable:E*t').Value
                    $Et = 5
                """),
                cleandoc("""
                    Write-Output $ExecutionContext
                    $Et = 5
                """),
            ),
            (
                cleandoc("""
                    function f {
                      $Et = 5
                    }
                    f
                    Write-Output (Get-Item 'Variable:E*t').Value
                """),
                cleandoc("""
                    function f {
                      $Et = 5
                    }
                    f
                    Write-Output $ExecutionContext
                """),
            ),
        ):
            with self.subTest(source):
                self.assertEqual(self._apply(source, Ps1WildcardResolution), expected)

    def test_a_variable_the_engine_creates_while_running_keeps_the_listing(self):
        for source in (
            "(Get-Variable 'Matc*').Name",
            cleandoc("""
                'a' -match 'a'
                (Get-Variable 'Matc*').Name
            """),
            cleandoc("""
                foreach ($i in 1) {
                  (Get-Variable 'fore*').Name
                }
            """),
            "(Get-Variable 'Thi?').Name",
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1WildcardResolution)

    def test_a_listed_variable_is_named_as_the_session_spells_it(self):
        for source, expected in (
            ("(Get-Variable 'PSHo*').Name", "'PSHOME'"),
            ("(Get-Variable 'Shel*').Name", "'ShellId'"),
        ):
            with self.subTest(source):
                self.assertEqual(self._apply(source, Ps1WildcardResolution), expected)

    def test_an_event_action_keeps_a_listing_its_variables_match(self):
        self._assertUnchanged(
            cleandoc("""
                Register-EngineEvent x -Action {
                  (Get-Item 'Variable:E*t').Value
                }
            """),
            Ps1WildcardResolution,
        )

    def test_a_listing_read_before_the_session_state_is_handed_on_folds(self):
        self.assertEqual(
            self._apply(
                "$s = $ExecutionContext.((Get-Item 'Variable:E*t').Value.GetType().Name)",
                Ps1WildcardResolution,
            ),
            '$s = $ExecutionContext.($ExecutionContext.GetType().Name)',
        )

    def test_a_write_through_the_session_state_before_the_listing_keeps_it(self):
        self._assertUnchanged(
            cleandoc("""
                $ExecutionContext.($m).PSVariable.Set($n, 5)
                Write-Output (Get-Item 'Variable:E*t').Value
            """),
            Ps1WildcardResolution,
        )

    def test_a_filter_on_the_listing_keeps_it(self):
        for source in (
            '(Get-Variable x -Exclude x).Value',
            "(Get-Item 'Variable:x' -Include y).Value",
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1WildcardResolution)


class TestPs1ABindingErrorKeepsTheVariableCommand(TestPs1):

    def test_a_command_the_binder_rejects_stays(self):
        for source in (
            "Set-Item -P 'Variable:x' 5",
            '(Get-Variable x -Bogus).Value',
            'Get-Variable x zzq -ValueOnly',
            "Set-Item Variable:x 'a' 'b'",
            "Set-Variable x 'a' 'b'",
            '(Get-Variable x -Verbose).GetType().Name',
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1WildcardResolution)

    def test_a_command_the_binder_accepts_folds(self):
        for source, expected in (
            ('Set-Variable -N x -Va 5', '$x = 5'),
            ('$y = Get-Variable x -ValueOnly', '$y = $x'),
        ):
            with self.subTest(source):
                self.assertEqual(self._apply(source, Ps1WildcardResolution), expected)

    def test_a_value_only_switch_turned_off_reads_the_variable_object(self):
        self._assertUnchanged('Get-Variable x -ValueOnly:$false', Ps1WildcardResolution)

    @backlog
    def test_a_lookup_of_a_name_the_script_never_sets_keeps_its_error(self):
        self._assertUnchanged('Write-Output (Get-Variable zzq -ValueOnly)', Ps1WildcardResolution)


class TestPs1ALookupAFunctionTakesOverIsNotReadAsTheSession(TestPs1):

    def test_a_member_listing_through_a_lister_a_function_takes_over_stays(self):
        self._assertUnchanged(cleandoc("""
            function Get-Member {
              'zzz'
            }
            ('abc' | Get-Member -MemberType Method | Where-Object {
              $_.Name -like 'Clo?e'
            }).Name
        """), Ps1WildcardResolution)

    def test_a_variable_command_a_function_takes_over_stays(self):
        for command, use in (
            ('Get-Variable', "(Get-Variable 'E*t').Value"),
            ('Get-Variable', "(gv 'E*t').Value"),
            ('Get-Variable', '$y = Get-Variable x -ValueOnly'),
            ('Get-Item', "(Get-Item 'Variable:E*t').Value"),
            ('Set-Variable', 'Set-Variable Cf 5'),
            ('Set-Item', 'Set-Item Variable:Cf 5'),
        ):
            source = cleandoc(F"""
                function {command} {{
                  'zzz'
                }}
                {use}
            """)
            with self.subTest(source):
                self._assertUnchanged(source, Ps1WildcardResolution)

    def test_a_type_mutation_before_a_variable_command_does_not_take_it_over(self):
        self.assertEqual(
            self._apply(
                cleandoc("""
                    Add-Type -AssemblyName System.Xml
                    (Get-Item 'Variable:E*t').Value
                """),
                Ps1WildcardResolution,
            ),
            cleandoc("""
                Add-Type -AssemblyName System.Xml
                $ExecutionContext
            """),
        )


class TestPs1ANarrowingFiltersOnlyOnTheNameOfTheCurrentObject(TestPs1):

    def test_a_read_of_anything_but_the_name_of_the_current_object_does_not_narrow(self):
        for source in (
            cleandoc("""
                function f {
                  ('abc' | Get-Member -MemberType Method | Where-Object {
                    $global:_.Name -ilike 'Clo?e'
                  }).Name
                }
            """),
            cleandoc("""
                ('abc' | Get-Member -MemberType Method | Where-Object {
                  $_::Name -ilike 'Clo?e'
                }).Name
            """),
            cleandoc("""
                (Get-Command | Where-Object {
                  $_::Name -ilike '*w-*ct'
                }).Name
            """),
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1WildcardResolution)


class TestPs1AVariableCommandFoldsWhereItsReplacementWritesWhatItWrites(TestPs1):

    def test_a_write_whose_output_is_used_stays_a_command(self):
        for source in (
            'Set-Variable x 5 | Out-Null',
            'Write-Output (Set-Variable x 5)',
            '$y = Set-Variable x 5',
            'Set-Item Variable:x 5 | Out-Null',
            'Write-Output (Set-Item Variable:x 5)',
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1WildcardResolution)

    def test_a_write_standing_as_a_statement_becomes_an_assignment(self):
        self.assertEqual(
            self._apply(cleandoc("""
                if ($true) {
                  Set-Variable x 5
                }
            """), Ps1WildcardResolution),
            cleandoc("""
                if ($true) {
                  $x = 5
                }
            """),
        )

    def test_a_command_input_is_piped_into_stays(self):
        for source in (
            '123 | Get-Variable x -ValueOnly',
            '123 | Set-Variable x -Value 6',
            '123 | Get-Variable ExecutionContext -ValueOnly',
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1WildcardResolution)

    def test_a_value_only_lookup_folds_where_its_output_is_collected_into_one_value(self):
        for source, expected in (
            ('Write-Output (Get-Variable x -ValueOnly).Count', 'Write-Output ($x).Count'),
            ('$y = Get-Variable x -ValueOnly', '$y = $x'),
        ):
            with self.subTest(source):
                self.assertEqual(self._apply(source, Ps1WildcardResolution), expected)

    def test_a_value_only_lookup_whose_output_the_pipeline_unrolls_stays(self):
        for source in (
            'Get-Variable x -ValueOnly',
            'Write-Output @(Get-Variable x -ValueOnly).Count',
            cleandoc("""
                Get-Variable x -ValueOnly | ForEach-Object {
                  'item'
                }
            """),
            'Write-Output $(Get-Variable x -ValueOnly).GetType().Name',
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1WildcardResolution)

    def test_a_value_only_lookup_of_a_value_the_pipeline_does_not_unroll_folds_anywhere(self):
        self.assertEqual(
            self._apply(
                cleandoc("""
                    Get-Variable ExecutionContext -ValueOnly | ForEach-Object {
                      $_.GetType().Name
                    }
                """),
                Ps1WildcardResolution,
            ),
            cleandoc("""
                $ExecutionContext | ForEach-Object {
                  $_.GetType().Name
                }
            """),
        )

    def test_an_item_write_of_a_name_holding_a_colon_stays(self):
        for source in (
            "Set-Item 'Variable:e:pathext' 5",
            "Set-Item 'Variable:global:zq' 5",
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1WildcardResolution)

    def test_a_parameter_neither_a_reference_nor_an_assignment_carries_stays(self):
        for source in (
            'Set-Item Variable:x 5 -Force',
            'Set-Item Variable:x 5 -Exclude x',
            'Set-Item Variable:x 5 -WhatIf',
            'Set-Variable x 5 -WhatIf',
            'Set-Variable x 5 -Confirm',
            'Set-Variable x 5 -Verbose',
            "Set-Variable x 5 -Description 'd'",
            "(Get-Item 'Variable:x' -Force).Value",
            '(Get-Variable x -ValueOnly:$v).Value',
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1WildcardResolution)
