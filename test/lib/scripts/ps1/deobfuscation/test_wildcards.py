from __future__ import annotations

from inspect import cleandoc

from test import backlog, blocker, todo, wontfix
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
        result = self._deobfuscate("Set-Variable 0 'hello'\n$0")
        self.assertIn('hello', result)
        self.assertNotIn('Set-Variable', result)

    def test_get_variable_value_only_resolved(self):
        result = self._deobfuscate('Get-Variable ExecutionContext -ValueOnly')
        self.assertEqual(result.strip(), '$ExecutionContext')

    def test_get_variable_value_only_abbreviated(self):
        result = self._deobfuscate('Get-Variable Cf -ValueO')
        self.assertEqual(result.strip(), '$Cf')

    def test_get_variable_value_abbreviated_short(self):
        for switch in ('-V', '-Va', '-Val', '-Valu', '-Value', '-ValueO', '-ValueOn', '-ValueOnl', '-ValueOnly'):
            with self.subTest(switch=switch):
                result = self._deobfuscate(F'Get-Variable Cf {switch}')
                self.assertEqual(result.strip(), '$Cf')

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
            '((New-Object Net.WebClient) | Get-Member) | ? { $_.Name -ilike \'Do*e\' }'
        )
        self.assertIn('DownloadFile', result)
        self.assertNotIn('Do*e', result)

    @blocker
    def test_a_get_member_index_over_a_new_object_names_the_member_at_that_index(self):
        source = '(New-Object Net.WebClient | Get-Member)[6].Name'
        self._assertDeobfuscatesToOneOf(source, source, "'OpenWriteCompleted'")

    def test_where_object_wildcard_variable_type_inferred(self):
        code = (
            "$x = New-Object Net.WebClient;"
            " ($x | Get-Member) | ? { $_.Name -ilike 'Do*e' }"
        )
        result = self._deobfuscate(code, remove_junk=False)
        self.assertIn('DownloadFile', result)
        self.assertNotIn('Do*e', result)

    def test_where_object_wildcard_matches_the_members_of_its_own_bodys_write(self):
        result = self._apply(cleandoc("""
            function f {
              $q = New-Object Net.WebClient
              $q | Get-Member | Where-Object {
                $_.Name -ilike 'Downl*g'
              }
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
            $q | Get-Member | Where-Object {
              $_.Name -ilike 'Downl*g'
            }
            $q = New-Object Net.WebClient
        """), Ps1WildcardResolution)

    def test_where_object_wildcard_ignores_a_type_written_in_another_scope(self):
        self._assertUnchanged(cleandoc("""
            function f {
              $q = New-Object Net.WebClient
            }
            $q | Get-Member | Where-Object {
              $_.Name -ilike 'Downl*g'
            }
        """), Ps1WildcardResolution)


class TestPs1AWildcardIsNotMatchedPastABlockThatWritesItsCallersName(TestPs1):

    def test_a_write_a_caller_scope_block_replaces_does_not_decide_the_member_list(self):
        for source in [
            cleandoc("""
                $q = New-Object Net.WebClient
                . {
                  $q = 5
                }
                $q | Get-Member | Where-Object {
                  $_.Name -ilike 'Downl*g'
                }
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                1..3 | ForEach-Object {
                  $q = 5
                }
                $q | Get-Member | Where-Object {
                  $_.Name -ilike 'Downl*g'
                }
            """),
        ]:
            with self.subTest(source):
                self._assertUnchanged(source, Ps1WildcardResolution)

    def test_a_block_that_writes_no_such_name_leaves_the_wildcard_resolvable(self):
        result = self._apply(cleandoc("""
            $q = New-Object Net.WebClient
            . { $z = 5 }
            $q | Get-Member | Where-Object {
              $_.Name -ilike 'Downl*g'
            }
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
            $q | Get-Member | Where-Object {
              $_.Name -ilike 'Downl*g'
            }
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

    @todo
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

    def test_wildcard_member_filter_no_space_before_operator(self):
        result = self._deobfuscate(
            '$w = New-Object Net.WebClient\n'
            "$w.(($w | Get-Member | ? { $_.Name-ilike'Downl*g' }).Name)"
        )
        self.assertEqual(result, '$w = New-Object Net.WebClient\n$w.DownloadString')

    def test_wildcard_where_get_command(self):
        result = self._deobfuscate("Get-Command | ? { $_.Name -ilike '*w-*ct' }")
        self.assertIn('New-Object', result)

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

    def test_getcommand_wildcard_resolved(self):
        result = self._deobfuscate(
            "$ExecutionContext.InvokeCommand.GetCommand('*w-*ct', 'All')"
        )
        self.assertIn('New-Object', result)
        self.assertNotIn('GetCommand', result)

    def test_getcommand_exact_name_resolved(self):
        result = self._deobfuscate(
            "$ExecutionContext.InvokeCommand.GetCommand('New-Object', 'Cmdlet')"
        )
        self.assertIn('New-Object', result)
        self.assertNotIn('GetCommand', result)

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
            'Get-Variable payload -ValueOnly > C:\\out.txt', Ps1WildcardResolution)

    def test_a_redirected_variable_write_is_not_rewritten_to_an_assignment(self):
        self._assertUnchanged("Set-Variable x 'v' > C:\\out.txt", Ps1WildcardResolution)

    def test_an_unredirected_variable_read_is_still_rewritten(self):
        self.assertEqual(
            self._apply('Get-Variable payload -ValueOnly', Ps1WildcardResolution), '$payload')

    def test_a_refused_rewrite_leaves_every_parent_pointer_true(self):
        source = 'Get-Variable payload -ValueOnly > C:\\out.txt'
        self._assertTreeIsIntact(source, source, Ps1WildcardResolution)

    def test_a_refused_variable_write_leaves_every_parent_pointer_true(self):
        source = "Set-Variable x 'v' > C:\\out.txt"
        self._assertTreeIsIntact(source, source, Ps1WildcardResolution)


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
            self._apply("Set-Variable y 'b' -Description 'd'", Ps1WildcardResolution),
            "$y = 'b'")

    def test_a_parameter_an_assignment_cannot_carry_declines_the_rewrite(self):
        for source in (
            "Set-Variable y 'b' -Option ReadOnly",
            "Set-Variable y 'b' -Option Constant",
            "Set-Variable y 'b' -Force",
            "Set-Variable y 'b' -PassThru",
            "Set-Variable y 'b' -Visibility Private",
        ):
            with self.subTest(source):
                self._assertUnchanged(source, Ps1WildcardResolution)

    def test_a_qualified_name_beside_a_scope_declines_the_rewrite(self):
        self._assertUnchanged("Set-Variable global:y 'b' -Scope Script", Ps1WildcardResolution)

    def test_a_read_carries_its_scope_and_declines_what_it_cannot_name(self):
        self.assertEqual(
            self._apply('Get-Variable -Scope Global y -ValueOnly', Ps1WildcardResolution),
            '$global:y')
        self._assertUnchanged('Get-Variable y -ValueOnly -Scope 1', Ps1WildcardResolution)

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
            ('Get-Variable -Name y -ValueOnly', '$y'),
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
                self.assertEqual(result.strip(), cleandoc(F"""
                    ${written} = 'payload'
                    ${denoted}
                """))

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
            ('Get-Variable 007 -ValueOnly', '$007'),
            ('Get-Variable 0x10 -ValueOnly', '$0x10'),
            ('Get-Variable 1_000 -ValueOnly', '$1_000'),
            ('(Get-Item Variable:0x10).Value', '$0x10'),
        ):
            with self.subTest(source):
                self.assertEqual(self._apply(source, Ps1WildcardResolution), expected)

    def test_the_value_property_names_what_the_ValueOnly_spelling_names(self):
        self.assertEqual(
            self._apply('Get-Variable 0x10 -ValueOnly', Ps1WildcardResolution), '$0x10')
        self.assertEqual(
            self._apply('(Get-Variable 0x10).Value', Ps1WildcardResolution), '$0x10')

    def test_the_name_property_is_the_text_the_number_was_written_as(self):
        self.assertEqual(
            self._apply("Set-Variable 0x10 'v'\n(Get-Variable 0x10).Name", Ps1WildcardResolution),
            "$0x10 = 'v'\n'0x10'",
        )
