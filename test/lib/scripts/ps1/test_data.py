from __future__ import annotations

import unittest

from refinery.lib.scripts.ps1 import data


class TestPs1MetadataReader(unittest.TestCase):
    """
    These exercise the reader against the shipped metadata rather than a fixture: the data is the
    genuine collected surface, and the point is that the reader's resolution agrees with it.
    """

    def test_the_schema_version_is_the_one_the_reader_expects(self):
        self.assertEqual(data._META['schema']['version'], data.SCHEMA_VERSION)
        self.assertTrue(data._META['authoritative'])

    def test_accelerators_resolve_to_their_full_type(self):
        cases = {
            'int'         : 'System.Int32',            # noqa
            'string'      : 'System.String',           # noqa
            'ref'         : 'System.Management.Automation.PSReference',
            'hashtable'   : 'System.Collections.Hashtable',
            'ipaddress'   : 'System.Net.IPAddress',    # noqa
            'scriptblock' : 'System.Management.Automation.ScriptBlock',
        }
        for accelerator, full in cases.items():
            self.assertEqual(data.resolve_type(accelerator), full, accelerator)

    def test_a_parser_type_keyword_resolves_although_no_host_reports_it(self):
        # `[ordered]` is understood in a cast position but was never registered as an accelerator,
        # so a collection run on real Windows PowerShell does not report it however authoritative
        # the host is. Leaving it unresolved made the language's most common hashtable idiom
        # unremovable, since a cast is granted purity only when its target type resolves.
        self.assertEqual(
            data.resolve_type('ordered'), 'System.Collections.Specialized.OrderedDictionary')
        self.assertNotIn('ordered', data._TYPES['accelerators'])

    def test_a_qualified_name_resolves_without_the_system_prefix(self):
        self.assertEqual(data.resolve_type('Net.WebClient'), 'System.Net.WebClient')
        self.assertEqual(data.resolve_type('System.Net.WebClient'), 'System.Net.WebClient')

    def test_a_mixed_case_accelerator_resolves(self):
        # The accelerator table is keyed in the casing PowerShell reports, which is mixed; resolving
        # one has to be case-insensitive or every capital-lettered accelerator silently fails.
        self.assertEqual(
            data.resolve_type('CimSession'), 'Microsoft.Management.Infrastructure.CimSession')
        self.assertEqual(
            data.resolve_type('X509Certificate'),
            'System.Security.Cryptography.X509Certificates.X509Certificate',
        )

    def test_a_generic_name_resolves_to_its_open_definition(self):
        self.assertEqual(
            data.resolve_type('Collections.Generic.List[int]'),
            'System.Collections.Generic.List`1',
        )
        self.assertEqual(
            data.resolve_type('System.Collections.Generic.Dictionary[string, object]'),
            'System.Collections.Generic.Dictionary`2',
        )

    def test_a_name_that_is_not_a_type_does_not_resolve(self):
        self.assertIsNone(data.resolve_type('NotARealType'))
        self.assertIsNone(data.resolve_type('q[1]'))
        self.assertIsNone(data.resolve_type(''))

    def test_canonical_type_is_resolve_type(self):
        self.assertEqual(data.canonical_type('int'), data.resolve_type('int'))

    def test_an_explicit_interface_member_is_present_with_its_type(self):
        # System.Array's Count comes from ICollection and is invisible to a bare GetProperties.
        members = data.type_members('array')
        self.assertIsNotNone(members)
        self.assertIn('Count', members)
        self.assertEqual(members['Count']['type'], 'System.Int32')
        self.assertEqual(members['Count']['source'], 'reflection')

    def test_an_extended_type_system_member_is_marked_as_such(self):
        # Process.Path is a ScriptProperty from types.ps1xml; reflection never reports it, and a
        # later purity gate must be able to tell it from a plain property.
        members = data.type_members('System.Diagnostics.Process')
        self.assertIsNotNone(members)
        self.assertEqual(members['Path']['kind'], 'ets_script_property')
        self.assertEqual(members['Path']['source'], 'ets')

    def test_member_order_is_present_for_a_type_with_an_instance(self):
        order = data.member_order('System.String')
        self.assertIsNotNone(order)
        self.assertIn('Length', order)

    def test_member_order_is_absent_for_a_type_without_an_instance(self):
        # SecurityProtocolType has no instance expression, so its Get-Member order was not observed.
        self.assertIsNone(data.member_order('System.Net.SecurityProtocolType'))

    def test_member_record_distinguishes_uncollected_from_absent(self):
        # The two negative outcomes a purity gate must treat oppositely: nothing is known about an
        # uncollected type's surface (unsafe to read), whereas a collected type that lacks a member
        # yields $null (safe). A single None return would conflate them.
        self.assertIs(data.member_record('NotARealType', 'Anything'), data.MemberLookup.UNCOLLECTED)
        self.assertIs(data.member_record('System.String', 'NotAMember'), data.MemberLookup.ABSENT)
        self.assertIsNot(data.MemberLookup.UNCOLLECTED, data.MemberLookup.ABSENT)

    def test_member_record_returns_the_member_and_marks_its_source(self):
        # Process.Path is a types.ps1xml ScriptProperty that runs code; Process.ProcessName is a
        # plain reflection property. The record's source is what a gate reads to tell them apart.
        ets = data.member_record('System.Diagnostics.Process', 'Path')
        reflected = data.member_record('System.Diagnostics.Process', 'ProcessName')
        self.assertEqual(ets['source'], 'ets')
        self.assertEqual(reflected['source'], 'reflection')

    def test_member_record_matches_case_insensitively(self):
        # PowerShell resolves both type and member names without regard to case, and a type oracle
        # hands this query a lowercased canonical name; the first case-insensitive match is returned,
        # and it is the same record the full member table exposes.
        record = data.member_record('system.diagnostics.process', 'PATH')
        self.assertIs(record, data.type_members('System.Diagnostics.Process')['Path'])

    def test_a_command_carries_its_module_and_common_flag(self):
        gci = data.command('Get-ChildItem')
        self.assertIsNotNone(gci)
        self.assertEqual(gci['module'], 'Microsoft.PowerShell.Management')
        self.assertIn('Path', gci['parameters'])
        self.assertFalse(gci['parameters']['Path']['common'])
        self.assertTrue(gci['parameters']['ErrorAction']['common'])

    def test_a_command_resolves_case_insensitively(self):
        # PowerShell resolves command names without regard to case, and an obfuscated script may
        # write any casing; the lookup must not depend on the collected PascalCase key.
        self.assertIsNotNone(data.command('get-childitem'))
        self.assertEqual(data.command('GET-CHILDITEM'), data.command('Get-ChildItem'))

    def test_an_unknown_command_is_none(self):
        self.assertIsNone(data.command('Definitely-NotACommand'))

    def test_a_command_only_a_later_powershell_ships_is_absent(self):
        # Measured on a live 5.1 host: `Get-Command Get-Error` reports CommandNotFoundException,
        # where every name below resolves. A table that answered for a command the host cannot run
        # resolves a call onto nothing, which is the defect a bogus alias entry has as well.
        self.assertIsNone(data.command('Get-Error'))
        self.assertNotIn('get-error', data.KNOWN_CMDLETS)
        for present in ('Get-Item', 'Get-Member', 'Get-Variable', 'Get-ChildItem'):
            self.assertIsNotNone(data.command(present), present)

    @unittest.expectedFailure
    def test_the_command_table_answers_for_no_command_the_host_lacks(self):
        """
        A recorded defect rather than a law that holds. The leaked record is inert where a leaked
        *alias* is not — nothing rewrites a name into `Format-Hex`, so it costs a canonical spelling
        and not a resolution — and taking a record out of the shipped capture is a change to the
        capture, which is its own piece of work. This states what that work has to make true.
        """
        # Measured three ways on the 5.1 host the capture itself cites (5.1.26100.8875, Desktop):
        # `Get-Command Format-Hex` reports CommandNotFoundException, `'ab' | Format-Hex` throws, and
        # Microsoft.PowerShell.Utility exports only Format-Custom, Format-List, Format-Table and
        # Format-Wide. The collected record describes PowerShell 7's cmdlet — a `Raw` switch and a
        # `System.String` `Encoding` — and the loaded Utility module reports 7.0.0.0, so the capture
        # read it from a shadowing 7.0 module rather than from the host it declares itself
        # authoritative for.
        self.assertIsNone(data.command('Format-Hex'))
        self.assertNotIn('format-hex', data.KNOWN_CMDLETS)

    def test_the_two_names_help_is_reachable_under_are_both_commands(self):
        # Measured: `help` is a function on 5.1 and both `help` and `Get-Help` resolve. The bare
        # name being a command of its own is what keeps the implicit `Get-` retry from turning a
        # call to `help` into a call to `Get-Help`.
        self.assertIn('help', data.KNOWN_CMDLETS)
        self.assertIn('get-help', data.KNOWN_CMDLETS)
        self.assertIsNone(data.KNOWN_ALIAS.get('help'))

    def test_command_output_types_are_declared_and_lowercased(self):
        # Get-Date carries [OutputType([datetime], [string])]; the query lowercases the declared
        # full names. Get-Command declares PSObject among its outputs, which is why a later gate
        # cannot prove (Get-Command).Name pure — a PSObject read is a dynamic adapter lookup.
        self.assertEqual(
            data.command_output_types('Get-Date'),
            frozenset({'system.datetime', 'system.string'}),
        )
        self.assertIn(
            'system.management.automation.psobject',
            data.command_output_types('Get-Command'),
        )
        self.assertEqual(
            data.command_output_types('get-date'), data.command_output_types('Get-Date'))

    def test_command_output_types_are_none_when_undeclared(self):
        # Out-Null and Write-Host emit (or suppress) without an [OutputType] attribute, so their
        # output_types list is empty by absence, not by promise; reading that as "emits nothing"
        # is the fail-open shape the declared flag exists to prevent. An unknown command is None too.
        self.assertIsNone(data.command_output_types('Out-Null'))
        self.assertIsNone(data.command_output_types('Write-Host'))
        self.assertIsNone(data.command_output_types('Definitely-NotACommand'))

    def test_static_overloads_report_the_out_parameter_direction(self):
        # The two-argument TryParse marks its result parameter as a by-reference out; the purity
        # layer reads exactly this flag to know a `[Int]::TryParse($s, $r)` writes back through $r.
        overloads = data.static_overloads('int', 'TryParse')
        self.assertTrue(overloads)
        self.assertTrue(all(overload['static'] for overload in overloads))
        two = [overload for overload in overloads if len(overload['parameters']) == 2]
        self.assertEqual(len(two), 1)
        self.assertTrue(two[0]['parameters'][1]['byref'])

    def test_static_overloads_are_case_insensitive_and_static_only(self):
        self.assertTrue(data.static_overloads('INT', 'tryparse'))
        # TryGetValue is an instance method; the static view excludes it, since a [Type]::Member
        # call could never reach it.
        self.assertEqual(
            data.static_overloads('Collections.Generic.Dictionary[string, object]', 'TryGetValue'),
            [],
        )
        self.assertEqual(data.static_overloads('NotARealType', 'X'), [])
        self.assertEqual(data.static_overloads('int', 'NotAMember'), [])


class TestPs1MetadataViews(unittest.TestCase):
    """
    The historical view tables the deobfuscation transforms still read must stay well-formed.
    """

    def test_the_views_are_populated(self):
        self.assertGreater(len(data.TYPE_MEMBERS), 500)
        self.assertGreater(len(data.KNOWN_CMDLETS), 1000)
        self.assertGreater(len(data.ALL_PARAMETER_NAMES), 1000)

    def test_a_type_member_view_is_lowercased_and_canonical(self):
        members = data.MEMBER_LOOKUP['system.string']
        self.assertEqual(members['substring'], 'Substring')

    def test_common_parameters_are_excluded_from_the_parameter_views(self):
        # ALL_PARAMETER_NAMES drives a command-independent casing rewrite; the common parameters
        # are deliberately kept out of it.
        self.assertNotIn('erroraction', data.ALL_PARAMETER_NAMES)
        self.assertNotIn('verbose', data.ALL_PARAMETER_NAMES)

    def test_an_enum_view_lists_its_values_not_its_object_methods(self):
        members = data.TYPE_MEMBERS['system.net.securityprotocoltype']
        self.assertIn('Tls12', members)
        self.assertNotIn('GetType', members)

    def test_property_types_resolve_a_member_result_type(self):
        self.assertEqual(data.PROPERTY_TYPES[('system.array', 'length')], 'system.int32')
        self.assertEqual(data.PROPERTY_TYPES[('system.array', 'count')], 'system.int32')

    def test_module_provided_cim_aliases_are_present(self):
        # A pristine Get-Alias drops these module short forms; they are supplied so that a sample
        # using gcim/icim is still de-aliased to its (collected) target cmdlet.
        self.assertEqual(data.KNOWN_ALIAS['gcim'], 'Get-CimInstance')
        self.assertEqual(data.KNOWN_ALIAS['icim'], 'Invoke-CimMethod')
        self.assertIn('get-ciminstance', data.KNOWN_CMDLETS)

    def test_no_bare_noun_the_implicit_get_retry_reaches_is_bound_as_an_alias(self):
        # Measured: `Get-Alias` reports ItemNotFoundException for each of these names while it finds
        # `iex`. A name held here outranks a script's own function of that name, so recording one
        # rewrites a call to the script's function into a call to a cmdlet.
        nouns = frozenset({'childitem', 'item', 'member', 'variable', 'gerr', 'fhx'})
        self.assertEqual(nouns.intersection(data.KNOWN_ALIAS), frozenset())
        self.assertEqual(data.KNOWN_ALIAS['iex'], 'Invoke-Expression')

    def test_the_scope_only_pscmdlet_variable_type_is_present(self):
        self.assertEqual(
            data.VARIABLE_TYPES['pscmdlet'], 'system.management.automation.psscriptcmdlet')

    def test_common_parameters_carry_the_out_variable_aliases(self):
        # The common parameters are excluded from CMDLET_PARAMETERS; this is the one view that keeps
        # them, and the out-variable purity check reads their aliases from here rather than
        # hardcoding the set.
        self.assertIn('ov', data.COMMON_PARAMETERS['outvariable'])
        self.assertIn('ev', data.COMMON_PARAMETERS['errorvariable'])
        self.assertIn('erroraction', data.COMMON_PARAMETERS)
        self.assertNotIn('path', data.COMMON_PARAMETERS)


if __name__ == '__main__':
    unittest.main()
