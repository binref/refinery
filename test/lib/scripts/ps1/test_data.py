from __future__ import annotations

import unittest

from refinery.lib.scripts.ps1 import data


def _definition_of(resolved) -> str | None:
    return None if resolved is None else resolved.definition


def _ranks(name: str) -> tuple[int, ...] | None:
    resolved = data.resolve_type(name)
    return None if resolved is None else resolved.ranks


def _definition(name: str) -> str | None:
    """
    The reflection `FullName` of the type a source name resolves to, which is what the collected
    table is keyed by. `resolve_type` answers a `Ps1TypeName`, so the key is read off it rather than
    compared against a spelling — a name and a spelling of a name are the thing this module exists to
    keep apart.
    """
    resolved = data.resolve_type(name)
    return None if resolved is None else resolved.definition


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
            self.assertEqual(_definition(accelerator), full, accelerator)

    def test_a_parser_type_keyword_resolves_although_no_host_reports_it(self):
        # `[ordered]` is understood in a cast position but was never registered as an accelerator,
        # so a collection run on real Windows PowerShell does not report it however authoritative
        # the host is. Leaving it unresolved made the language's most common hashtable idiom
        # unremovable, since a cast is granted purity only when its target type resolves.
        self.assertEqual(
            _definition('ordered'), 'System.Collections.Specialized.OrderedDictionary')
        self.assertNotIn('ordered', data._TYPES['accelerators'])

    def test_a_qualified_name_resolves_without_the_system_prefix(self):
        self.assertEqual(_definition('Net.WebClient'), 'System.Net.WebClient')
        self.assertEqual(_definition('System.Net.WebClient'), 'System.Net.WebClient')

    def test_a_mixed_case_accelerator_resolves(self):
        # The accelerator table is keyed in the casing PowerShell reports, which is mixed; resolving
        # one has to be case-insensitive or every capital-lettered accelerator silently fails.
        self.assertEqual(
            _definition('CimSession'), 'Microsoft.Management.Infrastructure.CimSession')
        self.assertEqual(
            _definition('X509Certificate'),
            'System.Security.Cryptography.X509Certificates.X509Certificate',
        )

    def test_a_generic_name_resolves_to_its_open_definition(self):
        self.assertEqual(
            _definition('Collections.Generic.List[int]'),
            'System.Collections.Generic.List`1',
        )
        self.assertEqual(
            _definition('System.Collections.Generic.Dictionary[string, object]'),
            'System.Collections.Generic.Dictionary`2',
        )

    def test_a_name_that_is_not_a_type_does_not_resolve(self):
        self.assertIsNone(data.resolve_type('NotARealType'))
        self.assertIsNone(data.resolve_type('q[1]'))
        self.assertIsNone(data.resolve_type(''))

    def test_canonical_type_is_resolve_type(self):
        self.assertEqual(data.canonical_type('int'), data.resolve_type('int'))

    def test_the_array_accelerator_is_not_the_array_type_a_cast_to_it_produces(self):
        """
        A non-empty `ranks` is what makes a name an array type, and the accelerator `array` is where
        that parts company with the cast written using it: `array` names `System.Array`, which is
        not an array of anything, while `[array]5` yields a `System.Object[]`, which is. A predicate
        reading `ranks` therefore answers `False` for `[array]` and `True` for the cast's result.
        """
        self.assertEqual(_definition('array'), 'System.Array')
        self.assertEqual(_ranks('array'), ())
        self.assertEqual(_ranks('byte[]'), (1,))
        self.assertEqual(_ranks('System.Object[]'), (1,))
        # Measured on 5.1: `$t = [array]5` leaves $t a System.Object[] that prints 5 and counts 1.
        cast = data.conversion_outcome('array', 'System.Int32')
        assert cast is not None
        self.assertEqual(cast.single_type, data.resolve_type('System.Object[]'))

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

    def test_the_command_table_answers_for_no_command_the_host_lacks(self):
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
        self.assertNotIn('help', data.KNOWN_ALIAS)

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
        # output_types is None by absence, not a promise of "emits nothing". An unknown command is
        # None too.
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
    The tables the deobfuscation transforms read must stay well-formed.
    """

    def test_the_views_are_populated(self):
        self.assertGreater(len(data.CANONICAL_TYPE_NAMES), 500)
        self.assertGreater(len(data.KNOWN_CMDLETS), 1000)
        self.assertGreater(len(data.ALL_PARAMETER_NAMES), 1000)

    def test_a_member_is_reported_in_the_casing_the_metadata_records(self):
        self.assertEqual(data.canonical_member('string', 'substring'), 'Substring')

    def test_common_parameters_are_excluded_from_the_parameter_views(self):
        # ALL_PARAMETER_NAMES drives a command-independent casing rewrite; the common parameters
        # are deliberately kept out of it.
        self.assertNotIn('erroraction', data.ALL_PARAMETER_NAMES)
        self.assertNotIn('verbose', data.ALL_PARAMETER_NAMES)

    def test_an_enum_view_lists_its_values_not_its_object_methods(self):
        members = data.member_names('Net.SecurityProtocolType')
        assert members is not None
        self.assertIn('Tls12', members)
        self.assertNotIn('GetType', members)

    def test_a_member_result_type_resolves(self):
        self.assertEqual(_definition_of(data.resolve_member_type('System.Array', 'Length')),
                         'System.Int32')
        self.assertEqual(_definition_of(data.resolve_member_type('System.Array', 'Count')),
                         'System.Int32')

    def test_an_array_answers_a_member_off_the_array_and_not_off_its_element_type(self):
        self.assertEqual(_definition_of(data.resolve_member_type('char[]', 'Rank')), 'System.Int32')
        self.assertIsNone(data.resolve_member_type('char', 'Rank'))

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

    def test_the_engine_enum_the_capture_lacks_has_the_surface_the_capture_gives_an_enum(self):
        """
        `ActionPreference` is supplied beside the capture, and `ConfirmImpact` — its sibling in the
        engine, which the capture does report — is the control: reflection gives every enum the
        instance surface of `System.Enum`, its `value__` and one static field per member, so the
        two records agree everywhere but in the members they name.
        """
        engine = data.type_members('System.Management.Automation.ActionPreference')
        captured = data.type_members('System.Management.Automation.ConfirmImpact')
        assert engine is not None and captured is not None

        def own_fields(members: dict[str, dict]) -> dict[str, dict]:
            return {
                name: record for name, record in members.items()
                if record['kind'] == 'field' and record['static']
            }

        def shared_surface(members: dict[str, dict]) -> dict[str, dict]:
            own = own_fields(members)
            return {name: record for name, record in members.items() if name not in own}

        self.assertEqual(shared_surface(engine), shared_surface(captured))
        self.assertEqual(
            set(own_fields(engine)),
            {'SilentlyContinue', 'Stop', 'Continue', 'Inquire', 'Ignore', 'Suspend'},
        )
        for record in own_fields(engine).values():
            self.assertEqual(record['type'], 'System.Management.Automation.ActionPreference')
        self.assertTrue(data.type_is_sealed('System.Management.Automation.ActionPreference'))
        self.assertTrue(data.is_assignable_to(
            'System.Management.Automation.ActionPreference', 'System.Enum'))

    def test_the_captured_type_table_is_not_where_the_engine_enum_is_supplied(self):
        self.assertNotIn('System.Management.Automation.ActionPreference', data._TYPES['types'])

    def test_an_enum_member_is_read_by_name_and_by_ordinal(self):
        enum = 'System.Management.Automation.ActionPreference'
        self.assertTrue(data.is_enum(enum))
        self.assertTrue(data.is_enum('Management.Automation.ConfirmImpact'))
        self.assertFalse(data.is_enum('int'))
        self.assertFalse(data.is_enum('System.Enum'))
        self.assertEqual(data.enum_ordinal(enum, 'silentlycontinue'), 0)
        self.assertEqual(data.enum_ordinal(enum, 'Stop'), 1)
        self.assertIsNone(data.enum_ordinal(enum, 'Break'))
        self.assertEqual(data.enum_name(enum, 2), 'Continue')
        self.assertIsNone(data.enum_name(enum, 6))
        self.assertIsNone(data.enum_name(enum, True))
        self.assertEqual(data.enum_ordinal('System.Management.Automation.ConfirmImpact', 'High'), 3)
        self.assertIsNone(data.enum_ordinal('int', 'Stop'))
        self.assertIsNone(data.enum_name('int', 1))

    def test_an_ordinal_two_members_hold_spells_neither_of_them(self):
        policy = 'Microsoft.PowerShell.ExecutionPolicy'
        self.assertEqual(data.enum_ordinal(policy, 'Default'), 3)
        self.assertEqual(data.enum_ordinal(policy, 'Restricted'), 3)
        self.assertIsNone(data.enum_name(policy, 3))
        self.assertEqual(data.enum_name(policy, 0), 'Unrestricted')

    def test_an_enum_stores_its_ordinals_at_the_width_of_its_value_field(self):
        self.assertEqual(
            data.enum_storage('System.Management.Automation.ActionPreference'), 'System.Int32')
        self.assertEqual(data.enum_storage('System.Security.SecurityRuleSet'), 'System.Byte')
        self.assertIsNone(data.enum_storage('int'))

    def test_common_parameters_carry_the_out_variable_aliases(self):
        # The common parameters are excluded from CMDLET_PARAMETERS; this is the one view that keeps
        # them, and the out-variable purity check reads their aliases from here rather than
        # hardcoding the set.
        self.assertIn('ov', data.COMMON_PARAMETERS['outvariable'])
        self.assertIn('ev', data.COMMON_PARAMETERS['errorvariable'])
        self.assertIn('erroraction', data.COMMON_PARAMETERS)
        self.assertNotIn('path', data.COMMON_PARAMETERS)


class TestPs1TypeIdentity(unittest.TestCase):
    """
    `is_type` decides whether two names denote one type, and every gate that acts on a specific type
    rests on it.
    """

    def test_an_accelerator_and_the_full_name_are_one_type(self):
        self.assertTrue(data.is_type('int', 'System.Int32'))
        self.assertTrue(data.is_type('System.Int32', 'int'))

    def test_the_prefix_the_name_omits_does_not_change_the_type(self):
        self.assertTrue(data.is_type('Net.WebClient', 'System.Net.WebClient'))

    def test_case_does_not_change_the_type(self):
        self.assertTrue(data.is_type('system.CONVERT', 'System.Convert'))

    def test_an_assembly_qualification_does_not_change_the_type(self):
        self.assertTrue(data.is_type('System.Int32, mscorlib', 'System.Int32'))

    def test_whitespace_inside_the_name_does_not_change_the_type(self):
        self.assertTrue(data.is_type('System. Text . Encoding', 'System.Text.Encoding'))

    def test_two_spellings_of_an_array_are_one_type(self):
        self.assertTrue(data.is_type('byte[]', 'System.Byte[]'))
        self.assertTrue(data.is_type('Byte[]', 'byte[]'))

    def test_an_array_is_not_its_element_type(self):
        self.assertFalse(data.is_type('byte[]', 'System.Byte'))
        self.assertFalse(data.is_type('System.Byte', 'byte[]'))

    def test_an_array_of_one_element_type_is_not_an_array_of_another(self):
        self.assertFalse(data.is_type('byte[]', 'char[]'))

    def test_two_different_types_are_not_one_type(self):
        self.assertFalse(data.is_type('System.Convert', 'System.Text.Encoding'))

    def test_a_name_that_does_not_resolve_is_not_any_type_including_itself(self):
        self.assertFalse(data.is_type('NotARealType', 'NotARealType'))
        self.assertFalse(data.is_type('System.Int32', 'NotARealType'))


class TestPs1AbbreviatedParameter(unittest.TestCase):
    """
    The full parameter name a prefix binds on a cmdlet, measured on 5.1: a prefix unique among the
    cmdlet's own parameters expands to it, one shared by two or more of them is ambiguous and binds
    nothing, and a common parameter answers only where no own parameter is a prefix at all.
    """

    def test_a_prefix_unique_among_own_parameters_expands(self):
        self.assertEqual(data.abbreviated_parameter('New-Item', 'p'), 'Path')

    def test_a_prefix_shared_by_two_own_parameters_binds_nothing(self):
        for command in ('Copy-Item', 'Set-Content', 'Get-ChildItem', 'Move-Item'):
            with self.subTest(command):
                self.assertIsNone(data.abbreviated_parameter(command, 'p'))

    def test_an_own_ambiguity_is_not_reached_past_to_a_common_parameter(self):
        """
        5.1 rejects `Copy-Item x y -p` as ambiguous between `Path` and `PassThru`; reading own
        ambiguity as a licence to expand the common `-PipelineVariable` binds an argument the script
        never wrote.
        """
        self.assertIsNone(data.abbreviated_parameter('Copy-Item', 'pa'))

    def test_a_prefix_narrowed_to_one_own_parameter_expands(self):
        self.assertEqual(data.abbreviated_parameter('Copy-Item', 'pas'), 'PassThru')

    def test_an_own_parameter_wins_a_prefix_a_common_parameter_also_starts(self):
        self.assertEqual(data.abbreviated_parameter('Set-Alias', 'v'), 'Value')


class TestPs1MemberOriginQueries(unittest.TestCase):
    """
    The two type questions the reflection fold's argument guard turns on: whether the pipeline
    enumerates a value of the type, and whether a value of it can be `$null`. Both are properties
    of the host, answered from the collected interface set and `kind` field.
    """

    def test_a_string_is_not_enumerable_although_it_implements_the_interface(self):
        # Measured on 5.1: `@('ab')` is one element. String implements the interface and is
        # enumerated by nothing, so the query answers on the measurement rather than the set.
        self.assertIs(data.is_enumerable('System.String'), False)

    def test_a_value_type_implementing_the_interface_is_enumerable(self):
        # Measured on 5.1: an ArraySegment of two ints flattens to two elements in `@(...)`.
        self.assertIs(data.is_enumerable('System.ArraySegment`1'), True)

    def test_an_array_is_enumerable_whatever_its_element_is(self):
        self.assertIs(data.is_enumerable('System.Char[]'), True)

    def test_a_scalar_value_type_is_not_enumerable(self):
        self.assertIs(data.is_enumerable('System.Int32'), False)

    def test_a_collection_class_is_enumerable(self):
        self.assertIs(data.is_enumerable('System.Collections.Generic.List[string]'), True)

    def test_an_uncollected_type_answers_nothing_about_enumeration(self):
        self.assertIsNone(data.is_enumerable('Zzqnope'))

    def test_a_struct_is_a_value_type(self):
        self.assertTrue(data.type_is_value_type('System.Int32'))

    def test_an_enum_is_a_value_type(self):
        self.assertTrue(data.type_is_value_type('System.DayOfWeek'))

    def test_a_class_is_not_a_value_type(self):
        self.assertFalse(data.type_is_value_type('System.String'))

    def test_an_array_is_not_a_value_type_whatever_its_element_is(self):
        # `char[]` is a reference to an array of a struct, so the answer is read from the array
        # before the element's record.
        self.assertFalse(data.type_is_value_type('System.Char[]'))

    def test_an_uncollected_type_is_not_a_value_type(self):
        self.assertFalse(data.type_is_value_type('Zzqnope'))

    def test_the_non_null_table_floors_a_member_that_is_not_a_method(self):
        # `StringBuilder.Length` is a property, and a vouch keyed on it has no overloads to read.
        with self.assertRaises(ValueError):
            data._required_non_null_returns({('text.stringbuilder', 'length')})

    def test_the_non_null_table_floors_an_unsealed_receiver(self):
        # A subtype of `Exception` could override the member to return `$null`.
        with self.assertRaises(ValueError):
            data._required_non_null_returns({('system.exception', 'gettype')})

    def test_the_non_null_table_floors_overloads_that_do_not_agree(self):
        # `Marshal.PtrToStructure` is static, so its instance side names no return at all.
        with self.assertRaises(ValueError):
            data._required_non_null_returns({('runtime.interopservices.marshal', 'ptrtostructure')})

    def test_the_generic_method_table_floors_a_member_that_is_not_a_method(self):
        with self.assertRaises(ValueError):
            data._required_reflection_method_keys({('text.stringbuilder', 'length')})


class TestPs1InheritedStaticShadowing(unittest.TestCase):
    """
    The reflection fold's overload selection draws its candidate set only from the statics a
    type declares, while the direct call's binder also selects among the statics its base types
    declare. A base overload strictly more specific than a declared one is the one shape the
    fold's uniqueness guard cannot see — the binder would re-select it where the type array
    selected the declared overload — so the collected surface is pinned to hold none.
    """

    @staticmethod
    def _statics(name, member):
        record = data.member_record(name, member)
        if not isinstance(record, dict):
            return []
        return [overload for overload in record.get('overloads') or () if overload.get('static')]

    @staticmethod
    def _parameters(overload):
        """
        The resolved non-byref parameter types, or `None` where a parameter spelling does not
        resolve: a pair one of whose sides cannot be judged is not one the census can compare.
        """
        resolved = []
        for parameter in overload.get('parameters') or ():
            if parameter.get('byref'):
                return None
            found = data.resolve_type(parameter['type'])
            if found is None:
                return None
            resolved.append(found)
        return resolved

    @classmethod
    def _base_chain(cls, resolved):
        chain = []
        seen = {resolved.definition}
        while True:
            record = data._type_record(resolved.definition)
            parent = None if record is None else record.get('base')
            if not parent:
                return chain
            resolved = data.resolve_type(parent)
            if resolved is None or resolved.definition in seen:
                return chain
            seen.add(resolved.definition)
            chain.append(resolved)

    def test_no_base_static_is_strictly_more_specific_than_a_declared_one(self):
        violations = []
        compared = 0
        for name in data.collected_type_names():
            try:
                resolved = data.resolve_type(name)
            except ValueError:
                # a nested-generic spelling the name parser misreads; the fold cannot spell a
                # lookup on it either, so the census skips it.
                continue
            if resolved is None or resolved.ranks:
                continue
            chain = self._base_chain(resolved)
            members = data.type_members(resolved)
            if not members or not chain:
                continue
            for member, record in members.items():
                if record.get('kind') != 'method':
                    continue
                declared = [
                    self._parameters(overload)
                    for overload in self._statics(resolved, member)
                ]
                for ancestor in chain:
                    for their_parameters in (
                        self._parameters(overload)
                        for overload in self._statics(ancestor, member)
                    ):
                        if their_parameters is None:
                            continue
                        for my_parameters in declared:
                            if (
                                my_parameters is None
                                or len(my_parameters) != len(their_parameters)
                            ):
                                continue
                            compared += 1
                            narrower = (
                                all(
                                    data.is_assignable_to(theirs, mine) is True
                                    for theirs, mine in zip(their_parameters, my_parameters)
                                )
                                and any(
                                    data.is_assignable_to(mine, theirs) is not True
                                    for theirs, mine in zip(their_parameters, my_parameters)
                                )
                            )
                            if narrower:
                                violations.append(
                                    F'{resolved.definition}::{member} against '
                                    F'{ancestor.definition}::{member}'
                                )
        # the count is only bounded below, so a regeneration may grow it; a walk that found
        # nothing to compare answers nothing and fails here.
        self.assertGreater(compared, 0)
        self.assertEqual(violations, [])


if __name__ == '__main__':
    unittest.main()
