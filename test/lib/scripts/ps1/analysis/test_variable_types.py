from __future__ import annotations

from inspect import cleandoc

from test import TestBase

from refinery.lib.scripts.analysis.cycles import CycleModel
from refinery.lib.scripts.ps1.analysis.blocks import build_block_model
from refinery.lib.scripts.ps1.analysis.cfg import build_control_flow_model
from refinery.lib.scripts.ps1.analysis.dataflow import build_variable_flow
from refinery.lib.scripts.ps1.analysis.dominance import build_dominance
from refinery.lib.scripts.ps1.analysis.model import build_semantic_model, is_write_occurrence
from refinery.lib.scripts.ps1.analysis.variable_types import type_at
from refinery.lib.scripts.ps1.model import Ps1Variable
from refinery.lib.scripts.ps1.parser import Ps1Parser


def _in_source_order(node):
    """
    Pre-order over `children()`, which is source order. `Node.walk` is driven by a stack and comes
    back reversed, and `Ps1Variable.offset` is never set by the parser, so neither of them orders
    occurrences.
    """
    yield node
    for child in node.children():
        yield from _in_source_order(child)


class TestPs1TypeAt(TestBase):
    """
    What .NET type a variable carries at one read of it, expressed as the name PowerShell reports
    for that type. Reads are addressed by their position in the source rather than by name, since
    two reads of one name can answer differently.
    """

    def _type_at(self, source: str, read: int = -1, name: str = 'q') -> str | None:
        tree = Ps1Parser(source).parse()
        semantic = build_semantic_model(tree)
        control = build_control_flow_model(tree)
        blocks = build_block_model(tree)
        flow = build_variable_flow(
            semantic,
            control,
            build_dominance(control),
            blocks,
            CycleModel(control, blocks.body_site),
        )
        reads = [
            node for node in _in_source_order(tree)
            if isinstance(node, Ps1Variable)
            and node.name.lower() == name
            and not is_write_occurrence(node)
        ]
        found = type_at(reads[read], flow)
        return None if found is None else str(found)

    def test_a_name_the_script_never_writes_has_no_type(self):
        self.assertIsNone(self._type_at("$q.downloadstring('u')"))

    def test_a_read_after_the_only_write_carries_what_that_write_established(self):
        self.assertEqual(self._type_at(cleandoc("""
            $q = New-Object Net.WebClient
            $q.downloadstring('u')
        """)), 'System.Net.WebClient')

    def test_a_write_inside_a_function_body_does_not_type_a_read_outside_it(self):
        """
        The top-level `$q` holds `$null` however the body writes it, since nothing says the function
        was ever called. Answering `System.Net.WebClient` here folded `($q | Get-Member)[0].Name` to
        a member of a type that name never holds.
        """
        self.assertIsNone(self._type_at(cleandoc("""
            function f {
              $q = New-Object Net.WebClient
            }
            ($q | Get-Member)[0].Name
        """)))

    def test_a_write_inside_a_function_body_types_a_read_inside_that_body(self):
        self.assertEqual(self._type_at(cleandoc("""
            function f {
              $q = New-Object Net.WebClient
              $q.downloadstring('u')
            }
        """)), 'System.Net.WebClient')

    def test_a_write_inside_one_function_body_does_not_type_a_read_inside_another(self):
        self.assertIsNone(self._type_at(cleandoc("""
            function f {
              $q = New-Object Net.WebClient
            }
            function g {
              $q.downloadstring('u')
            }
        """)))

    def test_two_function_bodies_writing_one_name_are_typed_from_their_own_write(self):
        source = cleandoc("""
            function f {
              $q = New-Object Net.WebClient
              $q.downloadstring('u')
            }
            function g {
              $q = New-Object Text.StringBuilder
              $q.tostring()
            }
        """)
        self.assertEqual(self._type_at(source, read=0), 'System.Net.WebClient')
        self.assertEqual(self._type_at(source, read=1), 'System.Text.StringBuilder')

    def test_a_store_through_a_member_leaves_the_name_holding_what_it_held(self):
        self.assertEqual(self._type_at(cleandoc("""
            $q = New-Object Net.WebClient
            $q.Proxy = $null
            $q.downloadstring('u')
        """)), 'System.Net.WebClient')

    def test_a_write_and_a_read_inside_one_subexpression_are_typed(self):
        self.assertEqual(
            self._type_at("$($q = New-Object Net.WebClient; $q.downloadstring('u'))"),
            'System.Net.WebClient',
        )

    def test_a_read_before_the_write_it_shares_a_subexpression_with_is_refused(self):
        self.assertIsNone(
            self._type_at('$(($q | Get-Member)[0].Name; $q = New-Object Net.WebClient)'))

    def test_each_read_is_typed_by_the_write_it_observes_where_the_writes_disagree(self):
        source = cleandoc("""
            $q = New-Object Net.WebClient
            $q.downloadstring('u')
            $q = New-Object Text.StringBuilder
            $q.tostring()
        """)
        self.assertEqual(self._type_at(source, read=0), 'System.Net.WebClient')
        self.assertEqual(self._type_at(source, read=1), 'System.Text.StringBuilder')

    def test_a_read_no_single_write_reaches_is_refused_where_the_writes_disagree(self):
        self.assertIsNone(self._type_at(cleandoc("""
            $q = New-Object Net.WebClient
            if ($c) {
              $q = New-Object Text.StringBuilder
            }
            $q.tostring()
        """)))

    def test_a_read_no_single_write_reaches_is_typed_where_the_writes_agree(self):
        self.assertEqual(self._type_at(cleandoc("""
            $q = New-Object Net.WebClient
            if ($c) {
              $q = New-Object Net.WebClient
            }
            $q.downloadstring('u')
        """)), 'System.Net.WebClient')

    def test_a_read_preceding_every_write_of_the_name_is_refused(self):
        """
        Writes that agree about a type say nothing here: what stands at the read is whatever stood
        before the script ran, and `Get-Member` over that `$null` is an error, not a member list.
        """
        self.assertIsNone(self._type_at(cleandoc("""
            ($q | Get-Member)[0].Name
            $q = New-Object Net.WebClient
        """)))

    def test_a_read_at_the_top_of_a_loop_body_precedes_the_write_below_it(self):
        self.assertIsNone(self._type_at(cleandoc("""
            while ($c) {
              ($q | Get-Member)[0].Name
              $q = New-Object Net.WebClient
            }
        """)))

    def test_a_loop_body_read_is_typed_once_a_write_before_the_loop_reaches_it(self):
        self.assertEqual(self._type_at(cleandoc("""
            $q = New-Object Net.WebClient
            while ($c) {
              $q.downloadstring('u')
              $q = New-Object Net.WebClient
            }
        """)), 'System.Net.WebClient')

    def test_a_write_on_one_branch_only_does_not_type_the_read_after_the_branch(self):
        self.assertIsNone(self._type_at(cleandoc("""
            if ($c) {
              $q = New-Object Net.WebClient
            }
            $q.downloadstring('u')
        """)))

    def test_a_write_inside_a_body_reached_by_a_qualifier_does_not_type_a_read_outside(self):
        """
        `$script:q` written in a function body names the same variable the top-level read does, but
        nothing says the function was ever called.
        """
        self.assertIsNone(self._type_at(cleandoc("""
            function f {
              $script:q = New-Object Net.WebClient
            }
            ($q | Get-Member)[0].Name
        """)))

    def test_a_write_through_a_qualifier_types_the_reads_that_follow_it_in_its_body(self):
        self.assertEqual(self._type_at(cleandoc("""
            function f {
              $script:q = New-Object Net.WebClient
              $q.downloadstring('u')
            }
        """)), 'System.Net.WebClient')

    def test_a_write_carrying_no_type_of_its_own_is_not_looked_past(self):
        self.assertIsNone(self._type_at(cleandoc("""
            $q = New-Object Net.WebClient
            $q += 1
            $q.downloadstring('u')
        """)))

    def test_a_read_an_unattributable_write_may_precede_is_refused(self):
        self.assertIsNone(self._type_at(cleandoc("""
            $q = New-Object Net.WebClient
            Invoke-Expression $code
            $q.downloadstring('u')
        """)))

    def test_an_unattributable_write_after_the_read_leaves_the_type_standing(self):
        self.assertEqual(self._type_at(cleandoc("""
            $q = New-Object Net.WebClient
            $q.downloadstring('u')
            Invoke-Expression $code
        """)), 'System.Net.WebClient')

    def test_a_read_through_a_scope_qualifier_is_refused(self):
        for source in [
            cleandoc("""
                $global:q = New-Object Net.WebClient
                $global:q.downloadstring('u')
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                $script:q.downloadstring('u')
            """),
        ]:
            with self.subTest(source):
                self.assertIsNone(self._type_at(source))

    def test_a_foreach_over_a_string_binds_the_string_and_not_its_characters(self):
        self.assertEqual(
            self._type_at("foreach ($s in 'abc') { $s.substring(0, 1) }", name='s'),
            'System.String',
        )

    def test_a_foreach_binding_carries_the_type_the_iterated_elements_share(self):
        for source, expected in [
            ("foreach ($s in 'a', 'b') { $s.tostring() }", 'System.String'),
            ('foreach ($s in 1, 2) { $s.tostring() }', 'System.Int32'),
            ("foreach ($s in 'a', 1) { $s.tostring() }", None),
            ('foreach ($s in $items) { $s.tostring() }', None),
        ]:
            with self.subTest(source):
                self.assertEqual(self._type_at(source, name='s'), expected)


class TestPs1AWriteThroughAWiderScopeIsNotTheNameABareReadResolves(TestPs1TypeAt):
    """
    At the top level of a script a bare `$q = …` writes the script scope and `$global:q = …` writes
    the scope around it, so the two are different variables and a bare read below them resolves to
    the script one. `$using:` names a scope wider still. `$script:` is not one of these: at the top
    level it names the scope a bare write already lands in, so a qualified write and a bare write
    are one variable there and a read carries whichever of them ran last.
    """

    def test_a_bare_read_does_not_carry_what_a_write_to_a_wider_scope_stored(self):
        for qualifier in ['global', 'using']:
            with self.subTest(qualifier):
                self.assertIsNone(self._type_at(cleandoc(F"""
                    $q = $text
                    ${qualifier}:q = New-Object Net.WebClient
                    $q.downloadstring('u')
                """)))

    def test_a_bare_write_standing_beside_a_wider_one_is_refused_and_not_read_past(self):
        """
        5.1 answers `System.String` here — the value the bare write stored, which is the one the
        read resolves to. The refusal is what this layer has while one binding stands for the two
        names; the answer that may not stand is the WebClient, which is under a name no read of
        this script reaches.
        """
        self.assertIsNone(self._type_at(cleandoc("""
            $q = 'text'
            $global:q = New-Object Net.WebClient
            $q.downloadstring('u')
        """)))

    def test_a_name_only_a_wider_scope_writes_is_the_one_a_bare_read_resolves_to(self):
        self.assertEqual(self._type_at(cleandoc("""
            $global:q = New-Object Net.WebClient
            $q.downloadstring('u')
        """)), 'System.Net.WebClient')

    def test_the_script_qualifier_names_the_scope_a_bare_write_already_lands_in(self):
        for source in [
            cleandoc("""
                $q = $text
                $script:q = New-Object Net.WebClient
                $q.downloadstring('u')
            """),
            cleandoc("""
                $script:q = $text
                $q = New-Object Net.WebClient
                $q.downloadstring('u')
            """),
        ]:
            with self.subTest(source):
                self.assertEqual(self._type_at(source), 'System.Net.WebClient')


class TestPs1ATypeIsNotTakenFromAStoreThatMayNotHaveCompleted(TestPs1TypeAt):
    """
    A `catch` handler is entered exactly on the run where the `try` body threw. Measured on 5.1 the
    name holds what it held before the script started, both in the handler and at the statement
    after the whole `try`, and `Get-Member` over that `$null` is an error rather than a member list.
    """

    def test_a_handler_does_not_carry_the_write_its_try_body_may_not_have_completed(self):
        self.assertIsNone(self._type_at(cleandoc("""
            try {
              $q = New-Object Net.WebClient
            } catch {
              ($q | Get-Member)[0].Name
            }
        """)))

    def test_a_read_after_the_whole_try_does_not_carry_the_write_inside_it(self):
        self.assertIsNone(self._type_at(cleandoc("""
            try {
              $q = New-Object Net.WebClient
            } catch {}
            ($q | Get-Member)[0].Name
        """)))

    def test_a_read_only_the_completing_body_reaches_still_carries_the_write(self):
        """
        The floor under the two above: refusing every read a `try` stands anywhere near types
        nothing in a script that handles an error at all.
        """
        self.assertEqual(self._type_at(cleandoc("""
            try {
              $q = New-Object Net.WebClient
              $q.downloadstring('u')
            } catch {}
        """)), 'System.Net.WebClient')


class TestPs1NoReadInsideATrapBodyIsTyped(TestPs1TypeAt):
    """
    A hole this layer has, recorded so that it is a stated fact with a test that changes when it
    closes rather than an assumption nobody wrote down. A trap body is reached from the exceptional
    exit of every definition in the block it stands in, so no write reaches a read inside it and
    every such read is refused. For the write standing below the trap that is 5.1's own answer — a
    throw from above it leaves the name `$null` — but the same refusal falls on a write that cannot
    throw and on the body's own write directly above the read, and both of those do carry a value on
    5.1. No floor is constructible inside a trap body today, so what is pinned here is the refusal
    and not the completed-store rule the class above pins.
    """

    def test_a_write_standing_below_the_trap_does_not_type_a_read_inside_it(self):
        self.assertIsNone(self._type_at(cleandoc("""
            trap {
              ($q | Get-Member)[0].Name
            }
            $q = New-Object Net.WebClient
        """)))

    def test_a_write_the_trap_body_performs_itself_does_not_type_the_read_below_it(self):
        self.assertIsNone(self._type_at(cleandoc("""
            trap {
              $q = New-Object Net.WebClient
              $q.downloadstring('u')
            }
        """)))

    def test_a_write_that_cannot_throw_does_not_type_a_read_inside_the_trap_either(self):
        self.assertIsNone(self._type_at(cleandoc("""
            $q = 'abc'
            trap {
              $q.substring(0, 1)
            }
        """)))
        self.assertEqual(self._type_at(cleandoc("""
            $q = 'abc'
            $q.substring(0, 1)
        """)), 'System.String')


class TestPs1AWriteNobodyCanReadTypesNoReadWhereverThatReadStands(TestPs1TypeAt):
    """
    Measured on 5.1 with `Invoke-Expression '$q = New-Object Text.StringBuilder'` between the write
    and the read: the read carries the StringBuilder and not the WebClient the script wrote, at the
    top level, inside `1..3 | %{ }` and inside `& { }` alike. Where the read is written decides
    nothing, so the three have to answer together.
    """

    def test_a_read_the_call_precedes_carries_no_type(self):
        for source in [
            cleandoc("""
                $q = New-Object Net.WebClient
                Invoke-Expression $code
                $q.downloadstring('u')
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                Invoke-Expression $code
                1..3 | %{ $q.downloadstring('u') }
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                Invoke-Expression $code
                & { $q.downloadstring('u') }
            """),
        ]:
            with self.subTest(source):
                self.assertIsNone(self._type_at(source))

    def test_a_read_the_call_follows_still_carries_the_write(self):
        for source in [
            cleandoc("""
                $q = New-Object Net.WebClient
                $q.downloadstring('u')
                Invoke-Expression $code
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                1..3 | %{ $q.downloadstring('u') }
                Invoke-Expression $code
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                & { $q.downloadstring('u') }
                Invoke-Expression $code
            """),
        ]:
            with self.subTest(source):
                self.assertEqual(self._type_at(source), 'System.Net.WebClient')


class TestPs1ATypeIsNotCarriedPastABlockThatWritesItsCallersName(TestPs1TypeAt):
    """
    Measured on 5.1: a dot-sourced block and a `ForEach-Object` or `Where-Object` body store into
    the caller's own `$q`, so the write standing above one of them is not what the read below it
    observes. `($q | Get-Member)[0].Name` is `Clone` for a String, `Disposed` for a WebClient and
    `CompareTo` for an Int32, and each of these scripts answers with the members of the type the
    block left behind. A `&` block opens a scope of its own and changes nothing outside it.
    """

    def test_a_write_a_caller_scope_block_replaces_is_not_carried_past_it(self):
        for source in [
            cleandoc("""
                $q = 'abc'
                . { $q = New-Object Net.WebClient }
                ($q | Get-Member)[0].Name
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                . { $q = 5 }
                ($q | Get-Member)[0].Name
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                1..3 | ForEach-Object { $q = 5 }
                ($q | Get-Member)[0].Name
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                1..3 | Where-Object { $q = 5 }
                ($q | Get-Member)[0].Name
            """),
        ]:
            with self.subTest(source):
                self.assertIsNone(self._type_at(source))

    def test_a_block_that_writes_no_such_name_leaves_the_write_above_it_standing(self):
        for source in [
            cleandoc("""
                $q = New-Object Net.WebClient
                . { $z = 5 }
                $q.downloadstring('u')
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                1..3 | ForEach-Object { $z = 5 }
                $q.downloadstring('u')
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                1..3 | Where-Object { $z = 5 }
                $q.downloadstring('u')
            """),
            cleandoc("""
                $q = New-Object Net.WebClient
                & { $q = 5 }
                $q.downloadstring('u')
            """),
        ]:
            with self.subTest(source):
                self.assertEqual(self._type_at(source), 'System.Net.WebClient')


class TestPs1AConstrainedTargetTypesTheNameFromItsConstraint(TestPs1TypeAt):
    """
    `[string]$q = 5` constrains the variable, and PowerShell converts what is assigned to the
    constraint rather than storing it as written, so 5.1 leaves `$q` holding a `System.String`. The
    type below such a write is the constraint's whatever the assigned value's own type is.
    """

    def test_the_constraint_and_not_the_assigned_value_names_the_type(self):
        self.assertEqual(self._type_at(cleandoc("""
            [string]$q = 5
            $q.substring(0, 1)
        """)), 'System.String')

    def test_a_constraint_naming_the_type_the_value_already_has_carries_it_too(self):
        self.assertEqual(self._type_at(cleandoc("""
            [Net.WebClient]$q = New-Object Net.WebClient
            $q.downloadstring('u')
        """)), 'System.Net.WebClient')

    def test_a_constraint_types_the_name_where_the_assigned_value_has_no_type_of_its_own(self):
        """
        Whatever `$unknown` holds, converting it to `[string]` yields a String — `$null` converts to
        the empty string — so the name holds one however the read of `$unknown` answers.
        """
        self.assertEqual(self._type_at(cleandoc("""
            [string]$q = $unknown
            $q.substring(0, 1)
        """)), 'System.String')

    def test_a_constraint_naming_no_type_this_layer_knows_is_refused(self):
        self.assertIsNone(self._type_at(cleandoc("""
            [NoSuchType]$q = 5
            $q.tostring()
        """)))

    def test_each_read_carries_the_constraint_of_the_write_it_observes(self):
        source = cleandoc("""
            [string]$q = 5
            $q.substring(0, 1)
            [int]$q = '5'
            $q.tostring()
        """)
        self.assertEqual(self._type_at(source, read=0), 'System.String')
        self.assertEqual(self._type_at(source, read=1), 'System.Int32')

    def test_a_constrained_and_a_plain_write_agreeing_type_a_read_neither_of_them_reaches(self):
        self.assertEqual(self._type_at(cleandoc("""
            $q = 'abc'
            if ($c) {
              [string]$q = 5
            }
            $q.substring(0, 1)
        """)), 'System.String')

    def test_a_constraint_disagreeing_with_a_plain_write_refuses_the_read_neither_reaches(self):
        """
        The two writes store the same `5` and the constraint is the whole difference between them:
        one leaves an `Int32` and the other the `String` it converts that `5` to.
        """
        self.assertIsNone(self._type_at(cleandoc("""
            $q = 5
            if ($c) {
              [string]$q = 5
            }
            $q.tostring()
        """)))

    def test_a_constrained_write_and_a_read_inside_one_subexpression_are_typed(self):
        self.assertEqual(
            self._type_at('$([string]$q = 5; $q.substring(0, 1))'), 'System.String')

    def test_the_constraint_is_the_type_its_name_resolves_to(self):
        for constraint, expected in [
            ('System.String', 'System.String'),
            ('STRING', 'System.String'),
            ('int32', 'System.Int32'),
            ('long', 'System.Int64'),
            ('char', 'System.Char'),
            ('bool', 'System.Boolean'),
            ('decimal', 'System.Decimal'),
        ]:
            with self.subTest(constraint):
                self.assertEqual(self._type_at(cleandoc(F"""
                    [{constraint}]$q = 1
                    $q.tostring()
                """)), expected)

    def test_a_constraint_naming_an_array_type_leaves_the_name_holding_the_array(self):
        self.assertEqual(self._type_at(cleandoc("""
            [string[]]$q = 1, 2
            $q.Length
        """)), 'System.String[]')

    def test_a_constraint_converts_the_object_a_read_would_otherwise_reach_a_member_on(self):
        self.assertEqual(self._type_at(cleandoc("""
            [string]$q = New-Object Net.WebClient
            $q.substring(0, 1)
        """)), 'System.String')

    def test_a_cast_on_the_assigned_value_constrains_nothing_and_the_write_below_it_answers(self):
        """
        `$q = [string]5` converts what is stored that once and leaves the variable free, so the
        array the next write stores is what stands at the read. Written `[string]$q = 5`, the same
        cast would convert that array on its way in as well.
        """
        self.assertEqual(self._type_at(cleandoc("""
            $q = [string]5
            $q = 1, 2, 3
            $q.Length
        """)), 'System.Object[]')

    def test_a_later_plain_write_the_constraint_leaves_alone_types_the_name(self):
        """
        The constraint is stored on the variable and not on the statement carrying it, so it
        converts what every later write stores too. `'abc'` is already a String and is therefore
        stored as written, so the name holds one whether or not that conversion runs.
        """
        self.assertEqual(self._type_at(cleandoc("""
            [string]$q = 5
            $q = 'abc'
            $q.substring(0, 1)
        """)), 'System.String')

    def test_a_constrained_write_is_bound_by_every_rule_a_plain_write_is(self):
        for source in [
            cleandoc("""
                function f {
                  [string]$q = 5
                }
                ($q | Get-Member)[0].Name
            """),
            cleandoc("""
                [string]$q = 5
                Invoke-Expression $code
                $q.substring(0, 1)
            """),
            cleandoc("""
                [string]$q = 5
                . { $q = New-Object Net.WebClient }
                ($q | Get-Member)[0].Name
            """),
            cleandoc("""
                try {
                  [string]$q = 5
                } catch {}
                ($q | Get-Member)[0].Name
            """),
        ]:
            with self.subTest(source):
                self.assertIsNone(self._type_at(source))


class TestPs1AMultiAssignmentSlotTypesTheNameFromTheElementOppositeIt(TestPs1TypeAt):
    """
    `$q, $r = 'abc', 'd'` stores `abc` into `$q` and `d` into `$r`, so a slot carries the type of
    the element standing opposite it. Measured on 5.1 that only holds where the two sides have the
    same number of elements: `$a, $b = 1, 2, 3` leaves `$b` holding the array `2, 3`, and
    `$a, $b = 1` leaves `$b` holding `$null`.
    """

    def test_each_slot_carries_the_element_standing_opposite_it(self):
        source = cleandoc("""
            $q, $r, $s = 'abc', 1, (New-Object Net.WebClient)
            $q.substring(0, 1)
            $r.tostring()
            $s.downloadstring('u')
        """)
        self.assertEqual(self._type_at(source, name='q'), 'System.String')
        self.assertEqual(self._type_at(source, name='r'), 'System.Int32')
        self.assertEqual(self._type_at(source, name='s'), 'System.Net.WebClient')

    def test_a_slot_whose_element_has_no_type_leaves_the_slot_beside_it_typed(self):
        source = cleandoc("""
            $q, $r = 'abc', $unknown
            $q.substring(0, 1)
            $r.tostring()
        """)
        self.assertEqual(self._type_at(source, name='q'), 'System.String')
        self.assertIsNone(self._type_at(source, name='r'))

    def test_a_slot_a_shorter_right_hand_side_leaves_empty_carries_no_type(self):
        self.assertIsNone(self._type_at(cleandoc("""
            $a, $q = 1
            $q.tostring()
        """)))

    def test_a_slot_swallowing_the_rest_of_a_longer_right_hand_side_is_not_typed_from_one(self):
        self.assertIsNone(self._type_at(cleandoc("""
            $a, $q = 1, 2, 3
            $q.tostring()
        """)))

    def test_a_slot_with_an_element_opposite_it_is_refused_where_another_slot_has_none(self):
        """
        The same store that leaves the last slot `$null` puts the `1` into `$q`, so the refusal here
        is weaker than 5.1 rather than agreeing with it: it falls on the whole assignment and not on
        the slot whose element is missing.
        """
        for source in [
            cleandoc("""
                $q, $a = 1
                $q.tostring()
            """),
            cleandoc("""
                $q, $a, $b = 1, 2
                $q.tostring()
            """),
        ]:
            with self.subTest(source):
                self.assertIsNone(self._type_at(source))

    def test_the_two_sides_are_read_through_the_parentheses_around_either_of_them(self):
        for source in [
            cleandoc("""
                ($q, $r) = 'abc', 1
                $q.substring(0, 1)
                $r.tostring()
            """),
            cleandoc("""
                $q, $r = ('abc', 1)
                $q.substring(0, 1)
                $r.tostring()
            """),
        ]:
            with self.subTest(source):
                self.assertEqual(self._type_at(source, name='q'), 'System.String')
                self.assertEqual(self._type_at(source, name='r'), 'System.Int32')

    def test_a_constrained_slot_carries_its_constraint_and_the_slot_beside_it_its_element(self):
        source = cleandoc("""
            [string]$q, $r = 5, 6
            $q.substring(0, 1)
            $r.tostring()
        """)
        self.assertEqual(self._type_at(source, name='q'), 'System.String')
        self.assertEqual(self._type_at(source, name='r'), 'System.Int32')

    def test_a_slot_and_a_plain_write_agreeing_type_a_read_neither_of_them_reaches(self):
        self.assertEqual(self._type_at(cleandoc("""
            $q = 5
            if ($c) {
              $q, $r = 5, 6
            }
            $q.tostring()
        """)), 'System.Int32')

    def test_a_slot_whose_element_is_an_array_carries_the_array_and_not_its_first_item(self):
        source = cleandoc("""
            $q, $r = (1, 2), 3
            $q.Length
            $r.tostring()
        """)
        self.assertEqual(self._type_at(source, name='q'), 'System.Object[]')
        self.assertEqual(self._type_at(source, name='r'), 'System.Int32')

    def test_a_right_hand_side_whose_elements_cannot_be_counted_types_no_slot(self):
        """
        A slot carries the element opposite it only where the two sides have the same number of
        elements, and neither a name nor a command says how many elements it stands for.
        """
        for source in [
            cleandoc("""
                $q, $r = $pair
                $q.tostring()
            """),
            cleandoc("""
                $q, $r = Get-Pair
                $q.tostring()
            """),
        ]:
            with self.subTest(source):
                self.assertIsNone(self._type_at(source))

    def test_each_read_carries_the_slot_of_the_multi_assignment_it_observes(self):
        source = cleandoc("""
            $q, $r = 'abc', 1
            $q.substring(0, 1)
            $q, $r = 1, 'abc'
            $q.tostring()
        """)
        self.assertEqual(self._type_at(source, read=0), 'System.String')
        self.assertEqual(self._type_at(source, read=1), 'System.Int32')

    def test_a_multi_assignment_write_is_bound_by_every_rule_a_plain_write_is(self):
        for source in [
            cleandoc("""
                function f {
                  $q, $r = 'abc', 'd'
                }
                ($q | Get-Member)[0].Name
            """),
            cleandoc("""
                $q, $r = 'abc', 'd'
                Invoke-Expression $code
                $q.substring(0, 1)
            """),
            cleandoc("""
                $q, $r = 'abc', 'd'
                . { $q = 5 }
                ($q | Get-Member)[0].Name
            """),
            cleandoc("""
                ($q | Get-Member)[0].Name
                $q, $r = 'abc', 'd'
            """),
        ]:
            with self.subTest(source):
                self.assertIsNone(self._type_at(source))


class TestPs1NeitherNewSpellingDecidesWhichWriteAReadObserves(TestPs1TypeAt):
    """
    A constrained target and a multi-assignment slot are writes like any other, so which of them a
    read observes stays the ordering's to answer: a read at the top of a loop body precedes the
    write below it on the first visit, and carries a write standing before the loop once there is
    one.
    """

    def test_a_read_at_the_top_of_a_loop_body_precedes_either_spelling_below_it(self):
        for source in [
            cleandoc("""
                while ($c) {
                  ($q | Get-Member)[0].Name
                  [string]$q = 5
                }
            """),
            cleandoc("""
                while ($c) {
                  ($q | Get-Member)[0].Name
                  $q, $r = 'abc', 'd'
                }
            """),
        ]:
            with self.subTest(source):
                self.assertIsNone(self._type_at(source))

    def test_either_spelling_before_a_loop_types_the_read_at_the_top_of_its_body(self):
        for source in [
            cleandoc("""
                [string]$q = 5
                while ($c) {
                  $q.substring(0, 1)
                  [string]$q = 6
                }
            """),
            cleandoc("""
                $q, $r = 'abc', 'd'
                while ($c) {
                  $q.substring(0, 1)
                  $q, $r = 'e', 'f'
                }
            """),
        ]:
            with self.subTest(source):
                self.assertEqual(self._type_at(source), 'System.String')


if __name__ == '__main__':
    import unittest
    unittest.main()
