from __future__ import annotations

import unittest

from collections import Counter
from typing import Iterator, NamedTuple

from refinery.lib.scripts.ps1 import data
from refinery.lib.scripts.ps1.lexer import _DASH_OPERATORS

BINARY_OPERATORS = [
    '+',
    '-',
    '*',
    '/',
    '%',
    '-band',
    '-bor',
    '-bxor',
    '-shl',
    '-shr',
    '-and',
    '-or',
    '-xor',
    '-eq',
    '-ne',
    '-lt',
    '-le',
    '-gt',
    '-ge',
    '-ceq',
    '-cne',
    '-clt',
    '-cle',
    '-cgt',
    '-cge',
    '-ieq',
    '-ine',
    '-ilt',
    '-ile',
    '-igt',
    '-ige',
    '-contains',
    '-notcontains',
    '-in',
    '-notin',
    '-ccontains',
    '-cnotcontains',
    '-cin',
    '-cnotin',
    '-icontains',
    '-inotcontains',
    '-iin',
    '-inotin',
    '-like',
    '-notlike',
    '-match',
    '-notmatch',
    '-clike',
    '-cnotlike',
    '-cmatch',
    '-cnotmatch',
    '-ilike',
    '-inotlike',
    '-imatch',
    '-inotmatch',
    '-replace',
    '-creplace',
    '-ireplace',
    '-split',
    '-csplit',
    '-isplit',
    '-join',
    '-f',
]

UNARY_OPERATORS = [
    '-',
    '+',
    '-not',
    '-bnot',
]

TYPE_OPERATORS = [
    '-is',
    '-isnot',
    '-as',
]

OPERAND_TYPES = [
    'System.Byte',
    'System.SByte',
    'System.Int16',
    'System.UInt16',
    'System.Int32',
    'System.UInt32',
    'System.Int64',
    'System.UInt64',
    'System.Single',
    'System.Double',
    'System.Decimal',
    'System.String',
    'System.Char',
    'System.Boolean',
    'System.Object[]',
    'System.Void',
]

CONVERSION_TARGETS = [
    'byte',
    'sbyte',
    'int16',
    'uint16',
    'int',
    'uint32',
    'long',
    'uint64',
    'single',
    'double',
    'decimal',
    'string',
    'char',
    'bool',
    'array',
    'byte[]',
    'char[]',
    'int[]',
    'string[]',
    'object[]',
]

NUMERIC_TYPES = [
    'System.Byte',
    'System.SByte',
    'System.Int16',
    'System.UInt16',
    'System.Int32',
    'System.UInt32',
    'System.Int64',
    'System.UInt64',
    'System.Single',
    'System.Double',
    'System.Decimal',
]

COLLECTION_TYPE = 'System.Object[]'

NULL_TYPE = 'System.Void'

SCALAR_TYPES = [
    name for name in OPERAND_TYPES if name not in (COLLECTION_TYPE, NULL_TYPE)
]

Cell = tuple[tuple[str, ...], bool, bool]

GridEntry = tuple[tuple[str, ...], 'data.OperatorOutcome | None']


def _cell(outcome: data.OperatorOutcome | None) -> Cell | None:
    """
    A grid cell as one exactly comparable value: the sorted names of the types it was seen to
    produce, whether it was seen to throw, and whether it was seen to yield `$null`.
    """
    if outcome is None:
        return None
    return (
        tuple(sorted(str(name) for name in outcome.types)),
        outcome.may_throw,
        outcome.may_be_null,
    )


def _binary(operator: str, left: str, right: str) -> Cell | None:
    return _cell(data.binary_outcome(operator, left, right))


def _cast(target: str, source: str) -> Cell | None:
    return _cell(data.conversion_outcome(target, source))


def _every_binary_cell() -> Iterator[GridEntry]:
    for operator in BINARY_OPERATORS:
        for left in OPERAND_TYPES:
            for right in OPERAND_TYPES:
                yield (operator, left, right), data.binary_outcome(operator, left, right)


def _every_conversion_cell() -> Iterator[GridEntry]:
    for target in CONVERSION_TARGETS:
        for source in OPERAND_TYPES:
            yield (target, source), data.conversion_outcome(target, source)


def _every_cell() -> Iterator[GridEntry]:
    yield from _every_binary_cell()
    yield from _every_conversion_cell()


def _classify(outcome: data.OperatorOutcome | None) -> str:
    if outcome is None:
        return 'uncovered'
    if outcome.single_type is not None:
        return 'type determined'
    if outcome.may_throw and not outcome.types and not outcome.may_be_null:
        return 'always throws'
    return 'value dependent'


def _recorded_binary(operator: str, left: str, right: str) -> tuple[str, ...]:
    """
    The outcome names the capture recorded for one binary cell.

    A cell in the shipped document is a position in its table of distinct outcomes, and the axes are
    positions too, so reading one back means indexing through both. The axes come from the document
    rather than from this file's own lists, because a test that read its own order would agree with
    itself about a document that had been rewritten underneath it.
    """
    axis = data._OPERATORS['types']
    cell = data._OPERATORS['binary'][operator][axis.index(left)][axis.index(right)]
    return tuple(data._OPERATORS['outcomes'][cell])


def _recorded_conversion(target: str, source: str) -> tuple[str, ...]:
    """
    The outcome names the capture recorded for one conversion cell, read as `_recorded_binary`
    reads a binary one.
    """
    cell = data._OPERATORS['conversions'][target][data._OPERATORS['types'].index(source)]
    return tuple(data._OPERATORS['outcomes'][cell])


def _recorded_outcomes() -> set[str]:
    return {entry for outcome in data._OPERATORS['outcomes'] for entry in outcome}


def _asymmetric_pairs(operator: str, types: list[str]) -> list[tuple[str, str]]:
    """
    Every unordered pair of operand types whose cell differs from the cell of the same pair with the
    operands exchanged, listed once each in the order the type axis declares them.
    """
    return [
        (left, right)
        for index, left in enumerate(types)
        for right in types[index:]
        if _binary(operator, left, right) != _binary(operator, right, left)
    ]


class TestPs1OperatorGridCoverage(unittest.TestCase):
    """
    The grid answers for every operator and cast the capture declares, over every operand type, and
    it answers regardless of how the operator or the type is spelled at the call site.
    """

    def test_the_grid_axes_are_the_ones_the_capture_declares(self):
        self.assertEqual(list(data._OPERATORS['binary']), BINARY_OPERATORS)
        self.assertEqual(list(data._OPERATORS['witnesses']), OPERAND_TYPES)
        self.assertEqual(data._OPERATORS['types'], OPERAND_TYPES)
        self.assertEqual(data._OPERATORS['targets'], CONVERSION_TARGETS)
        self.assertEqual(list(data._OPERATORS['unary']), UNARY_OPERATORS)
        self.assertEqual(list(data._OPERATORS['type_tests']), TYPE_OPERATORS)
        self.assertEqual(list(data._OPERATORS['conversions']), CONVERSION_TARGETS)

    def test_every_operator_the_language_spells_is_measured_in_some_table(self):
        measured = set(BINARY_OPERATORS) | set(UNARY_OPERATORS) | set(TYPE_OPERATORS)
        self.assertEqual(sorted(set(_DASH_OPERATORS.values()) - measured), [])

    def test_every_binary_cell_is_present(self):
        cells = list(_every_binary_cell())
        self.assertEqual([key for key, outcome in cells if outcome is None], [])
        self.assertEqual(len(cells), 16128)

    def test_every_conversion_cell_is_present(self):
        cells = list(_every_conversion_cell())
        self.assertEqual([key for key, outcome in cells if outcome is None], [])
        self.assertEqual(len(cells), 320)

    def test_an_operator_is_one_operator_in_any_casing(self):
        for operator in BINARY_OPERATORS:
            self.assertEqual(
                _binary(operator.upper(), 'System.Int32', 'System.Int32'),
                _binary(operator, 'System.Int32', 'System.Int32'),
                operator,
            )
        self.assertEqual(
            _binary('-BXOR', 'System.Int32', 'System.Int32'),
            (('System.Int32',), False, False),
        )

    def test_a_cast_target_is_one_target_in_any_casing(self):
        for target in CONVERSION_TARGETS:
            self.assertEqual(
                _cast(target.upper(), 'System.String'), _cast(target, 'System.String'), target)

    def test_a_type_is_found_under_any_spelling_of_its_name(self):
        self.assertEqual(
            _binary('-bxor', 'int', 'long'),
            _binary('-bxor', 'System.Int32', 'System.Int64'),
        )
        self.assertEqual(
            _binary('+', 'object[]', 'object[]'),
            _binary('+', 'System.Object[]', 'System.Object[]'),
        )
        self.assertEqual(_cast('int', 'string'), _cast('int', 'System.String'))


class TestPs1OperatorCellIsNotAType(unittest.TestCase):
    """
    A cell is the set of outcomes observed over several witness values per operand type, not a
    result type. Every measurement below comes out of one `(operator, left type, right type)` triple
    and shows that the triple does not determine the answer.
    """

    def test_adding_two_integers_widens_to_double_on_overflow(self):
        self.assertEqual(
            _binary('+', 'System.Int32', 'System.Int32'),
            (('System.Double', 'System.Int32'), False, False),
        )

    def test_a_string_on_the_left_of_addition_decides_the_result_type(self):
        self.assertEqual(
            _binary('+', 'System.String', 'System.Int32'),
            (('System.String',), False, False),
        )

    def test_a_string_on_the_right_of_addition_is_parsed_as_a_number_or_throws(self):
        self.assertEqual(
            _binary('+', 'System.Int32', 'System.String'),
            (('System.Double', 'System.Int32'), True, False),
        )

    def test_a_bitwise_exclusive_or_of_two_integers_is_type_determined(self):
        self.assertEqual(
            _binary('-bxor', 'System.Int32', 'System.Int32'),
            (('System.Int32',), False, False),
        )

    def test_a_long_on_either_side_of_a_bitwise_exclusive_or_makes_the_result_long(self):
        self.assertEqual(
            _binary('-bxor', 'System.Int64', 'System.Int32'),
            (('System.Int64',), False, False),
        )
        self.assertEqual(
            _binary('-bxor', 'System.Int32', 'System.Int64'),
            (('System.Int64',), False, False),
        )

    def test_multiplying_a_char_by_an_integer_produces_no_type_at_all(self):
        self.assertEqual(_binary('*', 'System.Char', 'System.Int32'), ((), True, False))

    def test_a_collection_on_the_left_of_a_comparison_filters_instead_of_answering_a_boolean(self):
        self.assertEqual(
            _binary('-ne', 'System.Object[]', 'System.Int32'),
            (('System.Object[]',), False, False),
        )

    def test_a_collection_on_the_right_of_a_comparison_does_not_filter(self):
        self.assertEqual(
            _binary('-eq', 'System.Int32', 'System.Object[]'),
            (('System.Boolean',), False, False),
        )

    def test_the_binary_grid_is_not_one_type_per_cell(self):
        census = Counter(_classify(outcome) for _, outcome in _every_binary_cell())
        self.assertEqual(census, Counter({
            'type determined' : 13668,  # noqa
            'value dependent' : 1838,   # noqa
            'always throws'   : 622,    # noqa
        }))

    def test_the_conversion_grid_is_not_one_type_per_cell(self):
        census = Counter(_classify(outcome) for _, outcome in _every_conversion_cell())
        self.assertEqual(census, Counter({
            'type determined' : 191,  # noqa
            'value dependent' : 109,  # noqa
            'always throws'   : 20,   # noqa
        }))


class TestPs1ConversionOutcomes(unittest.TestCase):

    def test_casting_an_integer_to_char_is_a_char_or_throws(self):
        self.assertEqual(_cast('char', 'System.Int32'), (('System.Char',), True, False))

    def test_casting_a_string_to_int_is_an_integer_or_throws(self):
        self.assertEqual(_cast('int', 'System.String'), (('System.Int32',), True, False))

    def test_casting_a_collection_to_string_always_succeeds(self):
        self.assertEqual(_cast('string', 'System.Object[]'), (('System.String',), False, False))

    def test_casting_a_scalar_to_array_wraps_it(self):
        self.assertEqual(_cast('array', 'System.Int32'), (('System.Object[]',), False, False))


def _single_type(operator: str, left: str, right: str):
    outcome = data.binary_outcome(operator, left, right)
    assert outcome is not None
    return outcome.single_type


def _cast_single_type(target: str, source: str):
    outcome = data.conversion_outcome(target, source)
    assert outcome is not None
    return outcome.single_type


def _always_throws(operator: str, left: str, right: str) -> bool:
    outcome = data.binary_outcome(operator, left, right)
    assert outcome is not None
    return outcome.always_throws


class RecordedCell(NamedTuple):
    """
    One grid cell from both ends of the same measurement: the grid it belongs to, the key it is
    indexed by, the outcome the reader answers for it, and the entries the capture holds under that
    key. A question about the reader's predicates is asked of the outcome and held against the
    entries, so that a predicate is compared with the data it reads rather than with itself.
    """
    grid: str
    key: tuple[str, ...]
    outcome: data.OperatorOutcome
    entries: tuple[str, ...]


def _every_recorded_cell() -> Iterator[RecordedCell]:
    for operator in BINARY_OPERATORS:
        for left in OPERAND_TYPES:
            for right in OPERAND_TYPES:
                outcome = data.binary_outcome(operator, left, right)
                assert outcome is not None, (operator, left, right)
                yield RecordedCell(
                    'binary',
                    (operator, left, right),
                    outcome,
                    _recorded_binary(operator, left, right),
                )
    for target in CONVERSION_TARGETS:
        for source in OPERAND_TYPES:
            outcome = data.conversion_outcome(target, source)
            assert outcome is not None, (target, source)
            yield RecordedCell(
                'conversion',
                (target, source),
                outcome,
                _recorded_conversion(target, source),
            )


#: Every cell of both shipped grids, which is the population the questions about `always_throws`
#: below are asked over rather than a handful of cells chosen here.
RECORDED_CELLS: tuple[RecordedCell, ...] = tuple(_every_recorded_cell())


class TestPs1OperatorOutcomeSingleType(unittest.TestCase):
    """
    `single_type` is the one answer a caller may act on without a value domain, so it is available
    only from a cell that always produces exactly that type.
    """

    def test_single_type_is_the_sole_type_of_a_cell_that_neither_throws_nor_is_null(self):
        self.assertEqual(
            _single_type('-bxor', 'System.Int32', 'System.Int32'),
            data.resolve_type('System.Int32'),
        )

    def test_single_type_is_none_when_the_cell_may_throw(self):
        self.assertEqual(_cast('int', 'System.String'), (('System.Int32',), True, False))
        self.assertIsNone(_cast_single_type('int', 'System.String'))

    def test_single_type_is_none_when_the_cell_may_be_null(self):
        """
        Asked of a constructed outcome rather than of a cell, because no cell of either grid now
        carries one type beside a `$null`.
        """
        collection = data.resolve_type('System.Object[]')
        self.assertIsNotNone(collection)
        assert collection is not None
        outcome = data.OperatorOutcome(
            types=frozenset({collection}),
            may_throw=False,
            may_be_null=True,
        )
        self.assertEqual(len(outcome.types), 1)
        self.assertIsNone(outcome.single_type)
        self.assertEqual(
            [key for key, cell in _every_cell()
             if cell is not None and cell.may_be_null and len(cell.types) == 1],
            [],
        )

    def test_single_type_is_none_when_the_cell_has_more_than_one_type(self):
        self.assertIsNone(_single_type('+', 'System.Int32', 'System.Int32'))

    def test_no_cell_in_either_grid_reports_a_single_type_it_does_not_always_produce(self):
        wrong = []
        for key, outcome in _every_cell():
            if outcome is None:
                wrong.append(key)
                continue
            certain = (
                len(outcome.types) == 1
                and not outcome.may_throw
                and not outcome.may_be_null
            )
            expected = next(iter(outcome.types)) if certain else None
            if outcome.single_type != expected:
                wrong.append(key)
        self.assertEqual(wrong, [])


class TestPs1OperatorOutcomeUndefined(unittest.TestCase):
    """
    `always_throws` is the cell every witness threw for and none of them produced anything out of,
    which is the one shape a caller may read as the operator having no answer for these operand
    types at all. The two questions it is not sit on either side of it: a cell that threw for one
    witness and answered for another, and a cell whose only outcome was `$null`. Both are populated,
    so reading either in its place is a wrong answer rather than a stricter one.
    """

    def test_a_cell_always_throws_exactly_where_the_capture_recorded_only_a_throw(self):
        self.assertEqual(len(RECORDED_CELLS), 16448)
        self.assertEqual(
            [
                cell.key for cell in RECORDED_CELLS
                if cell.outcome.always_throws != (set(cell.entries) == {'throw'})
            ],
            [],
        )

    def test_throwing_and_always_throwing_are_different_questions(self):
        self.assertEqual(
            Counter((cell.outcome.may_throw, cell.outcome.always_throws) for cell in RECORDED_CELLS),
            Counter({
                (False, False) : 14115, # noqa
                (True, False)  : 1691,  # noqa
                (True, True)   : 642,   # noqa
            }),
        )

    def test_having_no_type_and_always_throwing_are_different_questions(self):
        typeless = [cell for cell in RECORDED_CELLS if not cell.outcome.types]
        self.assertEqual(len(typeless), 665)
        self.assertEqual(
            [cell.key for cell in typeless if not cell.outcome.always_throws],
            [cell.key for cell in typeless if set(cell.entries) == {'null'}],
        )
        self.assertEqual(len([cell for cell in typeless if not cell.outcome.always_throws]), 23)

    def test_no_cell_records_a_throw_and_a_null_with_no_type_beside_them(self):
        """
        That shape is the only one that would tell the null clause of `always_throws` from the two
        beside it, and neither grid holds a cell of it, so a predicate that dropped the clause
        answers exactly as the shipped one does. The census is pinned whole rather than that one
        shape counted, so a regeneration producing the shape is read here first.
        """
        self.assertEqual(
            Counter(
                (bool(cell.outcome.types), cell.outcome.may_throw, cell.outcome.may_be_null)
                for cell in RECORDED_CELLS
            ),
            Counter({
                (False, False, True) : 23,    # noqa
                (False, True, False) : 642,   # noqa
                (True, False, False) : 14092, # noqa
                (True, True, False)  : 1691,  # noqa
            }),
        )

    def test_a_cell_whose_every_witness_produced_null_is_not_always_throws(self):
        self.assertEqual(_binary('*', 'System.Void', 'System.Int32'), ((), False, True))
        self.assertIs(_always_throws('*', 'System.Void', 'System.Int32'), False)

    def test_a_boolean_dividend_throws_beside_two_types_where_a_boolean_factor_has_none(self):
        self.assertEqual(
            _binary('/', 'System.Boolean', 'System.Int32'),
            (('System.Double', 'System.Int32'), True, False),
        )
        self.assertIs(_always_throws('/', 'System.Boolean', 'System.Int32'), False)
        self.assertEqual(_binary('*', 'System.Boolean', 'System.Int32'), ((), True, False))
        self.assertIs(_always_throws('*', 'System.Boolean', 'System.Int32'), True)

    def test_both_grids_hold_cells_the_predicate_calls_always_throws(self):
        self.assertEqual(
            Counter(cell.grid for cell in RECORDED_CELLS if cell.outcome.always_throws),
            Counter({'binary': 622, 'conversion': 20}),
        )

    def test_the_casts_that_always_throw_are_a_collection_source_or_a_char_out_of_reach(self):
        """
        Two causes, and the cells say which is which. A scalar cast from a collection throws at
        every length the witnesses carry, including one, so `[int] @(5)` is no better off than
        `[int] @(1, 2)`. A `Char` is out of reach of the four types no witness reached one from,
        and `[char[]]` inherits exactly those four while `[char]` also has the collection above it.
        """
        self.assertEqual(
            [
                cell.key for cell in RECORDED_CELLS
                if cell.grid == 'conversion' and cell.outcome.always_throws
            ],
            [
                ('byte', 'System.Object[]'),
                ('sbyte', 'System.Object[]'),
                ('int16', 'System.Object[]'),
                ('uint16', 'System.Object[]'),
                ('int', 'System.Object[]'),
                ('uint32', 'System.Object[]'),
                ('long', 'System.Object[]'),
                ('uint64', 'System.Object[]'),
                ('single', 'System.Object[]'),
                ('double', 'System.Object[]'),
                ('decimal', 'System.Object[]'),
                ('char', 'System.Single'),
                ('char', 'System.Double'),
                ('char', 'System.Decimal'),
                ('char', 'System.Boolean'),
                ('char', 'System.Object[]'),
                ('char[]', 'System.Single'),
                ('char[]', 'System.Double'),
                ('char[]', 'System.Decimal'),
                ('char[]', 'System.Boolean'),
            ],
        )


class TestPs1OperatorGridUnknowns(unittest.TestCase):
    """
    An uncovered cell answers `None`, which a caller has to read as nothing being known rather than
    as the cell producing nothing.
    """

    def test_an_operator_no_capture_covers_is_none(self):
        self.assertIsNone(data.binary_outcome('-nosuchoperator', 'System.Int32', 'System.Int32'))

    def test_an_operator_another_table_measures_is_not_found_among_the_binary_ones(self):
        self.assertIsNone(data.binary_outcome('-bnot', 'System.Int32', 'System.Int32'))
        self.assertIsNone(data.binary_outcome('-not', 'System.Boolean', 'System.Boolean'))
        self.assertIsNone(data.binary_outcome('-is', 'System.Int32', 'System.Int32'))
        self.assertIsNone(data.binary_outcome('-isnot', 'System.Int32', 'System.Int32'))
        self.assertIsNone(data.binary_outcome('-as', 'System.Int32', 'System.Int32'))

    def test_a_type_name_that_does_not_resolve_is_none(self):
        self.assertIsNone(data.binary_outcome('+', 'NotARealType', 'System.Int32'))
        self.assertIsNone(data.binary_outcome('+', 'System.Int32', 'NotARealType'))
        self.assertIsNone(data.conversion_outcome('int', 'NotARealType'))

    def test_a_type_the_grid_has_no_row_for_is_none_although_the_name_resolves(self):
        self.assertIsNotNone(data.resolve_type('System.Net.WebClient'))
        self.assertIsNone(data.binary_outcome('+', 'System.Net.WebClient', 'System.Int32'))

    def test_a_cast_target_the_grid_does_not_cover_is_none(self):
        self.assertIsNone(data.conversion_outcome('hashtable', 'System.Int32'))
        self.assertIsNone(data.conversion_outcome('void', 'System.Int32'))


class TestPs1OperatorGridLaws(unittest.TestCase):
    """
    Laws of the capture rather than of the reader: a cell that a symmetry relates to another has to
    agree with it, and a capture that measured one of the two wrongly is where that shows up.
    """

    def test_the_bitwise_operators_are_commutative_over_the_scalar_types(self):
        for operator in ('-band', '-bor', '-bxor'):
            self.assertEqual(_asymmetric_pairs(operator, SCALAR_TYPES), [], operator)

    def test_the_bitwise_operators_are_not_commutative_over_null(self):
        """
        Only over `$null`, and only for the three widths that keep their own type. A bitwise operator
        throws for a collection whichever side it stands on, so a collection is symmetric.
        """
        expected = [
            ('System.UInt32', 'System.Void'),
            ('System.Int64', 'System.Void'),
            ('System.UInt64', 'System.Void'),
        ]
        for operator in ('-band', '-bor', '-bxor'):
            self.assertEqual(_asymmetric_pairs(operator, OPERAND_TYPES), expected, operator)
        self.assertEqual(
            _binary('-bxor', 'System.Int64', 'System.Void'),
            (('System.Int64',), False, False),
        )
        self.assertEqual(_binary('-bxor', 'System.Void', 'System.Int64'), ((), True, False))

    def test_addition_is_commutative_in_its_outcome_over_the_numeric_types(self):
        self.assertEqual(_asymmetric_pairs('+', NUMERIC_TYPES), [])

    def test_addition_is_not_commutative_once_a_string_or_a_collection_is_involved(self):
        self.assertNotEqual(
            _binary('+', 'System.String', 'System.Int32'),
            _binary('+', 'System.Int32', 'System.String'),
        )
        self.assertEqual(
            _binary('+', 'System.Object[]', 'System.Int32'),
            (('System.Object[]',), False, False),
        )
        self.assertEqual(
            _binary('+', 'System.Int32', 'System.Object[]'),
            ((), True, False),
        )

    def test_every_recorded_outcome_is_a_marker_or_a_type_the_type_table_resolves(self):
        recorded = _recorded_outcomes()
        self.assertEqual(recorded, {
            'throw',
            'null',
            'System.Boolean',
            'System.Byte',
            'System.Byte[]',
            'System.Char',
            'System.Char[]',
            'System.Decimal',
            'System.Double',
            'System.Int16',
            'System.Int32',
            'System.Int32[]',
            'System.Int64',
            'System.Object[]',
            'System.SByte',
            'System.Single',
            'System.String',
            'System.String[]',
            'System.UInt16',
            'System.UInt32',
            'System.UInt64',
        })
        unresolved = [
            name for name in sorted(recorded - {'throw', 'null'})
            if data.resolve_type(name) is None
        ]
        self.assertEqual(unresolved, [])


class TestPs1OperatorGridProvenance(unittest.TestCase):

    def test_the_grid_was_captured_on_an_authoritative_windows_powershell_5_1_host(self):
        host = data._OPERATORS['host']
        self.assertEqual(host['ps_version'].split('.')[:2], ['5', '1'])
        self.assertEqual(host['edition'], 'Desktop')
        self.assertEqual(host['culture'], 'en-US')
        self.assertIs(host['authoritative'], True)

    def test_the_schema_version_is_the_one_the_reader_expects(self):
        self.assertEqual(data._OPERATORS['schema']['version'], data.OPERATOR_SCHEMA_VERSION)


if __name__ == '__main__':
    unittest.main()
