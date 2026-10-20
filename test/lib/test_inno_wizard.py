from refinery.lib.inno.delphi.errors import DelphiException
from refinery.lib.inno.emulation import EmulatorEndless
from refinery.lib.inno.installation import InstalledPaths
from refinery.lib.inno.wizard import (
    CheckList,
    CheckOperation,
    CheckState,
    comma_strings,
    comma_text,
    list_contains,
)

from .. import TestBase


class TestTheCheckListsOfTheWizard(TestBase):
    """
    The check lists of the wizard keep their check marks as Inno Setup's `TNewCheckListBox` keeps
    them. Setup creates its lists of components and tasks with `RequireRadioSelection`.
    """

    def test_a_radio_group_at_the_top_of_a_list_that_requires_a_selection_checks_its_first_button(self):
        tasks = CheckList('TasksList', require_radio_selection=True)
        tasks.add_radio_button(0, False, True, 'a')
        tasks.add_radio_button(0, False, True, 'b')
        self.assertEqual([tasks.checked(0), tasks.checked(1)], [True, False])

    def test_a_radio_group_at_the_top_of_another_list_keeps_its_buttons_unchecked(self):
        items = CheckList('RunList')
        items.add_radio_button(0, False, True, 'a')
        items.add_radio_button(0, False, True, 'b')
        self.assertEqual([items.checked(0), items.checked(1)], [False, False])

    def test_a_radio_group_below_a_checked_item_checks_its_first_button(self):
        items = CheckList('RunList')
        items.add_check_box(0, True, True, True, True, 'parent')
        items.add_radio_button(1, False, True, 'a')
        items.add_radio_button(1, False, True, 'b')
        self.assertEqual([items.checked(1), items.checked(2)], [True, False])

    def test_checking_a_radio_button_unchecks_the_other_buttons_of_its_group(self):
        items = CheckList('RunList')
        items.add_radio_button(0, True, True, 'a')
        items.add_radio_button(0, False, True, 'b')
        items.set_checked(1, True)
        self.assertEqual([items.checked(0), items.checked(1)], [False, True])

    def test_a_radio_button_cannot_be_unchecked(self):
        items = CheckList('RunList')
        items.add_radio_button(0, True, True, 'a')
        self.assertFalse(items.check(0, CheckOperation.Uncheck))
        self.assertTrue(items.checked(0))

    def test_a_check_box_with_some_of_its_children_checked_is_grayed(self):
        items = CheckList('RunList')
        items.add_check_box(0, True, True, False, True, 'parent')
        items.add_check_box(1, True, True, False, True, 'on')
        items.add_check_box(1, False, True, False, True, 'off')
        self.assertEqual([items.state(k) for k in range(3)], [CheckState.Grayed, CheckState.Checked, CheckState.Unchecked])

    def test_a_check_box_without_internal_children_is_unchecked_with_its_last_child(self):
        items = CheckList('RunList')
        items.add_check_box(0, True, True, False, True, 'parent')
        items.add_check_box(1, True, True, False, True, 'child')
        items.set_checked(1, False)
        self.assertFalse(items.checked(0))

    def test_a_disabled_check_box_below_a_radio_button_is_refused(self):
        items = CheckList('RunList')
        items.add_radio_button(0, False, True, 'a')
        with self.assertRaises(DelphiException) as raised:
            items.add_check_box(1, False, False, False, True, 'child')
        self.assertEqual(str(raised.exception), 'Radio item cannot have disabled child items')

    def test_unchecking_a_radio_button_that_a_disabled_checked_child_keeps_checked_ends_the_emulation(self):
        """
        Setup would uncheck the other button of the group forever. The child is disabled after it
        was added, which Setup allows.
        """
        items = CheckList('RunList')
        items.add_radio_button(0, True, True, 'a')
        items.add_check_box(1, True, True, False, True, 'child')
        items.add_radio_button(0, False, True, 'b')
        items.items[1].enabled = False
        with self.assertRaises(EmulatorEndless):
            items.set_checked(2, True)

    def test_a_list_with_more_levels_than_a_byte_holds_is_built(self):
        items = CheckList('RunList')
        for level in range(1100):
            items.add_check_box(level, True, True, False, True, level)
        self.assertEqual(len(items), 1100)
        self.assertTrue(all(items.checked(k) for k in range(1100)))

    def test_an_index_past_the_list_fails_with_the_message_of_delphi(self):
        items = CheckList('RunList')
        items.add_check_box(0, True, True, False, True, 'a')
        items.add_check_box(0, True, True, False, True, 'b')
        with self.assertRaises(DelphiException) as raised:
            items.checked(5)
        self.assertEqual(str(raised.exception), 'List index out of bounds (5).  TList range is 0..1')

    def test_a_list_whose_choices_are_not_known_counts_every_index_as_checked(self):
        items = CheckList('TasksList')
        items.known = False
        self.assertTrue(items.checked(999))
        self.assertTrue(items.check(999, CheckOperation.Uncheck))


class TestTheListsOfNames(TestBase):
    """
    Setup reads lists of names as `SetStringsFromCommaString` reads them, writes them as
    `StringsToCommaString` writes them, and finds a name as `ListContains` finds it.
    """

    def test_names_are_separated_by_commas_or_spaces(self):
        self.assertEqual(comma_strings(' a, b  c ,d '), ['a', 'b', 'c', 'd'])

    def test_a_name_in_quotes_holds_spaces_commas_and_doubled_quotes(self):
        self.assertEqual(comma_strings('"a b,c" "x""y"'), ['a b,c', 'x"y'])

    def test_a_comma_at_the_end_adds_an_empty_name(self):
        self.assertEqual(comma_strings('a,'), ['a', ''])

    def test_a_list_ends_at_its_first_nul_character(self):
        self.assertEqual(comma_strings('a,b\0,c'), ['a', 'b'])
        self.assertEqual(comma_strings('\0a'), [])

    def test_a_name_with_spaces_commas_or_quotes_is_written_in_quotes(self):
        self.assertEqual(comma_text(['a', 'b c', 'd,e', 'f"g']), 'a,"b c","d,e","f""g"')

    def test_a_single_empty_name_is_written_as_two_quotes(self):
        self.assertEqual(comma_text(['']), '""')

    def test_a_name_is_found_without_case_of_the_letters_a_to_z_only(self):
        self.assertTrue(list_contains(['Main'], 'MAIN'))
        self.assertFalse(list_contains(['\u00C4'], '\u00E4'))


class TestTheFilesThatTheInstallationCreates(TestBase):
    """
    Setup finds the sources of an external file with `FindFirstFile`, whose only wildcards are `*`
    and `?`; brackets are valid in the name of a file on Windows.
    """

    def test_brackets_in_the_name_of_a_source_stand_for_themselves(self):
        paths = InstalledPaths()
        paths.add_file('C:\\app\\data[1].bin')
        paths.add_file('C:\\app\\data1.bin')
        matches = paths.files_matching('C:\\app\\data[1].bin')
        self.assertEqual([match.lower() for match in matches], ['c:\\app\\data[1].bin'])

    def test_a_question_mark_and_a_star_are_wildcards(self):
        paths = InstalledPaths()
        paths.add_file('C:\\app\\data[1].bin')
        paths.add_file('C:\\app\\data1.bin')
        matches = paths.files_matching('C:\\app\\data?.bin')
        self.assertEqual([match.lower() for match in matches], ['c:\\app\\data1.bin'])
        self.assertEqual(len(paths.files_matching('C:\\app\\*.bin')), 2)
