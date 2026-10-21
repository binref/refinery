"""
The wizard of Setup as the emulator models it: the order of its pages, the pages that the script
creates, the page that is shown, the choices that its lists hold, and how far the installation got.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum, IntFlag, StrEnum, auto
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Generator,
    Generic,
    Iterable,
    Iterator,
    NamedTuple,
    TypeVar,
)

from refinery.lib.inno.archive import (
    SetupComponent,
    SetupFlags,
    SetupRunEntry,
    SetupTask,
    SetupType,
)
from refinery.lib.inno.delphi.errors import DelphiException
from refinery.lib.inno.emulation import EmulatorEndless, EntryField, InternalError
from refinery.lib.inno.pathfunc import PathFunc

if TYPE_CHECKING:
    from refinery.lib.inno.emulator import IFPSEmulatorConfig
    from refinery.lib.inno.ifps import Function

_T = TypeVar('_T')

Expander = Callable[[Any, EntryField, str], Generator[Any, Any, str]]
"""
Expands a field of an entry of the wizard's lists: the entry, the field, and its text.
"""


class PageID(int, Enum):
    """
    An IFPS enumeration that classifies the different installer pages.
    """
    wpWelcome = 1
    wpLicense = auto()
    wpPassword = auto()
    wpInfoBefore = auto()
    wpUserInfo = auto()
    wpSelectDir = auto()
    wpSelectComponents = auto()
    wpSelectProgramGroup = auto()
    wpSelectTasks = auto()
    wpReady = auto()
    wpPreparing = auto()
    wpInstalling = auto()
    wpInfoAfter = auto()
    wpFinished = auto()


_STANDARD_PAGES = tuple(PageID)


class PageEvent(StrEnum):
    """
    The events of a page, named as the properties of the page that hold the functions of the script
    that handle them.
    """
    OnActivate = 'OnActivate'
    OnShouldSkipPage = 'OnShouldSkipPage'
    OnNextButtonClick = 'OnNextButtonClick'
    OnBackButtonClick = 'OnBackButtonClick'
    OnCancelButtonClick = 'OnCancelButtonClick'


class ControlEvent(StrEnum):
    """
    The events of a control of the wizard, named as the properties of the control that hold their
    handlers.
    """
    OnChange = 'OnChange'


class PageStyle(IntFlag):
    """
    The style of a wizard page: Setup always skips a page with `AlwaysSkip`, and shows no buttons on
    a page with `NoButtons`, so that it does not ask which page Back would show.
    """
    Normal = 0
    AlwaysSkip = 1
    NoButtons = 2


class SetupHandler(Enum):
    """
    A handler of Setup's own that a control of the wizard holds.
    """
    UserInfoEditChange = auto()


class WizardPage:
    """
    A page of the wizard, a standard page or one that the script creates: its ID, its style, and
    the functions of the script that handle its events.
    """
    def __init__(self, id: int, style: PageStyle):
        self.id = id
        self.style = style
        self.handlers: dict[PageEvent, Function] = {}

    def __repr__(self):
        return F'WizardPage({self.id})'


class TEditCharCase(IntEnum):
    """
    Delphi's `TEditCharCase`: the case to which a text box converts every text that it receives.
    """
    ecNormal = 0
    ecUpperCase = 1
    ecLowerCase = 2


class TextBox:
    """
    A text box of the wizard: its text, its selection and its case as Windows' edit control keeps
    them, and the handler that runs when the box notifies a change, a function of the script or
    Setup's own. Where Setup refused its proposal, the text is unknown and the box reads as its
    stand-in, the text that names its value; writing the whole text makes it known again.
    """
    __slots__ = (
        'name',
        'stand_in',
        '_text',
        'selection_start',
        'selection_length',
        'char_case',
        'on_change',
    )

    def __init__(self, name: str, stand_in: str, text: str | None = ''):
        self.name = name
        self.stand_in = stand_in
        self._text = text
        self.selection_start = 0
        self.selection_length = 0
        self.char_case = TEditCharCase.ecNormal
        self.on_change: Function | SetupHandler | None = None

    def __repr__(self):
        return self.name

    @property
    def known(self) -> bool:
        return self._text is not None

    @property
    def text(self) -> str:
        if (text := self._text) is None:
            return self.stand_in
        return text

    def _cased(self, text: str) -> str:
        """
        The text in the case of the box. The edit control converts each character on its own, so
        that a character whose other case has more than one character stays as it is.
        """
        if (case := self.char_case) is TEditCharCase.ecNormal:
            return text
        convert = str.upper if case is TEditCharCase.ecUpperCase else str.lower
        return ''.join(c if len(converted := convert(c)) != 1 else converted for c in text)

    def set_text(self, text: str) -> bool:
        """
        Writes the text as Delphi's `TControl.SetText` does: nothing happens when the box holds it
        already; else `WM_SETTEXT` replaces it, in the case of the box, the selection is empty at
        the start, and the box notifies a change. The result tells whether it did.
        """
        if self._text == text:
            return False
        self._text = self._cased(text)
        self.selection_start = 0
        self.selection_length = 0
        return True

    def clear(self):
        """
        Delphi's `TCustomEdit.Clear`, which sends `WM_SETTEXT` with an empty text: the box notifies
        a change, also when it was empty.
        """
        self._text = ''
        self.selection_start = 0
        self.selection_length = 0

    def set_case(self, case: TEditCharCase):
        """
        Delphi's `TEdit.CharCase`: a new case makes the box convert its text and every text that it
        receives later; the box notifies no change.
        """
        if case is self.char_case:
            return
        self.char_case = case
        if (text := self._text) is not None:
            self._text = self._cased(text)
            self.selection_start = 0
            self.selection_length = 0

    def touched(self):
        """
        Notes that Setup refused the text; the emulated user entered one that Setup accepts, which
        the emulator does not know.
        """
        self._text = None

    def select(self, start: int, end: int):
        """
        Selects as `EM_SETSEL` does: the start -1 removes the selection and leaves the caret at its
        end; else both ends count as unsigned numbers clamped to the text, so that any other
        negative number stands for the end of the text, and the selection lies between them in
        either order.
        """
        size = len(self.text)
        if start == -1:
            self.selection_start = min(self.selection_start + self.selection_length, size)
            self.selection_length = 0
            return
        start = size if start < 0 else min(start, size)
        end = size if end < 0 else min(end, size)
        self.selection_start = min(start, end)
        self.selection_length = abs(end - start)

    @property
    def selected_text(self) -> str:
        start = self.selection_start
        return self.text[start:start + self.selection_length]

    def replace_selection(self, text: str):
        """
        Replaces the selection with the given text in the case of the box as `EM_REPLACESEL` does:
        the caret follows the new text, and the box notifies a change, also when the text stays
        the same. An unknown text stays unknown.
        """
        if (old := self._text) is None:
            return
        start = self.selection_start
        text = self._cased(text)
        self._text = F'{old[:start]}{text}{old[start + self.selection_length:]}'
        self.selection_start = start + len(text)
        self.selection_length = 0

    def clear_selection(self) -> bool:
        """
        Removes the selected text as `WM_CLEAR` does: the box notifies a change only when the
        selection was not empty. The result tells whether it did.
        """
        if not self.selection_length:
            return False
        self.replace_selection('')
        return True


class MainForm:
    """
    Stands in for Setup's main form, which a script of Inno Setup 6.0 to 6.4 finds in its variable
    `MainForm` once Setup created it.
    """
    def __repr__(self):
        return 'MainForm'


class StandIns(NamedTuple):
    """
    The values that the emulator gives where Setup's own are unknown: the folder and the program
    group of the installation.
    """
    folder: str
    group: str

    @classmethod
    def of(cls, config: IFPSEmulatorConfig) -> StandIns:
        """
        The stand-ins of the configured machine.
        """
        return cls(config.install_to, config.inno_name)


class Control:
    """
    Stands in for a control of the wizard whose state decides what Setup installs, but whose
    members the emulator does not model: the combo box of setup types and the check box that turns
    off the program group. Once the script touches it, the emulator no longer knows that choice.
    """
    def __init__(self, name: str):
        self.name = name
        self.known = True

    def __repr__(self):
        return self.name


class ItemType(IntEnum):
    """
    The kind of an item in a check list of the wizard.
    """
    Group = 0
    Check = 1
    Radio = 2


class CheckState(IntEnum):
    """
    The state of an item in a check list of the wizard; a grayed item counts as checked.
    """
    Unchecked = 0
    Checked = 1
    Grayed = 2


class CheckOperation(IntEnum):
    """
    How Setup changes the check mark of an item: uncheck it with its children, check it, or check
    it with the children that follow their parent.
    """
    Uncheck = 0
    Check = 1
    CheckWithChildren = 2


@dataclass
class CheckItem(Generic[_T]):
    """
    An item of a check list: its kind, level, whether the user can change it, whether a check box
    may be checked without a checked child, whether it is checked with its parent, the entry it
    stands for, its parent, its children, the run of radio buttons it belongs to, and its state.
    """
    type: ItemType
    level: int
    enabled: bool
    internal_children: bool
    follows_parent: bool
    entry: _T | None
    parent: int
    run: int
    children: list[int] = field(default_factory=list)
    state: CheckState = CheckState.Unchecked


class CheckList(Generic[_T]):
    """
    The check marks of a list in the wizard, as Inno Setup's `TNewCheckListBox` keeps them: check
    boxes, radio buttons and group labels on levels. A check box whose children are checked in part
    is grayed, a check box with children and without internal children is checked only with a
    checked child, and a radio group whose parent is checked keeps one selection; with
    `require_radio_selection`, so does a radio group at the top. Each item knows its parent, its
    children and its run of radio buttons, so that no change of a check mark searches the list.
    When the script changes the list in a way that the emulator does not model, its choices are no
    longer known: every item then counts as checked.
    """
    def __init__(self, name: str, require_radio_selection: bool = False):
        self.name = name
        self.require_radio_selection = require_radio_selection
        self.known = True
        self.clear()

    def __repr__(self):
        return self.name

    def clear(self):
        """
        Removes all items; whether the choices are known stays as it is.
        """
        self.items: list[CheckItem[_T]] = []
        self._roots: list[int] = []
        self._last_at_level: list[int] = []
        self._runs: list[list[int]] = []
        self._checked_in_run: list[int] = []

    def __len__(self):
        return len(self.items)

    def add_check_box(
        self,
        level: int,
        checked: bool,
        enabled: bool,
        internal_children: bool,
        follows_parent: bool,
        entry: _T,
    ) -> int:
        """
        Adds a check box as `TNewCheckListBox.AddCheckBox` does, which refuses a disabled check box
        below a radio button.
        """
        if not enabled and self._below_radio_button(level & 0xFF):
            raise DelphiException('Radio item cannot have disabled child items')
        return self._add(ItemType.Check, level, checked, enabled, internal_children, follows_parent, entry)

    def add_radio_button(self, level: int, checked: bool, enabled: bool, entry: _T) -> int:
        return self._add(ItemType.Radio, level, checked and enabled, enabled, False, True, entry)

    def add_group(self) -> int:
        return self._add(ItemType.Group, 0, False, True, False, True, None)

    def _below_radio_button(self, level: int) -> bool:
        """
        Setup's `CheckPotentialRadioParents`: whether an item added on the given level would have a
        radio button as its parent or as an ancestor of it.
        """
        items = self.items
        if not items:
            return False
        level = min(level, items[-1].level + 1)
        if level == 0:
            return False
        k = self._last_at_level[level - 1]
        while k != -1:
            if items[k].type is ItemType.Radio:
                return True
            k = items[k].parent
        return False

    def _add(
        self,
        type: ItemType,
        level: int,
        checked: bool,
        enabled: bool,
        internal_children: bool,
        follows_parent: bool,
        entry: _T | None,
    ) -> int:
        items = self.items
        level &= 0xFF
        level = min(level, items[-1].level + 1) if items else 0
        index = len(items)
        parent = self._last_at_level[level - 1] if level else -1
        siblings = items[parent].children if parent != -1 else self._roots
        run = -1
        if type is ItemType.Radio:
            if siblings and items[siblings[-1]].type is ItemType.Radio:
                run = items[siblings[-1]].run
                self._runs[run].append(index)
            else:
                run = len(self._runs)
                self._runs.append([index])
                self._checked_in_run.append(0)
        siblings.append(index)
        del self._last_at_level[level:]
        self._last_at_level.append(index)
        items.append(CheckItem(type, level, enabled, internal_children, follows_parent, entry, parent, run))
        if (
            type is ItemType.Radio
            and not checked
            and enabled
            and (self.require_radio_selection if parent == -1 else items[parent].state is not CheckState.Unchecked)
            and not self._has_checked_sibling(index)
        ):
            checked = True
        self.set_checked(index, checked)
        return index

    def item(self, index: int) -> CheckItem[_T]:
        """
        The item with the given index; an index past the list fails as Delphi's `TList` fails.
        """
        if not 0 <= index < (count := len(self.items)):
            raise DelphiException(F'List index out of bounds ({index}).  TList range is 0..{count - 1}')
        return self.items[index]

    def checked(self, index: int) -> bool:
        """
        Whether the item is checked, as `TNewCheckListBox.Checked` reads it.
        """
        return not self.known or self.item(index).state is not CheckState.Unchecked

    def enabled(self, index: int) -> bool:
        """
        Whether the user can change the item, as `TNewCheckListBox.ItemEnabled` reads it.
        """
        return not self.known or self.item(index).enabled

    def state(self, index: int) -> CheckState:
        """
        The state of the item, as `TNewCheckListBox.State` reads it; checked when the emulator does
        not know the choices.
        """
        if not self.known:
            return CheckState.Checked
        return self.item(index).state

    def entries(self) -> Iterator[_T]:
        """
        The entries of the checked items, in the order of the list.
        """
        for item in self.items:
            if item.entry is not None and (not self.known or item.state is not CheckState.Unchecked):
                yield item.entry

    def unchecked_entries(self) -> Iterator[_T]:
        """
        The entries of the items that are not checked, in the order of the list.
        """
        for item in self.items:
            if item.entry is not None and self.known and item.state is CheckState.Unchecked:
                yield item.entry

    def _set_state(self, index: int, state: CheckState) -> bool:
        item = self.items[index]
        if item.state is state:
            return False
        if item.run != -1:
            was = item.state is not CheckState.Unchecked
            now = state is not CheckState.Unchecked
            self._checked_in_run[item.run] += now - was
        item.state = state
        return True

    def _has_checked_sibling(self, index: int) -> bool:
        item = self.items[index]
        if item.run == -1:
            return False
        return self._checked_in_run[item.run] > (item.state is not CheckState.Unchecked)

    def _checked_sibling(self, index: int) -> int:
        """
        Setup's `FindCheckedSibling`: the nearest checked radio button before the item in its run,
        else the first one after it.
        """
        if not self._has_checked_sibling(index):
            return -1
        run = self._runs[self.items[index].run]
        position = run.index(index)
        for k in reversed(run[:position]):
            if self.items[k].state is not CheckState.Unchecked:
                return k
        for k in run[position + 1:]:
            if self.items[k].state is not CheckState.Unchecked:
                return k
        return -1

    def _calculated_state(self, index: int, check: bool) -> CheckState:
        """
        Setup's `CalcState`: the state that an item takes for the wanted check mark and the states
        of its children.
        """
        items = self.items
        has_checked = has_unchecked = False
        for k in items[index].children:
            child = items[k]
            if child.type is ItemType.Group:
                continue
            if child.state is CheckState.Unchecked:
                if child.type is not ItemType.Radio or not self._has_checked_sibling(k):
                    has_unchecked = True
            elif child.state is CheckState.Checked:
                has_checked = True
            else:
                has_checked = has_unchecked = True
        item = items[index]
        if has_unchecked and not has_checked and item.type is ItemType.Check and not item.internal_children:
            check = False
        if not check and not has_checked:
            return CheckState.Unchecked
        if has_unchecked and item.type is ItemType.Check:
            return CheckState.Grayed
        return CheckState.Checked

    def _recursive_check(self, index: int, operation: CheckOperation) -> bool:
        """
        Setup's `RecursiveCheck` without recursion: each child that the operation reaches is done
        with its own children before the next child is looked at, since a radio button is skipped
        when a sibling got checked before it. The result tells whether a state changed.
        """
        items = self.items
        check = operation is not CheckOperation.Uncheck
        changed = False
        stack: list[tuple[int, int]] = [(index, 0)]
        while stack:
            current, position = stack.pop()
            children = items[current].children
            while position < len(children):
                k = children[position]
                position += 1
                child = items[k]
                if not child.enabled:
                    continue
                if not (
                    operation is CheckOperation.Uncheck
                    or operation is CheckOperation.CheckWithChildren and child.follows_parent
                    or child.type is ItemType.Radio
                ):
                    continue
                if operation is CheckOperation.Uncheck or child.type is not ItemType.Radio or not self._has_checked_sibling(k):
                    stack.append((current, position))
                    stack.append((k, 0))
                    break
            else:
                if self._set_state(current, self._calculated_state(current, check)):
                    changed = True
        return changed

    def _uncheck_siblings(self, index: int):
        """
        Setup's `UncheckSiblings`. A sibling that stays checked, because a disabled child of it
        stays checked, makes Setup's loop run forever.
        """
        while (k := self._checked_sibling(index)) != -1:
            self._recursive_check(k, CheckOperation.Uncheck)
            if self.items[k].state is not CheckState.Unchecked:
                raise EmulatorEndless('Setup never ends unchecking a radio button whose disabled child stays checked.')

    def _ensure_radio_selection(self, index: int):
        """
        Setup's `EnsureChildRadioItemsHaveSelection`.
        """
        items = self.items
        for k in items[index].children:
            child = items[k]
            if (
                child.type is ItemType.Radio
                and child.enabled
                and child.state is not CheckState.Checked
                and not self._has_checked_sibling(k)
            ):
                self._recursive_check(k, CheckOperation.Check)

    def _update_parents(self, index: int):
        """
        Setup's `UpdateParentStates`.
        """
        items = self.items
        k = index
        while True:
            child_checked = items[k].state is not CheckState.Unchecked
            if (k := items[k].parent) == -1:
                break
            if child_checked:
                self._ensure_radio_selection(k)
            state = self._calculated_state(k, items[k].state is not CheckState.Unchecked)
            if state is not CheckState.Unchecked and items[k].type is ItemType.Radio:
                self._uncheck_siblings(k)
            self._set_state(k, state)

    def check(self, index: int, operation: CheckOperation) -> bool:
        """
        Changes the check mark of an item as `TNewCheckListBox.CheckItem` does: a radio button
        cannot be unchecked and unchecks its siblings, the children follow, and the parents are
        updated. The result tells whether the item or one of its children changed. In a list
        whose choices the emulator does not know, an index past the items changes nothing.
        """
        if not self.known and not 0 <= index < len(self.items):
            return True
        if self.item(index).type is ItemType.Radio:
            if operation is CheckOperation.Uncheck:
                return False
            self._uncheck_siblings(index)
        changed = self._recursive_check(index, operation)
        self._update_parents(index)
        return changed

    def set_checked(self, index: int, checked: bool):
        """
        Sets the check mark of an item as `TNewCheckListBox.Checked` does.
        """
        self.check(index, CheckOperation.Check if checked else CheckOperation.Uncheck)


_ASCII_LOWER_CASE = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')


def same_text(a: str, b: str) -> bool:
    """
    Compares two texts as Delphi's `CompareText` does: letters from A to Z without case, any other
    character as it is.
    """
    return a.translate(_ASCII_LOWER_CASE) == b.translate(_ASCII_LOWER_CASE)


def without_accelerators(text: str) -> str:
    """
    Delphi's `RemoveAccelChar`: drops each single ampersand and halves each double one.
    """
    parts = text.split('&&')
    return '&'.join(part.replace('&', '') for part in parts)


def comma_strings(text: str) -> list[str]:
    """
    Setup's `SetStringsFromCommaString`: the names in a list separated by commas or spaces, where a
    name in double quotes may hold both and doubles its quotes. Setup reads the text up to its
    first NUL character.
    """
    text = text.partition('\0')[0]
    names: list[str] = []
    end = len(text)
    cursor = 0
    while cursor < end and text[cursor] <= ' ':
        cursor += 1
    if cursor >= end:
        return names
    while True:
        if text[cursor] == '"':
            cursor += 1
            name: list[str] = []
            while cursor < end:
                if text[cursor] == '"':
                    cursor += 1
                    if cursor >= end or text[cursor] != '"':
                        break
                name.append(text[cursor])
                cursor += 1
            names.append(''.join(name))
        else:
            start = cursor
            while cursor < end and text[cursor] > ' ' and text[cursor] != ',':
                cursor += 1
            names.append(text[start:cursor])
        while cursor < end and text[cursor] <= ' ':
            cursor += 1
        if cursor >= end:
            return names
        if text[cursor] == ',':
            cursor += 1
            while cursor < end and text[cursor] <= ' ':
                cursor += 1
            if cursor >= end:
                names.append('')
                return names


def comma_text(names: list[str]) -> str:
    """
    Setup's `StringsToCommaString`: the names separated by commas, each one in double quotes when it
    holds a space, a control character, a comma or a quote, whose quotes are doubled.
    """
    if len(names) == 1 and not names[0]:
        return '""'
    quoted = []
    for name in names:
        if any(c <= ' ' or c == ',' or c == '"' for c in name):
            name = '"{}"'.format(name.replace('"', '""'))
        quoted.append(name)
    return ','.join(quoted)


def list_contains(names: Iterable[str], name: str) -> bool:
    """
    Setup's `ListContains`: whether the list has the name, compared as `CompareText` compares.
    """
    return any(same_text(entry, name) for entry in names)


class Selection(NamedTuple):
    """
    The names of the components and of the tasks that Setup reads from the wizard for the entries
    it processes; `None` when the emulator does not know them, and then every name counts as
    selected.
    """
    components: list[str] | None
    tasks: list[str] | None


class WizardForm:
    """
    Stands in for the wizard form of a setup: the order of its pages, with the pages that the script
    creates at their place, the page that is shown, whether the wizard is visible, how far the
    installation got, and the choices in its lists. In a walk of the wizard, Setup creates the form
    after `InitializeSetup`; before that, every function that reaches the form fails as in Setup. A
    form that the emulator does not walk stands for the time when Setup installs the files: it
    exists, the directory and the program group are chosen, the uninstaller has its name, and its
    choices are not known. The emulator does not know the choices of a script without its
    installer either. A script can keep the form and pass it to the methods of its controls.
    """
    def __init__(
        self,
        stand_ins: StandIns,
        walked: bool = False,
        entries_known: bool = True,
        uninstallable: bool = True,
    ):
        self.walked = walked
        self.created = not walked
        self.main = None if walked else MainForm()
        self.pages: list[int] = list(_STANDARD_PAGES)
        self.page_objects: dict[int, WizardPage] = {}
        self.current = 0
        self.visible = False
        self.done = False
        self.password_entered = False
        self.stand_ins = stand_ins
        if walked:
            folder = group = name = organization = serial = ''
        else:
            folder, group = stand_ins
            name = organization = serial = None
        self.password_box = TextBox('PasswordEdit', 'WizardForm.PasswordEdit.Text')
        self.dir_edit = TextBox('DirEdit', stand_ins.folder, folder)
        self.group_edit = TextBox('GroupEdit', stand_ins.group, group)
        self.user_info_name_edit = TextBox('UserInfoNameEdit', '{userinfoname}', name)
        self.user_info_org_edit = TextBox('UserInfoOrgEdit', '{userinfoorg}', organization)
        self.user_info_serial_edit = TextBox('UserInfoSerialEdit', '{userinfoserial}', serial)
        self.serial_accepted = True
        if walked:
            self.folder = self.group = self.uninstaller = ''
            self.user_info_name = self.user_info_org = self.user_info_serial = ''
        else:
            self.folder = stand_ins.folder
            self.group = stand_ins.group
            self.user_info_name = '{userinfoname}'
            self.user_info_org = '{userinfoorg}'
            self.user_info_serial = '{userinfoserial}'
            self.uninstaller = F'{PathFunc.add_backslash(stand_ins.folder)}unins000.exe' if uninstallable else ''
        self.needs_restart = False
        self.types: list[SetupType] = []
        self.type_descriptions: dict[int, str] = {}
        self.type_index = -1
        self.types_combo = Control('TypesCombo')
        self.no_icons_check = Control('NoIconsCheck')
        self.no_icons = False
        self.components: CheckList[SetupComponent] = CheckList('ComponentsList', require_radio_selection=True)
        self.tasks: CheckList[SetupTask] = CheckList('TasksList', require_radio_selection=True)
        self.run_list: CheckList[tuple[int, SetupRunEntry]] = CheckList('RunList')
        if not walked or not entries_known:
            for control in (self.components, self.tasks, self.run_list, self.types_combo, self.no_icons_check):
                control.known = False
        self._last_id = 99

    def __repr__(self):
        return 'WizardForm'

    @property
    def text_boxes(self) -> tuple[TextBox, ...]:
        return (
            self.dir_edit,
            self.group_edit,
            self.user_info_name_edit,
            self.user_info_org_edit,
            self.user_info_serial_edit,
            self.password_box,
        )

    @property
    def user_info_boxes(self) -> tuple[TextBox, TextBox, TextBox]:
        return (self.user_info_name_edit, self.user_info_org_edit, self.user_info_serial_edit)

    def page(self, id: int) -> WizardPage:
        """
        The page with the given ID, as Setup's `PageFromID` finds it; an internal error for an ID
        that no page has.
        """
        if (page := self.page_objects.get(id)) is not None:
            return page
        if id not in self.pages:
            raise InternalError(F'Could not find page with ID {id}')
        page = self.page_objects[id] = WizardPage(id, PageStyle.Normal)
        return page

    def page_index(self, id: int) -> int:
        """
        The index of the page with the given ID, as Setup's `PageIndexFromID` finds it.
        """
        try:
            return self.pages.index(id)
        except ValueError:
            raise InternalError(F'Could not find page with ID {id}') from None

    def require(self):
        """
        Raises Setup's error for a function that reaches the form before Setup created it.
        """
        if not self.created:
            raise InternalError('An attempt was made to access WizardForm before it has been created')

    def touched(self, control: object) -> bool:
        """
        Notes that the script used a member of the given control that the emulator does not model;
        the choices that the control holds are no longer known. The result tells whether the
        control is one of the form's choices.
        """
        if control is self.types_combo:
            self.types_combo.known = False
            self.components.known = False
        elif control is self.no_icons_check:
            self.no_icons_check.known = False
        elif control is self.components:
            self.components.known = False
        elif control is self.tasks:
            self.tasks.known = False
        elif control is self.run_list:
            self.run_list.known = False
        else:
            return False
        return True

    def add_page(self, after: int, style: PageStyle = PageStyle.Normal) -> WizardPage:
        """
        Adds a page that the script creates right after the page with the given ID, or at the end
        for -1, as Setup's `TWizardForm.AddPage` does. Setup raises an internal error for an ID that
        no page has, before the new page takes an ID.
        """
        if after == -1:
            index = len(self.pages)
        elif after in self.pages:
            index = self.pages.index(after) + 1
        else:
            raise InternalError(F'Could not find page with ID {after}')
        self._last_id += 1
        page = WizardPage(self._last_id, style)
        self.pages.insert(index, page.id)
        self.page_objects[page.id] = page
        return page

    def type_description(self, entry: SetupType) -> str:
        """
        The description of a type as Setup holds it, not expanded: a default type has the message
        of the active language.
        """
        return self.type_descriptions.get(id(entry), entry.Description)

    @property
    def setup_type(self) -> SetupType | None:
        """
        The selected setup type, as `TWizardForm.GetSetupType` reads it; none when the emulator does
        not know it.
        """
        if self.types_combo.known and 0 <= (index := self.type_index) < len(self.types):
            return self.types[index]
        return None

    @property
    def icons_off(self) -> bool:
        """
        Whether the check box that turns off the program group is checked; it counts as not checked
        when the emulator does not know it.
        """
        return self.no_icons_check.known and self.no_icons

    def selection(self) -> Selection:
        """
        The names that Setup's `GetComponents` and `GetTasks` read.
        """
        components = self.components
        tasks = self.tasks
        return Selection(
            [entry.Name for entry in components.entries()] if components.known else None,
            [entry.Name for entry in tasks.entries()] if tasks.known else None,
        )

    def selected_components(self, descriptions: bool, indent: bool, expand: Expander) -> Generator[Any, Any, list[str]]:
        """
        Setup's `GetSelectedComponents`: the names of the checked components, or their descriptions,
        indented by their level on request.
        """
        texts: list[str] = []
        for entry in self.components.entries():
            if not descriptions:
                texts.append(entry.Name)
                continue
            text = yield from expand(entry, EntryField.Description, entry.Description)
            if indent:
                text = ' ' * (3 * entry.Level) + text
            texts.append(text)
        return texts

    def selected_tasks(self, descriptions: bool, indent: bool, groups: bool, expand: Expander) -> Generator[Any, Any, list[str]]:
        """
        Setup's `GetSelectedTasks`: the names of the checked tasks, or their descriptions without
        accelerators, indented by their level on request; with `groups`, each group description
        that changes on the top level comes first, and the tasks below one are indented once more.
        """
        texts: list[str] = []
        last_group = ''
        for entry in self.tasks.entries():
            level = entry.Level
            if groups:
                group = yield from expand(entry, EntryField.GroupDescription, entry.GroupDescription)
                if entry.Level == 0 and group != last_group:
                    if group:
                        texts.append(without_accelerators(group))
                    last_group = group
                if last_group:
                    level += 1
            if not descriptions:
                texts.append(entry.Name)
                continue
            text = without_accelerators((yield from expand(entry, EntryField.Description, entry.Description)))
            if indent:
                text = ' ' * (3 * level) + text
            texts.append(text)
        return texts

    def select_components_from_type(self, type_name: str, only_fixed: bool):
        """
        Checks the components of the given setup type and unchecks the others, as
        `TWizardForm.SelectComponentsFromType` does; with `only_fixed`, only the fixed components.
        """
        for index, item in enumerate(self.components.items):
            if (component := item.entry) is None:
                continue
            if only_fixed and not component.Flags & SetupFlags.Fixed:
                continue
            self.components.set_checked(index, list_contains(comma_strings(component.Types), type_name))

    def select_components(self, select: Iterable[str], deselect: Iterable[str] = (), keep_fixed: bool = False):
        """
        Changes the check marks of the components as `TWizardForm.SelectComponents` does: a name
        checks the component, `*name` also its children, and `!name` unchecks it.
        """
        select = list(select)
        deselect = list(deselect)
        components = self.components
        for index, item in enumerate(components.items):
            if (component := item.entry) is None:
                continue
            if keep_fixed and component.Flags & SetupFlags.Fixed:
                continue
            name = component.Name
            if list_contains(select, F'*{name}'):
                components.check(index, CheckOperation.CheckWithChildren)
            elif list_contains(select, name):
                components.set_checked(index, True)
            elif list_contains(select, F'!{name}'):
                components.set_checked(index, False)
            elif list_contains(deselect, name):
                components.set_checked(index, False)

    def select_tasks(self, select: Iterable[str], deselect: Iterable[str] = ()):
        """
        Changes the check marks of the tasks as `TWizardForm.SelectTasks` does: a name checks the
        task and `!name` unchecks it.
        """
        select = list(select)
        deselect = list(deselect)
        tasks = self.tasks
        for index, item in enumerate(tasks.items):
            if (task := item.entry) is None:
                continue
            name = task.Name
            if list_contains(select, name):
                tasks.set_checked(index, True)
            elif list_contains(select, F'!{name}'):
                tasks.set_checked(index, False)
            elif list_contains(deselect, name):
                tasks.set_checked(index, False)

    def take_user_info(self):
        """
        Takes the texts of the boxes of the user information as Setup's values.
        """
        self.user_info_name = self.user_info_name_edit.text
        self.user_info_org = self.user_info_org_edit.text
        self.user_info_serial = self.user_info_serial_edit.text
