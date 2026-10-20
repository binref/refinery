"""
The wizard of Setup as the emulator models it: the order of its pages, the pages that the script
creates, the page that is shown, and how far the installation got.
"""
from __future__ import annotations

from enum import Enum, IntFlag, StrEnum, auto
from typing import TYPE_CHECKING

from refinery.lib.inno.delphi.errors import DelphiException

if TYPE_CHECKING:
    from refinery.lib.inno.ifps import Function


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


class PageEvent(StrEnum):
    """
    The events of a page that the script creates, named as the properties of the page that hold the
    functions of the script that handle them.
    """
    OnActivate = 'OnActivate'
    OnShouldSkipPage = 'OnShouldSkipPage'
    OnNextButtonClick = 'OnNextButtonClick'
    OnBackButtonClick = 'OnBackButtonClick'
    OnCancelButtonClick = 'OnCancelButtonClick'


class PageStyle(IntFlag):
    """
    The style of a wizard page: Setup always skips a page with `AlwaysSkip`, and shows no buttons on
    a page with `NoButtons`, so that it does not ask which page Back would show.
    """
    Normal = 0
    AlwaysSkip = 1
    NoButtons = 2


class WizardPage:
    """
    A page of the wizard that the script creates: its ID, its style, and the functions of the
    script that handle its events.
    """
    def __init__(self, id: int, style: PageStyle):
        self.id = id
        self.style = style
        self.handlers: dict[PageEvent, Function] = {}

    def __repr__(self):
        return F'WizardPage({self.id})'


class PasswordBox:
    """
    Stands in for the box on the password page of the wizard and holds its text.
    """
    def __init__(self):
        self.text = ''

    def __repr__(self):
        return 'PasswordEdit'


class WizardForm:
    """
    Stands in for the wizard form of a setup: the order of its pages, with the pages that the script
    creates at their place, the page that is shown, whether the wizard is visible, and how far the
    installation got. A wizard that the emulator does not walk stands for the time when Setup
    installs the files: the directory and the program group are chosen and the uninstaller has its
    name. A script can keep the form and pass it to the methods of its controls, which do not read
    it.
    """
    def __init__(self, walked: bool = False):
        self.pages: list[int] = list(PageID)
        self.custom: dict[int, WizardPage] = {}
        self.current = 0
        self.visible = False
        self.done = False
        self.password_entered = False
        self.password_box = PasswordBox()
        self.dir_chosen = not walked
        self.group_chosen = not walked
        self.uninstaller_named = not walked
        self.needs_restart = False
        self._last_id = 99

    def __repr__(self):
        return 'WizardForm'

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
            raise DelphiException(F'Internal error: Could not find page with ID {after}')
        self._last_id += 1
        page = WizardPage(self._last_id, style)
        self.pages.insert(index, page.id)
        self.custom[page.id] = page
        return page

    def leave(self, page: int):
        """
        Notes what Setup records when Next leaves the given page or passes it: the chosen directory
        and program group.
        """
        if page == PageID.wpSelectDir:
            self.dir_chosen = True
        elif page == PageID.wpSelectProgramGroup:
            self.group_chosen = True
