"""
Inno Setup's procedure as `refinery.lib.inno.emulator.InnoSetupEmulator` runs it: the walk of the
wizard when the user clicks Next on every page, and the events that Setup sends to the script.
"""
from __future__ import annotations

import enum
import operator

from typing import TYPE_CHECKING, Any, Callable, Generator, Protocol, Sequence

from refinery.lib.inno.emulation import NewScriptError, SetupEvent
from refinery.lib.inno.pascal import IFPSException
from refinery.lib.inno.wizard import PageEvent, PageID, PageStyle, WizardForm

if TYPE_CHECKING:
    from refinery.lib.inno.emulator import HostSetup, IFPSEmulatorConfig
    from refinery.lib.inno.ifps import Function, IFPSFile


class TSetupStep(int, enum.Enum):
    """
    An IFPS enumeration that classifies different setup steps.
    """
    ssPreInstall = 0
    ssInstall = enum.auto()
    ssPostInstall = enum.auto()
    ssDone = enum.auto()


_EVENT_RULES: dict[SetupEvent, tuple[Callable[[Any], bool] | None, Any]] = {
    SetupEvent.InitializeSetup        : (operator.not_, True),
    SetupEvent.NextButtonClick        : (operator.not_, True),
    SetupEvent.ShouldSkipPage         : (bool, False),
    SetupEvent.CheckPassword          : (bool, False),
    SetupEvent.CheckSerial            : (bool, False),
    SetupEvent.NeedRestart            : (bool, False),
    SetupEvent.GetCustomSetupExitCode : (bool, 0),
    SetupEvent.PrepareToInstall       : (bool, ''),
    SetupEvent.UpdateReadyMemo        : (bool, ''),
}
"""
For each setup event that returns a value, the result that stops Setup from calling more of its
functions, and the result when the script does not handle it.
"""


class ScriptHost(Protocol):
    """
    What Setup's procedure needs of the emulator that runs the script.
    """
    setup: HostSetup
    config: IFPSEmulatorConfig
    ifps: IFPSFile
    symbols: dict[str, Function]
    wizard_form: WizardForm

    def call_from_setup(self, function: Function, arguments: Sequence) -> Generator[Any, Any, Any]:
        ...


class Installation:
    """
    One installation by Setup in which the user clicks Next on every page until Setup finishes; a
    silent installation when the configuration says so. The given password is typed into the box
    on the password page; `password_test` stands for Setup's test of a password against its own.
    Setup would end or stay on the current page after an error in some events; the installation
    goes on, just as it ignores a `False` returned by `InitializeSetup` or `NextButtonClick`, a
    text returned by `PrepareToInstall`, and a wrong password: such an error is often a gap of the
    emulator rather than one that the script raises when it runs on Windows.
    """
    def __init__(
        self,
        host: ScriptHost,
        password: str,
        password_test: Callable[[str], bool] | None,
    ):
        self.host = host
        self.setup = host.setup
        self.config = host.config
        self.wizard = host.wizard_form
        self.password = password
        self.password_test = password_test
        self._implementations: dict[SetupEvent, list[Function]] = {}

    def run(self) -> Generator[Any, Any, None]:
        wizard = self.wizard
        yield from self.event(SetupEvent.InitializeSetup)
        yield from self.event(SetupEvent.InitializeWizard)
        yield from self._set_page(PageID.wpWelcome)
        if not self.config.wizard_silent:
            while not wizard.done and (yield from self._should_skip(wizard.current)):
                yield from self._click_next()
            wizard.visible = True
        while not wizard.done:
            yield from self._click_next()
        yield from self.event(SetupEvent.GetCustomSetupExitCode)
        yield from self.event(SetupEvent.DeinitializeSetup)

    def _click_next(self):
        """
        Clicks Next on the current page as Setup's `TWizardForm.NextButtonClick` handles it: the
        check of the page, the events of the click, then the following pages until one is not
        skipped; reaching the preparing page prepares, reaching the installing page installs, and
        leaving the finished page finishes.
        """
        wizard = self.wizard
        page = wizard.current
        if page == PageID.wpPassword:
            yield from self._check_password()
        wizard.leave(page)
        yield from self.page_event(page, PageEvent.OnNextButtonClick)
        yield from self.event(SetupEvent.NextButtonClick, page)
        index = wizard.pages.index(page)
        while True:
            wizard.leave(page)
            if page == PageID.wpFinished:
                yield from self.event(SetupEvent.CurStepChanged, TSetupStep.ssDone)
                wizard.done = True
                return
            index += 1
            if index >= len(wizard.pages):
                wizard.done = True
                return
            page = wizard.pages[index]
            if page == PageID.wpReady:
                if not self.setup.ready_memo_disabled:
                    yield from self.event(SetupEvent.UpdateReadyMemo, '      ', '\r\n', '', '', '', '', '', '')
            elif page == PageID.wpPreparing:
                yield from self._prepare_to_install()
                if self.setup.restart_manager:
                    yield from self._set_page(page)
                    wizard.visible = True
                    yield from self.event(SetupEvent.RegisterExtraCloseApplicationsResources)
                    yield from self._previous_page()
            elif page == PageID.wpInstalling:
                yield from self._set_page(page)
                yield from self._install()
                continue
            if not (yield from self._should_skip(page)):
                break
        yield from self._set_page(page)

    def _check_password(self):
        """
        Checks the password on the password page as Setup does when Next is clicked there: the user
        types the given password into the box unless it is empty, Setup tests the text of the box
        against its own password when it has one, and the script's `CheckPassword` receives the
        text when that test fails. The page is passed in any case.
        """
        wizard = self.wizard
        box = wizard.password_box
        if self.password:
            box.text = self.password
        text = box.text
        test = self.password_test
        accepted = self.setup.header_password and test is not None and bool(text) and test(text)
        if not accepted:
            yield from self.event(SetupEvent.CheckPassword, text)
        box.text = ''
        wizard.password_entered = True

    def _set_page(self, page: int):
        """
        Shows the given page as Setup's `TWizardForm.SetCurPage` does: unless the page shows no
        buttons, the earlier pages are asked whether they are skipped to decide whether Back is
        shown; the serial is checked on the page for user information, then the page is activated
        and the script is told about the change.
        """
        wizard = self.wizard
        previous = wizard.current
        wizard.current = page
        if page != PageID.wpInstalling and not self._page_style(page) & PageStyle.NoButtons:
            yield from self._previous_page()
        if page == PageID.wpUserInfo:
            yield from self.event(SetupEvent.CheckSerial, '')
        yield from self.page_event(page, PageEvent.OnActivate)
        if page != previous or not self.setup.page_changes_only:
            yield from self.event(SetupEvent.CurPageChanged, page)

    def _page_style(self, page: int) -> PageStyle:
        if (custom := self.wizard.custom.get(page)) is None:
            return PageStyle.Normal
        return custom.style

    def _previous_page(self):
        """
        Finds the page that Back would show as Setup's `TWizardForm.GetPreviousPageID` does: the
        pages before the current one are asked in turn whether they are skipped, back to the first
        that is shown, stopping at the installing page.
        """
        wizard = self.wizard
        for page in reversed(wizard.pages[:wizard.pages.index(wizard.current)]):
            if page == PageID.wpInstalling:
                return
            if not (yield from self._should_skip(page)):
                return

    def _should_skip(self, page: int):
        """
        Whether the given page is skipped, as Setup's `TWizardForm.ShouldSkipPage` decides: the
        ready page is shown while the wizard is not visible, then Setup's own rules, then the event
        of a page that the script created, then the script's `ShouldSkipPage`.
        """
        if page == PageID.wpReady and not self.wizard.visible:
            return False
        if self._setup_skips(page):
            return True
        if (yield from self.page_event(page, PageEvent.OnShouldSkipPage)):
            return True
        return bool((yield from self.event(SetupEvent.ShouldSkipPage, page)))

    def _setup_skips(self, page: int) -> bool:
        """
        Whether Setup skips the given page on its own: a page whose style says so, the preparing
        page, the license page of a silent installation, the password page when no password is
        needed or one was entered, the finished page when the header disables it and no restart is
        needed, and the pages that the header makes Setup skip.
        """
        wizard = self.wizard
        setup = self.setup
        if self._page_style(page) & PageStyle.AlwaysSkip:
            return True
        if page == PageID.wpPreparing:
            return True
        if page == PageID.wpLicense and self.config.wizard_silent:
            return True
        if page == PageID.wpPassword:
            needed = setup.header_password or bool(self.implementations(SetupEvent.CheckPassword))
            return not needed or wizard.password_entered
        if page == PageID.wpFinished:
            return setup.finished_page_disabled and not wizard.needs_restart
        return page in setup.skipped_pages

    def _prepare_to_install(self):
        """
        Prepares the installation as Setup's `TWizardForm.PrepareToInstall` does when the script has
        `PrepareToInstall`: the preparing page is shown, the event runs, and the buttons are
        updated, which asks the earlier pages again whether they are skipped. Showing the preparing
        page makes the wizard visible, also in a silent installation.
        """
        if not self.implementations(SetupEvent.PrepareToInstall):
            return
        yield from self._set_page(PageID.wpPreparing)
        self.wizard.visible = True
        yield from self.event(SetupEvent.PrepareToInstall, False)
        yield from self._previous_page()

    def _install(self):
        """
        The events of the installation itself, as Setup's `TMainForm.Install` sends them: the step
        of the installation, then the uninstaller gets its name, `NeedRestart` is asked when no
        restart is needed yet, the uninstallable setup with a key in the list of installed programs
        registers its data, and the step after the installation. The progress of the installation
        is not reported: it counts the bytes that Setup installs.
        """
        wizard = self.wizard
        setup = self.setup
        wizard.visible = True
        yield from self.event(SetupEvent.CurStepChanged, TSetupStep.ssInstall)
        wizard.uninstaller_named = True
        if not wizard.needs_restart and (yield from self.event(SetupEvent.NeedRestart)):
            wizard.needs_restart = True
        if setup.uninstallable and setup.uninstall_key:
            yield from self.event(SetupEvent.RegisterPreviousData, 0)
        yield from self.event(SetupEvent.CurStepChanged, TSetupStep.ssPostInstall)

    def implementations(self, event: SetupEvent) -> list[Function]:
        """
        The functions of the script that handle the given event, in the order in which Setup calls
        them: those with an event attribute naming it, in the order of the script, then the one
        named like the event.
        """
        cache = self._implementations
        try:
            return cache[event]
        except KeyError:
            pass
        name = event.value.casefold()
        functions = []
        for function in self.host.ifps.functions:
            if function.body is None:
                continue
            for attribute in function.attributes or ():
                if attribute.name.casefold() != 'event' or len(attribute.fields) != 1:
                    continue
                if str(attribute.fields[0].value).casefold() == name:
                    functions.append(function)
                    break
        if (main := self.host.symbols.get(event)) is not None and main.body is not None and main not in functions:
            functions.append(main)
        cache[event] = functions
        return functions

    def event(self, event: SetupEvent, *args):
        """
        Runs the functions of the script that handle the given setup event and combines their
        results as Setup does: a Boolean event stops at the first result that decides it, an
        integer event at the first one that is not zero, a text event at the first one that is not
        empty. When the script does not handle the event, the result is Setup's default. A function
        that ends with a script error stops the event; the error is reported as a `NewScriptError`
        and the result is the default.
        """
        stop, default = _EVENT_RULES.get(event, (None, None))
        result = default
        for function in self.implementations(event):
            try:
                value = yield from self.host.call_from_setup(function, args)
            except IFPSException as error:
                message = str(error)
            else:
                result = value
                if stop is not None and stop(value):
                    break
                continue
            yield NewScriptError(event, args, message)
            return default
        return result

    def page_event(self, page: int, event: PageEvent):
        """
        Runs the function of the script that handles the given event of a page that the script
        created, passing the page. The result is `None` when the page has no such function; a
        script error is reported as a `NewScriptError` and also gives `None`.
        """
        if (custom := self.wizard.custom.get(page)) is None:
            return None
        if (function := custom.handlers.get(event)) is None:
            return None
        try:
            return (yield from self.host.call_from_setup(function, (custom,)))
        except IFPSException as error:
            message = str(error)
        yield NewScriptError(event, (custom,), message)
        return None
