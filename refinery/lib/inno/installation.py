"""
Inno Setup's procedure as `refinery.lib.inno.emulator.InnoSetupEmulator` runs it: the walk of the
wizard when the user clicks Next on every page, the events that Setup sends to the script, the
entries that Setup loads and processes, and the installation itself. Setup calls the script for
its events and for the functions and code constants of its entries; a script error in such a call
is reported and the installation goes on.
"""
from __future__ import annotations

import enum
import ntpath
import re

from dataclasses import dataclass
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Generator,
    Generic,
    Iterable,
    Mapping,
    NamedTuple,
    Protocol,
    Sequence,
    TypeVar,
)

from refinery.lib.inno import expressions
from refinery.lib.inno.archive import (
    SetupComponent,
    SetupDeleteEntry,
    SetupDirective,
    SetupDirectory,
    SetupFile,
    SetupFileFlags,
    SetupFileType,
    SetupFileVerificationType,
    SetupFlags,
    SetupIcon,
    SetupIconFlags,
    SetupIniEntry,
    SetupIniFlags,
    SetupRegistryEntry,
    SetupRegistryFlags,
    SetupRegistryType,
    SetupRunEntry,
    SetupRunFlags,
    SetupTask,
    SetupTaskFlags,
    SetupType,
    TSetup,
    WinVerRange,
    YesNoDirective,
)
from refinery.lib.inno.delphi.errors import DelphiException
from refinery.lib.inno.delphi.runtime import Platform
from refinery.lib.inno.emulation import (
    AbortEmulation,
    EmulatorException,
    EmulatorMaxCalls,
    EntryField,
    EntryLocation,
    EntryParameter,
    EntrySection,
    NewEmulationError,
    NewScriptError,
    SetupEvent,
)
from refinery.lib.inno.pascal import IFPSException
from refinery.lib.inno.pathfunc import full_path_name
from refinery.lib.inno.symbols import IFPSEvents, IFPSSignature, parse_function
from refinery.lib.inno.wizard import (
    MainForm,
    PageEvent,
    PageID,
    PageStyle,
    Selection,
    TextBox,
    WizardForm,
    list_contains,
    same_text,
)
from refinery.lib.tools import exception_to_string

if TYPE_CHECKING:
    from refinery.lib.inno.emulator import IFPSEmulatorConfig
    from refinery.lib.inno.host import HostSetup
    from refinery.lib.inno.ifps import Function, IFPSFile

_E = TypeVar('_E')
_L = TypeVar('_L', SetupComponent, SetupTask)


class _ForWindows(Protocol):
    """
    An entry for some versions of Windows.
    """
    WindowsVersion: WinVerRange


_W = TypeVar('_W', bound=_ForWindows)


class TSetupStep(int, enum.Enum):
    """
    An IFPS enumeration that classifies different setup steps.
    """
    ssPreInstall = 0
    ssInstall = enum.auto()
    ssPostInstall = enum.auto()
    ssDone = enum.auto()


class ArgumentKind(enum.Enum):
    """
    The types of the values that Setup passes to the functions of the script and of the results
    that it takes from them, by their names in Inno Setup's declarations.
    """
    String = 'string'
    Integer = 'integer'
    Boolean = 'boolean'
    Step = 'tsetupstep'
    Page = 'twizardpage'
    Object = 'tobject'


class SetupCall(NamedTuple):
    """
    The declaration that Setup expects of a function of the script that it calls: the type of each
    parameter and whether it is passed by value, and the type of the result. The compiler of Inno
    Setup refuses a script whose functions do not fit the calls that it can see.
    """
    parameters: tuple[tuple[ArgumentKind, bool], ...]
    result: ArgumentKind | None

    @classmethod
    def of(cls, signature: IFPSSignature) -> SetupCall:
        def kind(name: str | None) -> ArgumentKind:
            if name is None:
                raise ValueError(F'The declaration of {signature.name} has a value without a type.')
            name = name.lower()
            return ArgumentKind.Integer if name == 'longint' else ArgumentKind(name)
        return cls(
            tuple((kind(p.type), p.const) for p in signature.parameters),
            None if signature.void else kind(signature.return_type),
        )

    @classmethod
    def of_parameters(cls, arguments: Sequence[expressions.Parameter], result: ArgumentKind | None) -> SetupCall:
        """
        The call of a function that an entry names, with the values that the entry gives.
        """
        kinds = []
        for argument in arguments:
            if isinstance(argument, bool):
                kinds.append((ArgumentKind.Boolean, True))
            elif isinstance(argument, int):
                kinds.append((ArgumentKind.Integer, True))
            else:
                kinds.append((ArgumentKind.String, True))
        return cls(tuple(kinds), result)

    def __str__(self):
        parameters = ', '.join(('' if by_value else 'var ') + kind.name for kind, by_value in self.parameters)
        result = F': {self.result.name}' if self.result else ''
        return F'({parameters}){result}'


CODE_CONSTANT = SetupCall(((ArgumentKind.String, True),), ArgumentKind.String)
"""
The call of the function that a code constant names.
"""

_EVENT_CALLS = {event: SetupCall.of(IFPSEvents[event.value]) for event in SetupEvent}

_PAGE_CALLS = {
    PageEvent.OnActivate          : SetupCall.of(parse_function('procedure OnActivate(Sender: TWizardPage)')),
    PageEvent.OnShouldSkipPage    : SetupCall.of(parse_function('function OnShouldSkipPage(Sender: TWizardPage): Boolean')),
    PageEvent.OnNextButtonClick   : SetupCall.of(parse_function('function OnNextButtonClick(Sender: TWizardPage): Boolean')),
    PageEvent.OnBackButtonClick   : SetupCall.of(parse_function('function OnBackButtonClick(Sender: TWizardPage): Boolean')),
    PageEvent.OnCancelButtonClick : SetupCall.of(parse_function(
        'procedure OnCancelButtonClick(Sender: TWizardPage; var ACancel, AConfirm: Boolean)')),
}

_EVENT_RULES: dict[SetupEvent, tuple[Callable[[Any], bool] | None, Any]] = {
    SetupEvent.InitializeSetup        : (lambda value: not value, True),
    SetupEvent.NextButtonClick        : (lambda value: not value, True),
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


class CurrentFile(NamedTuple):
    """
    The names that `CurrentFilename` and `CurrentSourceFilename` give in a function of a file
    entry: the destination and the source as the entry holds them, without expanding them.
    """
    destination: str
    source: str


@dataclass
class CurrentFolder:
    """
    The current folder of the emulated Setup process, a full path.
    """
    path: str


class InstalledPaths:
    """
    The files and directories that the emulated installation created. The emulated machine has no
    others: a path exists when the installation created it or a directory below it. Paths are
    compared as Windows compares them: by their full path in the current folder, without case.
    """
    def __init__(self, folder: CurrentFolder):
        self._folder = folder
        self._files: set[str] = set()
        self._directories: set[str] = set()

    def _key(self, path: str) -> str:
        if (full := full_path_name(path, self._folder.path)) is None:
            full = path
        return ntpath.normcase(full).rstrip('\\')

    def add_file(self, path: str):
        key = self._key(path)
        self._files.add(key)
        self._add_parents(key)

    def add_directory(self, path: str):
        key = self._key(path)
        self._directories.add(key)
        self._add_parents(key)

    def _add_parents(self, key: str):
        while (parent := ntpath.dirname(key)) and parent != key:
            self._directories.add(parent.rstrip('\\'))
            key = parent

    def remove(self, path: str):
        self._files.discard(self._key(path))

    def file_exists(self, path: str) -> bool:
        return self._key(path) in self._files

    def directory_exists(self, path: str) -> bool:
        return self._key(path) in self._directories

    def exists(self, path: str) -> bool:
        key = self._key(path)
        return key in self._files or key in self._directories

    def files_matching(self, pattern: str) -> list[str]:
        """
        The files in the directory of the pattern whose names match its last part, with `*` and `?`
        as wildcards, as `FindFirstFile` matches them; every other character stands for itself.
        """
        directory, name = ntpath.split(self._key(pattern))
        wildcard = re.compile(''.join('.*' if c == '*' else '.' if c == '?' else re.escape(c) for c in name), re.DOTALL)
        return sorted(f for f in self._files if ntpath.dirname(f) == directory and wildcard.fullmatch(ntpath.basename(f)))


class Loaded(NamedTuple, Generic[_E]):
    """
    An entry as Setup loads it, with its number in its section of the installer.
    """
    number: int
    entry: _E


def installs_on(versions: WinVerRange, os_version: tuple[int, int, int], service_pack: tuple[int, int]) -> bool:
    """
    Setup's `InstallOnThisVersion` for the emulated Windows: whether an entry with the given range
    of Windows versions is for it.
    """
    major, minor, build = os_version
    version = major << 24 | minor << 16 | build
    pack = service_pack[0] << 8 | service_pack[1]
    low = versions.Min
    high = versions.Max
    minimum = int(low.NT.Major) << 24 | int(low.NT.Minor) << 16 | int(low.NT.Build)
    if minimum == 0 or version < minimum:
        return False
    if version >> 16 == minimum >> 16 and pack < (int(low.ServicePackMajor) << 8 | int(low.ServicePackMinor)):
        return False
    if below := int(high.NT.Major) << 24 | int(high.NT.Minor) << 16 | int(high.NT.Build):
        below_pack = int(high.ServicePackMajor) << 8 | int(high.ServicePackMinor)
        compared = version if below & 0xFFFF else version & 0xFFFF0000
        if compared > below or compared == below and not below_pack:
            return False
        if version >> 16 == below >> 16 and below_pack and pack >= below_pack:
            return False
    return True


class SetupEntries(NamedTuple):
    """
    The entries of an installer as Setup loads them on the emulated Windows, each with its number in
    the installer. Setup drops an entry for another version of Windows when it reads it, except
    for components and tasks, whose versions it tests in the walk over their levels.
    """
    types: tuple[Loaded[SetupType], ...]
    components: tuple[Loaded[SetupComponent], ...]
    tasks: tuple[Loaded[SetupTask], ...]
    directories: tuple[Loaded[SetupDirectory], ...]
    files: tuple[Loaded[SetupFile], ...]
    icons: tuple[Loaded[SetupIcon], ...]
    ini: tuple[Loaded[SetupIniEntry], ...]
    registry: tuple[Loaded[SetupRegistryEntry], ...]
    install_delete: tuple[Loaded[SetupDeleteEntry], ...]
    uninstall_delete: tuple[Loaded[SetupDeleteEntry], ...]
    run: tuple[Loaded[SetupRunEntry], ...]
    uninstall_run: tuple[Loaded[SetupRunEntry], ...]

    @classmethod
    def of(cls, setup_info: TSetup, os_version: tuple[int, int, int], service_pack: tuple[int, int]) -> SetupEntries:
        def load(entries: list[_W]) -> tuple[Loaded[_W], ...]:
            return tuple(Loaded(k, e) for k, e in enumerate(entries) if installs_on(e.WindowsVersion, os_version, service_pack))

        def whole(entries: list[_L]) -> tuple[Loaded[_L], ...]:
            return tuple(Loaded(k, e) for k, e in enumerate(entries))

        return cls(
            load(setup_info.Types),
            whole(setup_info.Components),
            whole(setup_info.Tasks),
            load(setup_info.Directories),
            load(setup_info.Files),
            load(setup_info.Icons),
            load(setup_info.IniEntries),
            load(setup_info.RegistryEntries),
            load(setup_info.DeleteEntries),
            load(setup_info.UninstallDeleteEntries),
            load(setup_info.RunEntries),
            load(setup_info.UninstallRunEntries),
        )


class ScriptHost(Protocol):
    """
    What Setup's procedure needs of the emulator that runs the script.
    """
    setup: HostSetup
    config: IFPSEmulatorConfig
    ifps: IFPSFile
    symbols: dict[str, Function]
    wizard_form: WizardForm
    installed: InstalledPaths
    current_file: CurrentFile | None

    def call_from_setup(self, function: Function, arguments: Sequence, call: SetupCall) -> Generator[Any, Any, Any]:
        ...

    def call_by_name(self, name: str, arguments: list, call: SetupCall) -> Generator[Any, Any, Any]:
        ...

    def expand(self, text: str, custom: Mapping[str, str] | None = None) -> Generator[Any, Any, str]:
        ...

    def check_time(self):
        ...

    def registry_key_exists(self, key: str) -> bool:
        ...

    def text_changed(self, box: TextBox) -> Generator[Any, Any, None]:
        ...

    machine_folders: dict[str, str]

    @property
    def temporary_directory(self) -> str:
        ...

    @property
    def current_folder(self) -> CurrentFolder:
        ...


def _within_python(call: Generator[Any, Any, _E]) -> Generator[Any, Any, _E]:
    """
    Runs a call of the script; an expression that nests deeper than Python follows ends the
    emulation.
    """
    try:
        return (yield from call)
    except RecursionError as RE:
        raise EmulatorMaxCalls('An expression nests deeper than Python can follow.') from RE


_SCHEME_LETTERS = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
_SCHEME_CHARACTERS = _SCHEME_LETTERS | frozenset('0123456789+-.')


def _a_url(path: str) -> bool:
    """
    Setup's `IsPathURL`: whether the path starts with a scheme of two characters or more and a
    colon.
    """
    scheme, colon, _ = path.partition(':')
    return (
        bool(colon)
        and len(scheme) >= 2
        and scheme[0] in _SCHEME_LETTERS
        and all(character in _SCHEME_CHARACTERS for character in scheme[1:])
    )


_REGISTRY_TEXT_TYPES = (
    SetupRegistryType.String,
    SetupRegistryType.ExpandString,
    SetupRegistryType.MultiString,
    SetupRegistryType.DWord,
    SetupRegistryType.QWord,
)


class Field(NamedTuple):
    """
    A field of an entry that Setup expands, with the custom constants that Setup passes for it.
    """
    name: EntryField
    text: str | None
    custom: Mapping[str, str] | None = None


class Installation:
    """
    One installation by Setup in which the user clicks Next on every page until Setup finishes; a
    silent installation when the configuration says so. The given password is typed into the box
    on the password page; `password_test` stands for Setup's test of a password against its own.
    The entries are those of the installer, or `None` for a script without its installer, whose
    entries the emulator does not know. Setup would end or stay on the current page after an error
    in some events and entries; the installation goes on, just as it ignores a `False` returned by
    `InitializeSetup` or `NextButtonClick`, a text returned by `PrepareToInstall`, and a wrong
    password: such an error is often a gap of the emulator rather than one that the script raises
    when it runs on Windows.
    """
    def __init__(
        self,
        host: ScriptHost,
        entries: SetupEntries | None,
        password: str,
        password_test: Callable[[str], bool] | None,
    ):
        self.host = host
        self.setup = host.setup
        self.config = host.config
        self.wizard = host.wizard_form
        self.entries = entries
        self.password = password
        self.password_test = password_test
        self.selection = Selection(None, None)
        self.downloaded: dict[int, str] = {}
        self._loaded_types: list[Loaded[SetupType]] = []
        self._loaded_components: list[Loaded[SetupComponent]] = []
        self._numbers: dict[EntrySection, dict[int, int]] = {}
        if entries is not None:
            self._numbers[EntrySection.Components] = {id(e): k for k, e in entries.components}
            self._numbers[EntrySection.Tasks] = {id(e): k for k, e in entries.tasks}
        self._implementations: dict[SetupEvent, list[Function]] = {}

    def run(self) -> Generator[Any, Any, None]:
        wizard = self.wizard
        yield from self.event(SetupEvent.InitializeSetup)
        wizard.main = MainForm()
        yield from self._load_types_and_components()
        yield from self._measure_external_files()
        yield from self._create_wizard()
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
        setup = self.setup
        page = wizard.current
        if page == PageID.wpPassword:
            yield from self._check_password()
        self._leave(page)
        yield from self.page_event(page, PageEvent.OnNextButtonClick)
        yield from self.event(SetupEvent.NextButtonClick, page)
        index = wizard.pages.index(page)
        while True:
            self._leave(page)
            if page == PageID.wpFinished:
                yield from self._run_post_install_entries()
                yield from self.event(SetupEvent.CurStepChanged, TSetupStep.ssDone)
                wizard.done = True
                return
            index += 1
            if index >= len(wizard.pages):
                wizard.done = True
                return
            page = wizard.pages[index]
            if page == PageID.wpSelectTasks:
                yield from self._create_task_list()
            elif page == PageID.wpReady:
                if not setup.ready_memo_disabled:
                    yield from self._update_ready_page()
            elif page == PageID.wpPreparing:
                yield from self._prepare_to_install()
                if setup.restart_manager:
                    yield from self._set_page(page)
                    wizard.visible = True
                    yield from self._scan_files()
                    if setup.registers_close_applications_resources:
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
            yield from self._write(box, self.password)
        text = box.text
        test = self.password_test
        accepted = self.setup.header_password and test is not None and bool(text) and test(text)
        if not accepted:
            yield from self.event(SetupEvent.CheckPassword, text)
        yield from self._write(box, '')
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
        if (known := self.wizard.page_objects.get(page)) is None:
            return PageStyle.Normal
        return known.style

    def _write(self, box: TextBox, text: str) -> Generator[Any, Any, None]:
        """
        Setup writes the text of a box; its handler runs when the text changes.
        """
        if box.set_text(text):
            yield from self.host.text_changed(box)

    def _leave(self, page: int):
        """
        Setup's values of a page that Next leaves or passes, as its loop over the skipped pages
        takes them.
        """
        wizard = self.wizard
        path_func = self.setup.path_func
        if page == PageID.wpUserInfo:
            wizard.take_user_info()
        elif page == PageID.wpSelectDir:
            wizard.folder = path_func.remove_backslash_unless_root(wizard.dir_edit.text)
        elif page == PageID.wpSelectProgramGroup:
            wizard.group = path_func.remove_backslash_unless_root(wizard.group_edit.text)

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
        Setup's own rules of `TWizardForm.ShouldSkipPage`, from the header, the entries that Setup
        loaded and the lists of the wizard. A script without its installer has no header and
        unknown entries: it shows every page that the script can see.
        """
        wizard = self.wizard
        setup = self.setup
        entries = self.entries
        if self._page_style(page) & PageStyle.AlwaysSkip:
            return True
        if page == PageID.wpWelcome:
            return setup.welcome_page_disabled
        if page == PageID.wpLicense:
            return self.config.wizard_silent or not setup.license_text
        if page == PageID.wpPassword:
            needed = setup.header_password or bool(self.implementations(SetupEvent.CheckPassword))
            return not needed or wizard.password_entered
        if page == PageID.wpInfoBefore:
            return not setup.info_before_text
        if page == PageID.wpUserInfo:
            return not setup.user_info_page
        if page == PageID.wpSelectDir:
            return setup.dir_page_disabled
        if page == PageID.wpSelectComponents:
            return entries is not None and not self._loaded_components
        if page == PageID.wpSelectProgramGroup:
            return setup.group_page_disabled or entries is not None and not entries.icons
        if page == PageID.wpSelectTasks:
            return entries is not None and wizard.tasks.known and not wizard.tasks
        if page == PageID.wpReady:
            return setup.ready_page_disabled
        if page == PageID.wpPreparing:
            return True
        if page == PageID.wpInfoAfter:
            return not setup.info_after_text
        if page == PageID.wpFinished:
            return setup.finished_page_disabled and not wizard.needs_restart
        return False

    def _prepare_to_install(self):
        """
        Prepares the installation as Setup's `TWizardForm.PrepareToInstall` does: the selection is
        taken, the archives to download are downloaded, and when the script has `PrepareToInstall`,
        the preparing page is shown, the event runs, and the buttons are updated, which asks the
        earlier pages again whether they are skipped. Showing the preparing page makes the wizard
        visible, also in a silent installation.
        """
        setup = self.setup
        self.selection = self.wizard.selection() if setup.prepares_with_selection else Selection([], [])
        if setup.downloads_archives:
            yield from self._download_archives()
        if not self.implementations(SetupEvent.PrepareToInstall):
            return
        yield from self._set_page(PageID.wpPreparing)
        self.wizard.visible = True
        yield from self.event(SetupEvent.PrepareToInstall, False)
        yield from self._previous_page()

    def _install(self):
        """
        The installation itself, as Setup's `TMainForm.Install` and `PerformInstall` run it: the
        step of the installation, the directives on the environment and associations, every file's
        check for the size of the installation, the directive on uninstalling, the entries in
        Setup's order, `NeedRestart` when no restart is needed yet, the directive on the key in the
        list of installed programs and `RegisterPreviousData`, the uninstall run entries, the run
        entries, the step after the installation, and the list of run entries for the finished
        page. The uninstaller gets its name after the directories. The progress of the
        installation is not reported: it counts the bytes that Setup installs.
        """
        wizard = self.wizard
        setup = self.setup
        entries = self.entries
        wizard.visible = True
        self.selection = wizard.selection()
        yield from self.event(SetupEvent.CurStepChanged, TSetupStep.ssInstall)
        if setup.evaluates_change_directives:
            yield from self.directive(YesNoDirective.ChangesEnvironment, setup.changes_environment)
            yield from self.directive(YesNoDirective.ChangesAssociations, setup.changes_associations)
        if entries is not None:
            for loaded in entries.files:
                yield from self._should_process_file(loaded)
        uninstallable = yield from self.directive(YesNoDirective.Uninstallable, setup.uninstallable)
        if entries is not None:
            for number, entry in entries.install_delete:
                where = EntryLocation(EntrySection.InstallDelete, number)
                yield from self._process(where, entry, Field(EntryField.Name, entry.Name))
            for number, entry in reversed(entries.uninstall_delete):
                where = EntryLocation(EntrySection.UninstallDelete, number)
                yield from self._process(where, entry, Field(EntryField.Name, entry.Name))
            yield from self._create_directories(entries)
        if uninstallable:
            wizard.uninstaller = F'{self.setup.path_func.add_backslash(wizard.folder)}unins000.exe'
        if entries is not None:
            for loaded in entries.files:
                yield from self._copy_file(loaded, uninstallable)
            for loaded in entries.icons:
                yield from self._create_icon(loaded)
            for number, entry in entries.ini:
                yield from self._create_ini_entry(EntryLocation(EntrySection.INI, number), entry)
            for number, entry in entries.registry:
                yield from self._create_registry_entry(EntryLocation(EntrySection.Registry, number), entry)
        if not wizard.needs_restart and (yield from self.event(SetupEvent.NeedRestart)):
            wizard.needs_restart = True
        if uninstallable:
            if (yield from self.directive(YesNoDirective.CreateUninstallRegKey, setup.uninstall_key)):
                yield from self.event(SetupEvent.RegisterPreviousData, 0)
            if entries is not None:
                for number, entry in reversed(entries.uninstall_run):
                    yield from self._process(
                        EntryLocation(EntrySection.UninstallRun, number),
                        entry,
                        Field(EntryField.Filename, entry.Name),
                        Field(EntryField.Parameters, entry.Parameters),
                        Field(EntryField.WorkingDir, entry.WorkingDir),
                        Field(EntryField.RunOnceId, entry.RunOnceId),
                        Field(EntryField.Verb, entry.Verb),
                    )
        if entries is not None:
            for number, entry in entries.run:
                if entry.Flags & SetupRunFlags.PostInstall:
                    continue
                where = EntryLocation(EntrySection.Run, number)
                if not (yield from self._should_process_run(where, entry)):
                    continue
                if entry.StatusMessage:
                    yield from self.fields(where, Field(EntryField.StatusMsg, entry.StatusMessage))
                yield from self._run_entry(where, entry)
        yield from self.event(SetupEvent.CurStepChanged, TSetupStep.ssPostInstall)
        if not wizard.needs_restart:
            yield from self._update_run_list()

    def _create_directories(self, entries: SetupEntries):
        """
        Setup's `CreateDirs`: the directory of the application, then each [Dirs] entry.
        """
        installed = self.host.installed
        installed.add_directory(self.wizard.folder)
        for number, entry in entries.directories:
            where = EntryLocation(EntrySection.Dirs, number)
            if (texts := (yield from self._process(where, entry, Field(EntryField.Name, entry.Name)))) is not None:
                installed.add_directory(texts[0])

    def _update_run_list(self):
        """
        Setup's `UpdateRunList`: the post-install run entries that apply, with their descriptions,
        or the names of their programs, checked unless they are unchecked by default.
        """
        run_list = self.wizard.run_list
        run_list.clear()
        if (entries := self.entries) is None:
            return
        for loaded in entries.run:
            number, entry = loaded
            if not entry.Flags & SetupRunFlags.PostInstall:
                continue
            where = EntryLocation(EntrySection.Run, number)
            if not (yield from self._should_process_run(where, entry)):
                continue
            if entry.Description:
                yield from self.fields(where, Field(EntryField.Description, entry.Description))
            else:
                yield from self.fields(where, Field(EntryField.Filename, entry.Name))
            run_list.add_check_box(0, not entry.Flags & SetupRunFlags.Unchecked, True, True, True, loaded)

    def _run_post_install_entries(self):
        """
        Runs the entries that are checked on the finished page, as Setup's `TMainForm.Finish` does.
        """
        if self.wizard.needs_restart:
            return
        for number, entry in list(self.wizard.run_list.entries()):
            yield from self._run_entry(EntryLocation(EntrySection.Run, number), entry)

    def _run_entry(self, where: EntryLocation, entry: SetupRunEntry):
        """
        Setup's processing of a run entry that it runs: BeforeInstall, the fields that it expands
        before it starts the program, and AfterInstall; a failed field ends only the program.
        """
        condition = entry.Condition
        yield from self._notify(EntryParameter.BeforeInstall, where, condition.BeforeInstall)
        yield from self._run_fields(where, entry)
        yield from self._notify(EntryParameter.AfterInstall, where, condition.AfterInstall)

    def _run_fields(self, where: EntryLocation, entry: SetupRunEntry):
        """
        The fields of a run entry that Setup expands to start its program, in Setup's order. An
        entry that is skipped when its file does not exist expands no more after that test. Before
        Inno Setup 7, Setup expands the working directory only when it starts the program, and the
        32-bit Setup evaluates the arguments of a call that go on the stack before the others.
        """
        shell = bool(entry.Flags & SetupRunFlags.ShellExec)
        skip = bool(entry.Flags & SetupRunFlags.SkipIfDoesntExist)
        always = self.setup.run_working_dir_always
        installed = self.host.installed
        fields = [Field(EntryField.Filename, entry.Name), Field(EntryField.Parameters, entry.Parameters)]
        if always:
            fields.append(Field(EntryField.WorkingDir, entry.WorkingDir))
        if (texts := (yield from self.fields(where, *fields))) is None:
            return
        filename = texts[0]
        if skip and not (installed.exists(filename) if shell else installed.file_exists(filename)):
            return
        if always:
            if shell:
                yield from self.fields(where, Field(EntryField.Verb, entry.Verb))
        elif shell:
            yield from self.fields(where, Field(EntryField.WorkingDir, entry.WorkingDir), Field(EntryField.Verb, entry.Verb))
        else:
            yield from self.fields(where, Field(EntryField.WorkingDir, entry.WorkingDir))

    def _create_ini_entry(self, where: EntryLocation, entry: SetupIniEntry):
        """
        Setup's processing of an INI entry: the section, the key, the value and the file, which
        Setup writes when the entry has a key and a value; the emulated machine has no INI file
        with a key that the entry would only create.
        """
        condition = entry.Condition
        if not (yield from self._should_process_entry(where, condition)):
            return
        yield from self._notify(EntryParameter.BeforeInstall, where, condition.BeforeInstall)
        texts = yield from self.fields(
            where,
            Field(EntryField.Section, entry.Section),
            Field(EntryField.Key, entry.Key),
            Field(EntryField.String, entry.Value),
            Field(EntryField.Filename, entry.IniFile),
        )
        if texts is None:
            return
        _, key, _, filename = texts
        if key and entry.Flags & SetupIniFlags.HasValue:
            self.host.installed.add_file(filename)
        yield from self._notify(EntryParameter.AfterInstall, where, condition.AfterInstall)

    def _create_registry_entry(self, where: EntryLocation, entry: SetupRegistryEntry):
        """
        Setup's processing of a registry entry: the key and the value name, then the data of a value
        with text data that it writes into a key that opens. Setup creates the key unless the entry
        says not to; such a key opens when the emulated registry has it. An error in the data does
        not end the entry.
        """
        condition = entry.Condition
        if not (yield from self._should_process_entry(where, condition)):
            return
        yield from self._notify(EntryParameter.BeforeInstall, where, condition.BeforeInstall)
        texts = yield from self.fields(where, Field(EntryField.Subkey, entry.Key), Field(EntryField.ValueName, entry.Name))
        if texts is None:
            return
        kind = entry.Type
        if kind in _REGISTRY_TEXT_TYPES and (
            not entry.Flags & SetupRegistryFlags.DontCreateKey
            or self.host.registry_key_exists(texts[0])
        ):
            if kind is SetupRegistryType.MultiString:
                custom = {'olddata': '', 'break': '\0'}
            elif kind is SetupRegistryType.DWord or kind is SetupRegistryType.QWord:
                custom = None
            else:
                custom = {'olddata': ''}
            yield from self.fields(where, Field(EntryField.ValueData, entry.ValueText, custom))
        yield from self._notify(EntryParameter.AfterInstall, where, condition.AfterInstall)

    def _copy_file(self, loaded: Loaded[SetupFile], uninstallable: bool):
        """
        Setup's `CopyFiles` for one entry: the check, BeforeInstall, the names that Setup expands to
        install the file, and AfterInstall. A downloaded archive is a local archive by then.
        """
        number, entry = loaded
        if entry.Type == SetupFileType.UninstExe:
            if uninstallable:
                self.host.installed.add_file(self.wizard.uninstaller)
            return
        if entry.Type != SetupFileType.UserFile:
            return
        if not (yield from self._should_process_file(loaded)):
            return
        where = EntryLocation(EntrySection.Files, number)
        current = self._current(loaded)
        condition = entry.Condition
        yield from self._notify(EntryParameter.BeforeInstall, where, condition.BeforeInstall, current)
        if (yield from self._install_file(where, loaded)):
            yield from self._notify(EntryParameter.AfterInstall, where, condition.AfterInstall, current)

    def _view(self, loaded: Loaded[SetupFile]) -> tuple[str, str, SetupFileFlags]:
        """
        The source, the destination and the flags of a file entry as Setup holds them: once an
        archive was downloaded, the entry names the archive in the temporary directory, its
        destination is a folder that ends in a backslash, as `PathExtractPath` gives it, and it is
        no longer a download.
        """
        number, entry = loaded
        if (archive := self.downloaded.get(number)) is not None:
            flags = entry.Flags & ~(SetupFileFlags.Download | SetupFileFlags.CustomDestName)
            destination = entry.Destination
            folder = destination[:len(destination) - len(ntpath.basename(destination))]
            return archive, folder, flags
        return entry.Source, entry.Destination, entry.Flags

    def _current(self, loaded: Loaded[SetupFile]) -> CurrentFile:
        source, destination, _ = self._view(loaded)
        return CurrentFile(destination, source)

    def _install_file(self, where: EntryLocation, loaded: Loaded[SetupFile]) -> Generator[Any, Any, bool]:
        """
        The names that Setup expands to install a file, and the paths that it creates. An error
        that Setup asks to retry or ignore is ignored; the result tells whether Setup reaches
        AfterInstall.
        """
        _, entry = loaded
        source, destination, flags = self._view(loaded)
        if not entry.external:
            if (texts := (yield from self.fields(where, Field(EntryField.DestName, destination)))) is not None:
                yield from self._process_file(where, entry, texts[0], download=False)
            return True
        if (texts := (yield from self.fields(where, Field(EntryField.Source, source)))) is None:
            return False
        if flags & SetupFileFlags.Download:
            if (texts := (yield from self.fields(where, Field(EntryField.DestName, destination)))) is None:
                return False
            yield from self._process_file(where, entry, texts[0], download=True)
            return True
        return (yield from self._existing_sources(where, entry, texts[0], destination, flags, True)) is not None

    def _existing_sources(
        self,
        where: EntryLocation,
        entry: SetupFile,
        source: str,
        destination: str,
        flags: SetupFileFlags,
        install: bool,
    ) -> Generator[Any, Any, list[str] | None]:
        """
        Setup's walk over the sources of an external file that exist: an archive to extract gives
        its folder and its password, any other source the destination of each file found. The
        result holds the destinations, `None` when a field failed. An installation creates the
        files and ignores an error in the password, which ends the scan of the restart manager.
        """
        installed = self.host.installed
        if flags & SetupFileFlags.ExtractArchive:
            if not installed.file_exists(source):
                return []
            if (yield from self.fields(where, Field(EntryField.DestName, destination))) is None:
                return None
            password = yield from self.fields(where, Field(EntryField.ExtractArchivePassword, entry.ExtractArchivePassword))
            if password is None and not install:
                return None
            return []
        names: list[str] = []
        for path in installed.files_matching(source):
            if (texts := (yield from self.fields(where, Field(EntryField.DestName, destination)))) is None:
                return None
            name = texts[0] if flags & SetupFileFlags.CustomDestName else texts[0] + ntpath.basename(path)
            names.append(name)
            if install:
                installed.add_file(name)
        return names

    def _process_file(self, where: EntryLocation, entry: SetupFile, destination: str, download: bool):
        """
        Setup's `ProcessFileEntry` once the destination is known: a file that may only replace an
        existing one, or only be installed when none exists, is skipped; a download expands its
        credentials. The file exists afterwards.
        """
        installed = self.host.installed
        flags = entry.Flags
        exists = installed.file_exists(destination)
        if exists and flags & SetupFileFlags.OnlyIfDoesntExist:
            return
        if not exists and flags & SetupFileFlags.OnlyIfDestFileExists:
            return
        if download:
            fields = [
                Field(EntryField.DownloadUserName, entry.DownloadUserName),
                Field(EntryField.DownloadPassword, entry.DownloadPassword),
            ]
            if entry.Verification is not None and entry.Verification.Type == SetupFileVerificationType.ISSig:
                fields.append(Field(EntryField.DownloadISSigSource, entry.DownloadISSigSource))
            if (yield from self.fields(where, *fields)) is None:
                return
        installed.add_file(destination)

    def _create_icon(self, loaded: Loaded[SetupIcon]):
        """
        Setup's `CreateIcons` for one entry. Setup creates the icon only when its file exists if the
        entry says so; the 32-bit Setup evaluates the arguments that go on the stack first, the
        64-bit Setup from left to right. The icon is a shortcut file named after the entry, or an
        internet shortcut for a URL. An error ends the entry without AfterInstall.
        """
        number, entry = loaded
        where = EntryLocation(EntrySection.Icons, number)
        condition = entry.Condition
        if (
            self.wizard.icons_off
            and not condition.Tasks
            and entry.Name.startswith('{group}\\')
        ):
            return
        if not (yield from self._should_process_entry(where, condition)):
            return
        yield from self._notify(EntryParameter.BeforeInstall, where, condition.BeforeInstall)
        if (texts := (yield from self.fields(where, Field(EntryField.Filename, entry.FileName)))) is None:
            return
        target = texts[0]
        if not entry.Flags & SetupIconFlags.CreateOnlyIfFileExists or self.host.installed.file_exists(target):
            arguments = [
                Field(EntryField.Parameters, entry.Parameters),
                Field(EntryField.WorkingDir, entry.WorkingDir),
                Field(EntryField.IconFilename, entry.IconFile),
                Field(EntryField.AppUserModelID, entry.AppUserModelId),
            ]
            comment = Field(EntryField.Comment, entry.Comment)
            if self.setup.platform is Platform.Win64:
                fields = [comment, *arguments]
            else:
                fields = [*arguments, comment]
            fields.append(Field(EntryField.Name, entry.Name))
            if (texts := (yield from self.fields(where, *fields))) is None:
                return
            extension = '.url' if _a_url(target) else '.lnk'
            self.host.installed.add_file(F'{texts[-1]}{extension}')
        yield from self._notify(EntryParameter.AfterInstall, where, condition.AfterInstall)

    def _process(self, where: EntryLocation, entry: Any, *fields: Field) -> Generator[Any, Any, list[str] | None]:
        """
        Setup's processing of an entry: the check, BeforeInstall, the fields that it expands in
        order, and AfterInstall. A field that fails ends the entry. The result holds the expanded
        fields, `None` when the entry was not processed to its end.
        """
        condition = entry.Condition
        if not (yield from self._should_process_entry(where, condition)):
            return None
        yield from self._notify(EntryParameter.BeforeInstall, where, condition.BeforeInstall)
        if (texts := (yield from self.fields(where, *fields))) is None:
            return None
        yield from self._notify(EntryParameter.AfterInstall, where, condition.AfterInstall)
        return texts

    def fields(self, where: EntryLocation, *fields: Field) -> Generator[Any, Any, list[str] | None]:
        """
        Expands the given fields of an entry in order, as Setup does where it uses them, each with
        its custom constants. A failure is reported and stops the expansion. The result holds the
        expanded texts, `None` when a field failed.
        """
        texts: list[str] = []
        for name, text, custom in fields:
            if not text:
                texts.append('')
                continue
            value = yield from self._guarded(EntryParameter.Field, where._replace(field=name), self.host.expand(text, custom))
            if value is None:
                return None
            texts.append(value)
        return texts

    def _guarded(
        self,
        parameter: EntryParameter | YesNoDirective,
        where: EntryLocation | Callable[[], EntryLocation] | None,
        call: Generator[Any, Any, _E],
    ) -> Generator[Any, Any, _E | None]:
        """
        Runs one call of the script for an entry or a directive. A script error is reported as a
        `NewScriptError`, a failure of the emulator as a `NewEmulationError`, and the result is then
        `None`; an error that ends the emulation is passed on. The location of an entry may be a
        function when the entry is known only once the call failed; a directive has none.
        """
        try:
            return (yield from _within_python(call))
        except EmulatorException:
            raise
        except (IFPSException, DelphiException) as error:
            location = where if where is None or isinstance(where, EntryLocation) else where()
            yield NewScriptError(parameter, (), str(error), location)
        except Exception as error:
            location = where if where is None or isinstance(where, EntryLocation) else where()
            yield NewEmulationError(parameter if location is None else str(location), exception_to_string(error))
        return None

    def _read(self, section: EntrySection, reader: Callable[[Any], Generator[Any, Any, list[str]]]):
        """
        Runs one of Setup's readers of the selected components or tasks; the reader ends at the
        first field that fails, which is reported with its entry.
        """
        last: list[Any] = [None, None]

        def expand(entry: Any, field: EntryField, text: str):
            last[0] = entry
            last[1] = field
            return self.host.expand(text)

        def where() -> EntryLocation:
            return EntryLocation(section, self._numbers[section][id(last[0])], last[1])

        return (yield from self._guarded(EntryParameter.Field, where, reader(expand)))

    def _quietly(self, call: Generator[Any, Any, Any]) -> Generator[Any, Any, Any]:
        """
        Runs a call of the script whose errors Setup ignores; an error that ends the emulation is
        passed on.
        """
        try:
            return (yield from _within_python(call))
        except EmulatorException:
            raise
        except Exception:
            return None

    def _notify(self, parameter: EntryParameter, where: EntryLocation, text: str | None, current: CurrentFile | None = None):
        """
        Calls a `BeforeInstall` or `AfterInstall` function as Setup's `NotifyInstallEntry` does,
        with the names of the file of a [Files] entry for `CurrentFilename`. An error is reported
        and the installation goes on.
        """
        if not text:
            return
        host = self.host
        host.current_file = current
        evaluation = expressions.evaluate(text, self._install_function, expressions.INSTALL, host.expand)
        try:
            yield from self._guarded(parameter, where, evaluation)
        finally:
            host.current_file = None

    def _install_function(self, name: str, parameters: list[expressions.Parameter]):
        yield from self.host.call_by_name(name, list(parameters), SetupCall.of_parameters(parameters, None))
        return True

    def _check_function(self, name: str, parameters: list[expressions.Parameter]):
        call = SetupCall.of_parameters(parameters, ArgumentKind.Boolean)
        return bool((yield from self.host.call_by_name(name, list(parameters), call)))

    def _check(self, where: EntryLocation, text: str) -> Generator[Any, Any, bool]:
        """
        Evaluates a `Check` parameter as Setup's `EvalCheck` does inside `ShouldProcessEntry`: an
        error ends the expression, is reported, and the entry counts as not processed.
        """
        evaluation = expressions.evaluate(text, self._check_function, expressions.CHECK, self.host.expand)
        return bool((yield from self._guarded(EntryParameter.Check, where, evaluation)))

    def directive(self, name: YesNoDirective, directive: SetupDirective) -> Generator[Any, Any, bool]:
        """
        Evaluates a yes-or-no directive as Setup's `EvalDirectiveCheck` does. Setup ends the
        installation on an error; the emulator reports it and takes the answer as no.
        """
        if (answer := directive.answer) is not None:
            return answer
        evaluation = expressions.evaluate(directive.expression, self._check_function, expressions.CHECK, self.host.expand)
        return bool((yield from self._guarded(name, None, evaluation)))

    def _should_process_entry(
        self,
        where: EntryLocation,
        condition: Any,
        selection: Selection | None = None,
    ) -> Generator[Any, Any, bool]:
        """
        Setup's `ShouldProcessEntry` for an entry with the common parameters.
        """
        return (yield from self._should_process(
            where,
            condition.Components,
            condition.Tasks,
            condition.Languages,
            condition.Check,
            self.selection if selection is None else selection,
        ))

    def _should_process(
        self,
        where: EntryLocation,
        components: str | None,
        tasks: str | None,
        languages: str | None,
        check: str | None,
        selection: Selection,
    ) -> Generator[Any, Any, bool]:
        """
        Setup's `ShouldProcessEntry`: the components, tasks and languages of the entry by name, each
        tested in full, then its check when all three hold. Without a list of names, Setup does not
        test them; the emulator does not know the names when the script changed the lists in a way
        that it does not model. An error in a test ends the tests: Setup ends the installation
        there, the emulator reports the error and does not process the entry.
        """
        if not (components or tasks or languages or check):
            return True
        language = self.setup.language_name
        tests: list[tuple[EntryParameter, str, Callable[[str], bool]]] = []
        for parameter, expression, names in (
            (EntryParameter.Components, components, selection.components),
            (EntryParameter.Tasks, tasks, selection.tasks),
        ):
            if expression and names is not None:
                tests.append((parameter, expression, lambda name, names=names: list_contains(names, name)))
        if languages:
            tests.append((EntryParameter.Languages, languages, lambda name: same_text(language, name)))
        processed = True
        for parameter, expression, identifier in tests:
            if (decided := (yield from self._decide(parameter, where, expression, identifier))) is None:
                return False
            processed = processed and decided
        if not processed or not check:
            return processed
        return (yield from self._check(where, check))

    def _decide(
        self,
        parameter: EntryParameter,
        where: EntryLocation,
        expression: str,
        identifier: Callable[[str], bool],
    ) -> Generator[Any, Any, bool | None]:
        """
        Evaluates an expression of names as Setup's `EvalExpression` does; an error is reported, and
        the result is then `None`.
        """
        def decision() -> Generator[Any, Any, bool]:
            return expressions.decide(expression, identifier)
            yield

        return (yield from self._guarded(parameter, where, decision()))

    def _should_process_file(self, loaded: Loaded[SetupFile], selection: Selection | None = None) -> Generator[Any, Any, bool]:
        """
        Setup's `ShouldProcessFileEntry`: a file that is never copied is not processed; while its
        check runs, the entry is the current file.
        """
        number, entry = loaded
        if entry.Flags & SetupFileFlags.DontCopy:
            return False
        where = EntryLocation(EntrySection.Files, number)
        host = self.host
        host.current_file = self._current(loaded)
        try:
            return (yield from self._should_process_entry(where, entry.Condition, selection))
        finally:
            host.current_file = None

    def _should_process_run(self, where: EntryLocation, entry: SetupRunEntry) -> Generator[Any, Any, bool]:
        """
        Setup's `ShouldProcessRunEntry`: an entry for silent installations only, or for others only,
        is skipped before its conditions.
        """
        silent = self.config.wizard_silent
        if silent and entry.Flags & SetupRunFlags.SkipIfSilent:
            return False
        if not silent and entry.Flags & SetupRunFlags.SkipIfNotSilent:
            return False
        return (yield from self._should_process_entry(where, entry.Condition))

    def _shown(
        self,
        section: EntrySection,
        entries: Iterable[Loaded[_L]],
        show: Callable[[EntryLocation, _L], Generator[Any, Any, bool]],
    ) -> Generator[Any, Any, list[Loaded[_L]]]:
        """
        The walk of Setup over the levels of components or tasks: an entry is shown when its level
        is at most one below the last entry shown, its version of Windows is the emulated one, and
        `show` shows it when its other conditions allow it. An entry that is not shown hides the
        entries below it, unless it repeats the last entry shown, whose children may then follow.
        """
        cfg = self.config
        shown: list[Loaded[_L]] = []
        allowed = 0
        last: _L | None = None
        for loaded in entries:
            self.host.check_time()
            number, entry = loaded
            if (
                entry.Level <= allowed
                and installs_on(entry.WindowsVersion, cfg.windows_os_version, cfg.windows_sp_version)
                and (yield from show(EntryLocation(section, number), entry))
            ):
                allowed = entry.Level + 1
                last = entry
                shown.append(loaded)
            elif last is None or entry.Level != last.Level or not same_text(entry.Name, last.Name):
                allowed = min(allowed, entry.Level)
                last = None
        return shown

    def _load_types_and_components(self):
        """
        Removes the types and components whose conditions fail, as Setup does right after
        `InitializeSetup`.
        """
        if (entries := self.entries) is None:
            return
        unselected = Selection(None, None)
        for loaded in entries.types:
            number, entry = loaded
            where = EntryLocation(EntrySection.Types, number)
            if (yield from self._should_process(where, None, None, entry.Languages, entry.Check, unselected)):
                self._loaded_types.append(loaded)
        self.wizard.types = [entry for _, entry in self._loaded_types]

        def show(where: EntryLocation, entry: SetupComponent):
            return self._should_process(where, None, None, entry.Languages, entry.Check, unselected)

        self._loaded_components = yield from self._shown(EntrySection.Components, entries.components, show)

    def _measure_external_files(self):
        """
        Setup expands the source of each external file without a given size to measure it; it
        ignores every error there.
        """
        if (entries := self.entries) is None:
            return
        for _, entry in entries.files:
            flags = entry.Flags
            if not entry.external or flags & SetupFileFlags.ExternalSizePreset or flags & SetupFileFlags.Download:
                continue
            if flags & SetupFileFlags.ExtractArchive:
                yield from self._quietly(self._expand_all(entry.Source, entry.ExtractArchivePassword))
            elif entry.Type == SetupFileType.UserFile:
                yield from self._quietly(self._expand_all(entry.Source))

    def _expand_all(self, *texts: str | None):
        for text in texts:
            if text:
                yield from self.host.expand(text)

    def _create_wizard(self):
        """
        The part of creating the wizard that reads the entries: the descriptions of the types and
        components, the components in their list, and the components of the first type. The boxes
        of the folder and the group hold their stand-ins, and those of the user information are
        unknown. The form exists afterwards.
        """
        wizard = self.wizard
        wizard.dir_edit.set_text(wizard.stand_ins.folder)
        wizard.group_edit.set_text(wizard.stand_ins.group)
        for box in wizard.user_info_boxes:
            box.touched()
        if self.entries is None:
            wizard.created = True
            return
        for number, entry in self._loaded_types:
            yield from self.fields(EntryLocation(EntrySection.Types, number), Field(EntryField.Description, entry.Description))
        wizard.type_index = 0 if wizard.types else -1
        components = wizard.components
        for number, entry in self._loaded_components:
            yield from self.fields(EntryLocation(EntrySection.Components, number), Field(EntryField.Description, entry.Description))
            enabled = not entry.Flags & SetupFlags.Fixed
            try:
                if entry.Flags & SetupFlags.Exclusive:
                    components.add_radio_button(entry.Level, False, enabled, entry)
                else:
                    components.add_check_box(
                        entry.Level,
                        False,
                        enabled,
                        entry.Used,
                        not entry.Flags & SetupFlags.DontInheritCheck,
                        entry,
                    )
            except DelphiException as error:
                raise AbortEmulation(F'Setup cannot create its wizard: {error}') from error
        if wizard.types:
            wizard.select_components_from_type(wizard.types[0].Name, False)
        wizard.created = True

    def _create_task_list(self):
        """
        Builds the task list for the selected components as Setup's `CreateTaskButtons` does when
        Next reaches the tasks page: each task that its level, components, languages and check
        allow, with its description and group, checked unless it is unchecked by default; the check
        marks of the tasks that were already in the list are kept.
        """
        wizard = self.wizard
        if (entries := self.entries) is None:
            return
        tasks = wizard.tasks
        selected = [task.Name for task in tasks.entries()]
        deselected = [task.Name for task in tasks.unchecked_entries()]
        selection = Selection(wizard.selection().components, None)
        tasks.clear()
        group = ''

        def show(where: EntryLocation, entry: SetupTask):
            nonlocal group
            if not (yield from self._should_process(where, entry.Components, None, entry.Languages, entry.Check, selection)):
                return False
            yield from self.fields(where, Field(EntryField.Description, entry.Description))
            description = ''
            if entry.GroupDescription:
                expansion = self.fields(where, Field(EntryField.GroupDescription, entry.GroupDescription))
                if (texts := (yield from expansion)) is not None:
                    description = texts[0]
            if entry.Level == 0 and description != group:
                tasks.add_group()
                group = description
            checked = not entry.Flags & SetupTaskFlags.Unchecked
            if entry.Flags & SetupTaskFlags.Exclusive:
                tasks.add_radio_button(entry.Level, checked, True, entry)
            else:
                tasks.add_check_box(entry.Level, checked, True, entry.Used, not entry.Flags & SetupTaskFlags.DontInheritCheck, entry)
            return True

        yield from self._shown(EntrySection.Tasks, entries.tasks, show)
        wizard.select_tasks(selected, deselected)

    def _update_ready_page(self):
        """
        The part of Setup's `UpdateReadyPage` that runs code of the script: the description of the
        selected type and the selected components when the installer has components, the selected
        tasks with their groups, then `UpdateReadyMemo`. Each reader of the selection ends at its
        first error. The texts of the memo are not built.
        """
        wizard = self.wizard
        if self.entries is not None and self._loaded_components:
            if (setup_type := wizard.setup_type) is not None:
                number = self._loaded_types[wizard.type_index].number
                where = EntryLocation(EntrySection.Types, number, EntryField.Description)
                yield from self._guarded(EntryParameter.Field, where, self.host.expand(setup_type.Description))
            yield from self._read(EntrySection.Components, lambda expand: wizard.selected_components(True, True, expand))
        yield from self._read(EntrySection.Tasks, lambda expand: wizard.selected_tasks(True, True, True, expand))
        yield from self.event(SetupEvent.UpdateReadyMemo, '      ', '\r\n', '', '', '', '', '', '')

    def _scan_files(self):
        """
        Setup's `EnumFiles` for the restart manager: every file that would be installed, by its
        destination or, for an external file, its source and the destination of each source that
        exists, then every file that InstallDelete would delete. A failure ends the scan.
        """
        if (entries := self.entries) is None:
            return
        selection = self.selection
        for loaded in entries.files:
            number, entry = loaded
            if entry.Type != SetupFileType.UserFile:
                continue
            if not (yield from self._should_process_file(loaded, selection)):
                continue
            where = EntryLocation(EntrySection.Files, number)
            source, destination, flags = self._view(loaded)
            if not entry.external or flags & SetupFileFlags.Download:
                if (yield from self.fields(where, Field(EntryField.DestName, destination))) is None:
                    return
                continue
            if (texts := (yield from self.fields(where, Field(EntryField.Source, source)))) is None:
                return
            if (yield from self._existing_sources(where, entry, texts[0], destination, flags, False)) is None:
                return
        for number, entry in entries.install_delete:
            where = EntryLocation(EntrySection.InstallDelete, number)
            if not (yield from self._should_process_entry(where, entry.Condition, selection)):
                continue
            if (yield from self.fields(where, Field(EntryField.Name, entry.Name))) is None:
                return

    def _download_archives(self):
        """
        Setup's `DownloadArchivesToExtract`: each file to download and extract, with its check and
        the fields of its download; 6.5.0 and 6.5.1 test the components as the tasks. Setup expands
        the fields of every archive before it downloads any, so an error downloads none. The
        emulated download succeeds: the archive is then a file in the temporary directory, and the
        entry takes it as its source. The download page is not modelled.
        """
        if (entries := self.entries) is None:
            return
        selection = self.selection
        if self.setup.download_tests_components_as_tasks:
            selection = Selection(selection.components, selection.components)
        downloads: list[Loaded[SetupFile]] = []
        for loaded in entries.files:
            number, entry = loaded
            flags = entry.Flags
            if not flags & SetupFileFlags.Download or not flags & SetupFileFlags.ExtractArchive:
                continue
            if not (yield from self._should_process_file(loaded, selection)):
                continue
            where = EntryLocation(EntrySection.Files, number)
            fields = [
                Field(EntryField.Source, entry.Source),
                Field(EntryField.DownloadUserName, entry.DownloadUserName),
                Field(EntryField.DownloadPassword, entry.DownloadPassword),
            ]
            if entry.Verification is not None and entry.Verification.Type == SetupFileVerificationType.ISSig:
                fields.append(Field(EntryField.DownloadISSigSource, entry.DownloadISSigSource))
            if (yield from self.fields(where, *fields)) is None:
                return
            downloads.append(loaded)
        for number, entry in downloads:
            archive = F'{self.host.temporary_directory}\\_isetup{number}.tmp\\{ntpath.basename(entry.Destination)}'
            self.downloaded[number] = archive
            self.host.installed.add_file(archive)

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
        call = _EVENT_CALLS[event]
        result = default
        for function in self.implementations(event):
            try:
                value = yield from self.host.call_from_setup(function, args, call)
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
        if (known := self.wizard.page_objects.get(page)) is None:
            return None
        if (function := known.handlers.get(event)) is None:
            return None
        try:
            return (yield from self.host.call_from_setup(function, (known,), _PAGE_CALLS[event]))
        except IFPSException as error:
            message = str(error)
        yield NewScriptError(event, (known,), message)
        return None
