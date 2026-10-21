"""
Inno Setup as the host of a script: what Setup decides on its own from its installer and the
configuration, `HostSetup`, and the values of its constants on the emulated machine,
`SetupConstants`. Neither needs the script; an installer without one has both.
"""
from __future__ import annotations

import random

from dataclasses import dataclass
from enum import Enum, auto
from functools import cached_property
from typing import TYPE_CHECKING, Any, Generator, Mapping, NamedTuple

from refinery.lib.inno import constants, expressions
from refinery.lib.inno.archive import (
    Architecture,
    AutoBool,
    Flags,
    InnoArchive,
    InnoVersion,
    LanguageDetection,
    PrivilegesRequired,
    SetupDirective,
    SetupMessageName,
    SetupMessages,
    TSetup,
    YesNoDirective,
)
from refinery.lib.inno.delphi import numbers, x87
from refinery.lib.inno.delphi.runtime import Platform, Runtime, Win32, Win64
from refinery.lib.inno.emulation import InternalError
from refinery.lib.inno.pathfunc import PathFunc
from refinery.lib.inno.release import SetupRelease
from refinery.lib.inno.wizard import WizardForm, same_text

if TYPE_CHECKING:
    from refinery.lib.inno.emulator import IFPSEmulatorConfig


@dataclass(frozen=True)
class HostSetup:
    """
    What Setup decides on its own, read once from the setup header and the configuration: its
    version and release, the active language and its messages, the directives that the
    installation follows, the pages that the header makes it skip, its install modes, and how its
    release behaves where releases differ. A bare script has no header; it is taken to run under
    the Setup of the configured version, or the current Setup without one, with every page shown
    and every directive that sends an event on, so that each event that the script handles is
    sent, and in the install mode that its Setup has without the directive. None of this needs the
    script; the emulator checks that its script agrees.
    """
    version: InnoVersion | None
    release: SetupRelease
    language: int | None
    language_name: str
    platform: Platform
    install_mode: InstallMode
    restart_manager: bool
    uninstallable: SetupDirective
    uninstall_key: SetupDirective
    changes_environment: SetupDirective
    changes_associations: SetupDirective
    always_restart: bool
    header_password: bool
    welcome_page_disabled: bool
    license_text: bool
    info_before_text: bool
    user_info_page: bool
    dir_page_disabled: bool
    group_page_disabled: bool
    ready_page_disabled: bool
    ready_memo_disabled: bool
    info_after_text: bool
    finished_page_disabled: bool
    admin_install_mode: bool
    """
    Setup installs for all users: the user is an administrator and the installer does not ask for
    the lowest privileges.
    """
    always_use_personal_group: bool
    always_show_dir_on_ready_page: bool
    always_show_group_on_ready_page: bool
    allow_unc_path: bool
    allow_root_directory: bool
    setup_info: TSetup | None

    @property
    def messages(self) -> SetupMessages | None:
        """
        The messages of the active language, `None` for a bare script or when they fail Setup's
        checks.
        """
        if (setup_info := self.setup_info) is None or (language := self.language) is None:
            return None
        try:
            return setup_info.messages(language)
        except ValueError:
            return None

    def error_text(self, error: BaseException) -> str:
        """
        The text of an error as Setup gives it: an internal error has the frame of the message
        `ErrorInternal2` in the active language, or the English frame when the emulator does not
        have the language's messages.
        """
        if isinstance(error, InternalError) and (messages := self.messages) is not None:
            if (frame := messages.named(SetupMessageName.ErrorInternal2)) is not None:
                return constants.fmt_message(frame, [error.reason])
        return str(error)

    def custom_message(self, name: str) -> str | None:
        """
        The custom message with the given name, compared without case, as Setup's
        `GetCustomMessageValue` finds it: the last one that is for all languages or for the active
        language. A bare script has no messages; its message is the constant that names it.
        """
        if (setup_info := self.setup_info) is None:
            return F'{{cm:{name}}}'
        value = None
        folded = name.casefold()
        for message in setup_info.CustomMessages:
            if message.EncodedName.casefold() != folded:
                continue
            if (index := message.get_language_index()) == -1 or index == self.language:
                value = message.Value
        return value

    def message(self, index: int) -> str:
        """
        Setup's message with the given index in the active language, as `SetupMessage` returns it.
        A message that the emulator does not have is the call that asks for it.
        """
        name = None
        if (messages := self.messages) is not None and (known := messages.list) is not None:
            for candidate, position in zip(SetupMessageName, known.positions):
                if position == index:
                    name = candidate
        if name is not None:
            return self.named_message(name)
        if messages is None or not 0 <= index < len(messages):
            return F'SetupMessage({index})'
        return messages[index]

    def named_message(self, name: SetupMessageName) -> str:
        """
        The message with the given name as Setup holds it in the active language: from 6.1.1 on,
        Setup removes every `< ` from Back and every ` >` from Next. A message that the emulator
        does not have is the call that asks for it.
        """
        stand_in = F'SetupMessage(msg{name.value})'
        if (messages := self.messages) is None or (text := messages.named(name)) is None:
            return stand_in
        if name in (SetupMessageName.ButtonBack, SetupMessageName.ButtonNext):
            try:
                strips = self.release.since((6, 1, 1))
            except NotImplementedError:
                return stand_in
            if strips:
                text = text.replace('< ' if name is SetupMessageName.ButtonBack else ' >', '')
        return text

    @property
    def path_func(self) -> PathFunc:
        """
        Setup's path functions.
        """
        return PathFunc.of(self.release)

    @property
    def page_changes_only(self) -> bool:
        """
        Setup calls `CurPageChanged` only when the page changes, as Inno Setup 6.5 does.
        """
        return self.release.since((6, 5, 0)) and not self.release.since((6, 6, 0))

    @property
    def prepares_with_selection(self) -> bool:
        """
        The preparing page passes the selected components and tasks to its scans; 5.5.0 passes
        lists that are still empty.
        """
        return self.release.since((5, 5, 1))

    @property
    def registers_close_applications_resources(self) -> bool:
        """
        The restart manager's scan calls `RegisterExtraCloseApplicationsResources`, from 5.5.2 on.
        """
        return self.release.since((5, 5, 2))

    @property
    def evaluates_change_directives(self) -> bool:
        """
        The directives `ChangesEnvironment` and `ChangesAssociations` may be expressions, from
        6.0.0 on.
        """
        return self.release.since((6, 0, 0))

    @property
    def downloads_archives(self) -> bool:
        """
        The preparing page downloads the archives to extract, from 6.5.0 on.
        """
        return self.release.since((6, 5, 0))

    @property
    def download_tests_components_as_tasks(self) -> bool:
        """
        The download of archives tests the components of an entry as its tasks, in 6.5.0 and
        6.5.1.
        """
        return self.release.since((6, 5, 0)) and not self.release.since((6, 5, 2))

    @property
    def run_working_dir_always(self) -> bool:
        """
        A run entry expands its working directory before it tests whether its file exists, from
        7.0.0 on; earlier Setups expand it only to start the program.
        """
        return self.release.since((7, 0, 0))

    @classmethod
    def of_bare_script(cls, platform: Platform, config: IFPSEmulatorConfig) -> HostSetup:
        """
        The Setup of a script without its installer, for the given platform.
        """
        if (configured := config.setup_version) is None:
            release = SetupRelease.current()
        else:
            release = SetupRelease.exactly(configured)
        return cls(
            version=None,
            release=release,
            language=None,
            language_name=config.language,
            platform=platform,
            install_mode=InstallMode(platform is Platform.Win64 and config.x64),
            restart_manager=True,
            uninstallable=SetupDirective(True),
            uninstall_key=SetupDirective(True),
            changes_environment=SetupDirective(False),
            changes_associations=SetupDirective(False),
            always_restart=False,
            header_password=True,
            welcome_page_disabled=False,
            license_text=True,
            info_before_text=True,
            user_info_page=True,
            dir_page_disabled=False,
            group_page_disabled=False,
            ready_page_disabled=False,
            ready_memo_disabled=False,
            info_after_text=True,
            finished_page_disabled=False,
            admin_install_mode=config.admin,
            always_use_personal_group=False,
            always_show_dir_on_ready_page=False,
            always_show_group_on_ready_page=False,
            allow_unc_path=False,
            allow_root_directory=False,
            setup_info=None,
        )

    @classmethod
    def of_installer(cls, archive: InnoArchive, config: IFPSEmulatorConfig) -> HostSetup:
        """
        The Setup of an installer on the configured machine.
        """
        setup_info = archive.setup_info
        version = archive.version
        header = setup_info.Header
        flags = header.Flags
        language = _active_language(setup_info, config)
        texts = setup_info.wizard_texts(language)
        return cls(
            version=version,
            release=archive.release,
            language=language,
            language_name=setup_info.Languages[language].Name if language is not None else config.language,
            platform=Platform.Win64 if header.is_64bit else Platform.Win32,
            install_mode=_install_mode(header.ArchitecturesInstallIn64BitMode, config.x64),
            restart_manager=bool(flags & Flags.CloseApplications) and config.windows_os_version >= (6, 0),
            uninstallable=header.directive(YesNoDirective.Uninstallable),
            uninstall_key=header.directive(YesNoDirective.CreateUninstallRegKey),
            changes_environment=header.directive(YesNoDirective.ChangesEnvironment),
            changes_associations=header.directive(YesNoDirective.ChangesAssociations),
            always_restart=bool(flags & Flags.AlwaysRestart),
            header_password=bool(flags & Flags.Password),
            welcome_page_disabled=bool(flags & Flags.DisableWelcomePage),
            license_text=bool(texts.license),
            info_before_text=bool(texts.info_before),
            user_info_page=bool(flags & Flags.UserInfoPage),
            dir_page_disabled=header.DisableDirPage == AutoBool.Yes or not flags & Flags.CreateAppDir,
            group_page_disabled=header.DisableProgramGroupPage == AutoBool.Yes,
            ready_page_disabled=bool(flags & Flags.DisableReadyPage),
            ready_memo_disabled=bool(flags & Flags.DisableReadyMemo),
            info_after_text=bool(texts.info_after),
            finished_page_disabled=bool(flags & Flags.DisableFinishedPage),
            admin_install_mode=config.admin and header.PrivilegesRequired != PrivilegesRequired.Lowest,
            always_use_personal_group=bool(flags & Flags.AlwaysUsePersonalGroup),
            always_show_dir_on_ready_page=bool(flags & Flags.AlwaysShowDirOnReadyPage),
            always_show_group_on_ready_page=bool(flags & Flags.AlwaysShowGroupOnReadyPage),
            allow_unc_path=bool(flags & Flags.AllowUNCPath),
            allow_root_directory=bool(flags & Flags.AllowRootDirectory),
            setup_info=setup_info,
        )

    def runtime(self, settings: numbers.FormatSettings) -> Runtime:
        """
        The run-time library of a new process of this Setup.
        """
        if self.platform is Platform.Win64:
            return Win64(settings)
        return Win32(settings, _control_word(self.release))


class InstallMode(NamedTuple):
    """
    Whether Setup installs in 64-bit mode; the registry view and the folders of the .NET Framework
    that Setup reads follow it. When the emulator cannot decide the mode, `bits64` is `None` and
    `reason` says why; every value that depends on the mode then fails as a value that the emulator
    does not have.
    """
    bits64: bool | None
    reason: str = ''

    def decided(self) -> bool:
        if (bits64 := self.bits64) is None:
            raise NotImplementedError(F'The emulator cannot decide the install mode: {self.reason}')
        return bits64


class TSetupProcessorArchitecture(int, Enum):
    """
    An IFPS enumeration that classifies different processor architectures.
    """
    paUnknown = 0
    paX86 = auto()
    paX64 = auto()
    paArm32 = auto()
    paArm64 = auto()


_ARCHITECTURES: dict[str, tuple[TSetupProcessorArchitecture, bool]] = {
    'arm32compatible' : (TSetupProcessorArchitecture.paArm32, True),
    'arm64'           : (TSetupProcessorArchitecture.paArm64, False),
    'x64'             : (TSetupProcessorArchitecture.paX64, False),
    'x64os'           : (TSetupProcessorArchitecture.paX64, False),
    'x64compatible'   : (TSetupProcessorArchitecture.paX64, True),
    'x86'             : (TSetupProcessorArchitecture.paX86, False),
    'x86os'           : (TSetupProcessorArchitecture.paX86, False),
    'x86compatible'   : (TSetupProcessorArchitecture.paX86, True),
}
"""
Setup's architecture identifiers: the architecture each one names, and whether it asks for a
machine that runs code of that architecture rather than for a processor of it.
"""


def processor(x64: bool) -> TSetupProcessorArchitecture:
    """
    The processor of the emulated machine.
    """
    return TSetupProcessorArchitecture.paX64 if x64 else TSetupProcessorArchitecture.paX86


def architecture(name: str, x64: bool) -> bool:
    """
    Setup's `EvalArchitectureIdentifier` on the emulated machine: `win64` is 64-bit Windows, a
    compatible identifier holds when the machine runs code of the architecture, any other one when
    the processor is of the architecture.
    """
    if name == 'win64':
        return x64
    try:
        architecture, compatible = _ARCHITECTURES[name]
    except KeyError:
        raise expressions.ExpressionError(F'Unknown architecture \'{name}\'') from None
    if compatible:
        return architecture is TSetupProcessorArchitecture.paX86 or architecture is processor(x64)
    return architecture is processor(x64)


def _install_mode(directive: str | Architecture, x64: bool) -> InstallMode:
    """
    The install mode of Setup on the emulated machine: from 6.3.0 on, 64-bit when the expression of
    architecture identifiers holds; earlier, when the processor is in the set. Setup evaluates the
    expression on every machine and ends when it holds on 32-bit Windows; the emulator then goes
    on in 32-bit mode.
    """
    if isinstance(directive, Architecture):
        return InstallMode(x64 and Architecture.X64 in directive)
    if not directive:
        return InstallMode(False)
    try:
        holds = expressions.decide(directive, lambda name: architecture(name, x64))
    except InternalError as error:
        return InstallMode(None, str(error))
    except RecursionError:
        return InstallMode(None, 'the expression nests deeper than Python can follow')
    return InstallMode(x64 and holds)


def _control_word(release: SetupRelease) -> int:
    """
    The control word of the x87 that a 32-bit Setup runs the script with: Delphi 12, which builds
    Inno Setup from 6.4.3 on, masks every exception.
    """
    if release.since((6, 4, 3)):
        return x87.MASKED_CONTROL_WORD
    return x87.DEFAULT_CONTROL_WORD


def _active_language(setup_info: TSetup, config: IFPSEmulatorConfig) -> int | None:
    """
    The index of the language that Setup activates when the user accepts its choice, as Setup's
    `DetermineDefaultLanguage` finds it: the language with the configured name, which stands for
    the `/LANG=` parameter of Setup and is compared without case; else the language whose ID is
    the user's language, else the first whose primary language matches, else the first one. The
    configured language ID stands for both the language of the user interface and the locale.
    """
    if not (languages := setup_info.Languages):
        return None
    chosen = config.language
    for index, language in enumerate(languages):
        if same_text(language.Name, chosen):
            return index
    if setup_info.Header.LanguageDetection == LanguageDetection.Nothing:
        return 0
    wanted = config.lcid
    for index, language in enumerate(languages):
        if language.LanguageId.Value == wanted:
            return index
    for index, language in enumerate(languages):
        lcid = language.LanguageId.Value
        if lcid & 0x3FF != wanted & 0x3FF:
            continue
        if wanted & 0x3FF != 0x04 or (lcid in (0x0804, 0x1004)) == (wanted in (0x0804, 0x1004)):
            return index
    return 0


_PERSONAL_BEFORE_6 = {
    'commondesktop'   : 'userdesktop',
    'commonstartmenu' : 'userstartmenu',
    'commonprograms'  : 'userprograms',
    'commonstartup'   : 'userstartup',
    'commontemplates' : 'usertemplates',
    'commonfavorites' : 'userfavorites',
}
"""
The common shell folders that Setup before 6.0.0 replaces with the folders of the user when it does
not install for all users; the application data and the documents keep their common folders.
"""


def machine_folders(setup: HostSetup, config: IFPSEmulatorConfig) -> dict[str, str]:
    """
    The values of the constants without parameters on the emulated machine, by the names that
    Setup reads them as, but for the temporary folder of a Setup process. Names whose value
    depends on the version of Windows, on the setup or on the progress of the installation are
    decided by `SetupConstants.constant`.
    """
    cfg = config
    user = RF'C:\Users\{cfg.user_name}'
    map = {
        'win'               : R'C:\Windows',
        'sys'               : R'C:\Windows\System32',
        'src'               : setup.path_func.extract_dir(cfg.executable),
        'sd'                : R'C:',
        'commonfonts'       : R'C:\Windows\Fonts',
        'dotnet11'          : R'C:\Windows\Microsoft.NET\Framework\v1.1.4322',
        'dotnet2032'        : R'C:\Windows\Microsoft.NET\Framework\v2.0.50727',
        'dotnet4032'        : R'C:\Windows\Microsoft.NET\Framework\v4.0.30319',
        'localappdata'      : RF'{user}\AppData\Local',
        'userappdata'       : RF'{user}\AppData\Roaming',
        'userdesktop'       : RF'{user}\Desktop',
        'userdocs'          : RF'{user}\Documents',
        'userfavorites'     : RF'{user}\Favorites',
        'commonfavorites'   : RF'{user}\Favorites',
        'usersavedgames'    : RF'{user}\Saved Games',
        'usersendto'        : RF'{user}\SendTo',
        'userstartmenu'     : RF'{user}\Start Menu',
        'userprograms'      : RF'{user}\Start Menu\Programs',
        'userstartup'       : RF'{user}\Start Menu\Programs\Startup',
        'usertemplates'     : RF'{user}\Templates',
        'userpf'            : RF'{user}\AppData\Local\Programs',
        'usercf'            : RF'{user}\AppData\Local\Programs\Common',
        'userfonts'         : RF'{user}\AppData\Local\Microsoft\Windows\Fonts',
        'commonappdata'     : R'C:\ProgramData',
        'commondesktop'     : R'C:\Users\Public\Desktop',
        'commondocs'        : R'C:\Users\Public\Documents',
        'commonstartmenu'   : R'C:\ProgramData\Microsoft\Windows\Start Menu',
        'commonprograms'    : R'C:\ProgramData\Microsoft\Windows\Start Menu\Programs',
        'commonstartup'     : R'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup',
        'commontemplates'   : R'C:\ProgramData\Microsoft\Windows\Templates',
        'cmd'               : R'C:\Windows\System32\cmd.exe',
        'computername'      : cfg.host_name,
        'hwnd'              : '0',
        'wizardhwnd'        : '0',
        'srcexe'            : cfg.executable,
        'sysuserinfoname'   : '{sysuserinfoname}',
        'sysuserinfoorg'    : '{sysuserinfoorg}',
        'username'          : cfg.user_name,
        'log'               : '',
    }
    if cfg.x64:
        map['sysnative'] = R'C:\Windows\Sysnative'
        map['syswow64'] = R'C:\Windows\SysWOW64'
        map['commonpf32'] = R'C:\Program Files (x86)'
        map['commoncf32'] = R'C:\Program Files (x86)\Common Files'
        map['commonpf64'] = R'C:\Program Files'
        map['commoncf64'] = R'C:\Program Files\Common Files'
        map['dotnet2064'] = R'C:\Windows\Microsoft.NET\Framework64\v2.0.50727'
        map['dotnet4064'] = R'C:\Windows\Microsoft.NET\Framework64\v4.0.30319'
    else:
        map['sysnative'] = R'C:\Windows\System32'
        map['syswow64'] = R'C:\Windows\System32'
        map['commonpf32'] = R'C:\Program Files'
        map['commoncf32'] = R'C:\Program Files\Common Files'
    return map


class SetupConstants:
    """
    The constants of one emulated Setup process, as Setup's `ExpandIndividualConst` gives them on
    the emulated machine: the `refinery.lib.inno.constants.ConstantHost` of the emulator and of an
    installer without its script. The process draws the folder `{tmp}` once; the folders of the
    machine come from the configuration, the folder and the group of the installation, the user
    information and the uninstaller from the wizard form when a constant is expanded. The run of
    the script that asks for an expansion passes the runner of its code constants with it.
    """
    def __init__(
        self,
        setup: HostSetup,
        config: IFPSEmulatorConfig,
        form: WizardForm,
        folders: Mapping[str, str] | None = None,
    ):
        self.setup = setup
        self.config = config
        self.form = form
        self.release = setup.release
        self.admin = setup.admin_install_mode
        self.win64 = config.x64
        self.folders = machine_folders(setup, config) if folders is None else folders

    def expand(
        self,
        text: str,
        run_code: constants.CodeRunner | None = None,
        custom: Mapping[str, str] | None = None,
    ) -> Generator[Any, Any, str]:
        """
        Expands the constants in a text with the given runner of code constants and custom
        constants.
        """
        return constants.expand_constants(text, self, custom, run_code)

    @cached_property
    def temporary_directory(self) -> str:
        """
        The temporary directory of Setup, the value of `{tmp}`: the configured one, else a new
        folder with a random name for each process.
        """
        if tmp := self.config.temp_path:
            return tmp
        tmp = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=5))
        return RF'C:\Windows\Temp\IS-{tmp}'

    def _mode_constant(self, name: str) -> str | None:
        """
        The value of a constant that follows the install mode: the folders of programs and of
        shared files, and the folders of the .NET Framework that Setup reads through the registry
        view of the mode.
        """
        if name not in ('commonpf', 'commoncf', 'dao', 'dotnet20', 'dotnet40'):
            return None
        bits = '64' if self.setup.install_mode.decided() else '32'
        map = self.folders
        if name == 'dao':
            shared = map[F'commoncf{bits}']
            return RF'{shared}\Microsoft Shared\DAO'
        return map[F'{name}{bits}']

    def constant(self, name: str, original: str) -> str:
        form = self.form
        cfg = self.config
        if name == 'app' or name in ('group', 'groupname'):
            if not (value := form.folder if name == 'app' else form.group):
                raise constants.ConstantError(F'An attempt was made to expand the "{original}" constant before it was initialized')
            if name != 'group':
                return value
            common = self.admin and not self.setup.always_use_personal_group
            programs = self.constant('commonprograms' if common else 'userprograms', original)
            return F'{PathFunc.add_backslash(programs)}{value}'
        if name == 'userinfoname':
            return form.user_info_name
        if name == 'userinfoorg':
            return form.user_info_org
        if name == 'userinfoserial':
            return form.user_info_serial
        if name in ('commonpf64', 'commoncf64', 'dotnet2064', 'dotnet4064') and not cfg.x64:
            raise constants.ConstantError(F'Cannot expand "{original}" constant on this version of Windows')
        if (
            name in ('userpf', 'usercf') and cfg.windows_os_version < (6, 1)
            or name == 'usersavedgames' and cfg.windows_os_version < (6, 0)
        ):
            raise constants.ConstantError(F'Failed to expand shell folder constant "{original}"')
        if name == 'uninstallexe':
            return form.uninstaller
        if name == 'language':
            return self.setup.language_name
        if name == 'tmp':
            return self.temporary_directory
        if (value := self._mode_constant(name)) is not None:
            return value
        if (personal := _PERSONAL_BEFORE_6.get(name)) and not self.admin and not self.release.since((6, 0, 0)):
            name = personal
        try:
            return self.folders[name]
        except KeyError:
            raise NotImplementedError(F'The emulator has no value for the constant {original}.') from None

    def environment(self, name: str, has_default: bool) -> str:
        if (value := self.config.environment.get(name)) is not None:
            return value
        return '' if has_default else F'%{name}%'

    def registry(self, root: str, view: int | None, key: str) -> bool:
        """
        The emulated registry has no keys.
        """
        return False

    def registry_value(self, root: str, view: int | None, key: str, value: str, default: str) -> str:
        return default

    def ini_value(self, file: str, section: str, key: str, default: str) -> str:
        return default

    def parameter(self, name: str, default: str) -> str:
        return default

    def custom_message(self, name: str) -> str | None:
        return self.setup.custom_message(name)

    def format_message(self, message: str, arguments: list[str]) -> str:
        return constants.fmt_message(message, arguments)

    def drive(self, path: str) -> str:
        return self.setup.path_func.extract_drive(path)
