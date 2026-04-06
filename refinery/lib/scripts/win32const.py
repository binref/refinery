"""
Default Windows environment variable definitions for script emulation.
"""
from __future__ import annotations

from uuid import uuid4

DEFAULT_ENVIRONMENT_TEMPLATE = {
    'AllUsersProfile'          : r'C:\ProgramData',
    'AppData'                  : r'C:\Users\{u}\AppData\Roaming',
    'CommonProgramFiles'       : r'C:\Program Files\Common Files',
    'CommonProgramFiles(x86)'  : r'C:\Program Files (x86)\Common Files',
    'CommonProgramW6432'       : r'C:\Program Files\Common Files',
    'ComputerName'             : r'{h}',
    'ComSpec'                  : r'C:\WINDOWS\system32\cmd.exe',
    'DriverData'               : r'C:\Windows\System32\Drivers\DriverData',
    'HomeDrive'                : r'C:',
    'HomePath'                 : r'\Users\{u}',
    'LocalAppData'             : r'C:\Users\{u}\AppData\Local',
    'LogonServer'              : r'\\{h}',
    'NumberOfProcessors'       : r'16',
    'OneDrive'                 : r'C:\Users\{u}\OneDrive',
    'OS'                       : r'Windows_NT',
    'Path': ';'.join(
        [
            r'C:\Windows',
            r'C:\Windows\System32',
            r'C:\Windows\System32\Wbem',
            r'C:\Windows\System32\WindowsPowerShell\v1.0\\',
            r'C:\Windows\System32\OpenSSH\\',
            r'C:\Program Files\dotnet\\',
        ]
    ),
    'PathExt'                  : r'.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC',
    'ProcessorArchitecture'    : r'AMD64',
    'ProcessorIdentifier'      : r'Intel64 Family 6 Model 158 Stepping 10, GenuineIntel',
    'ProcessorLevel'           : r'6',
    'ProcessorRevision'        : r'99ff',
    'ProgramData'              : r'C:\ProgramData',
    'ProgramFiles'             : r'C:\Program Files',
    'ProgramFiles(x86)'        : r'C:\Program Files (x86)',
    'ProgramW6432'             : r'C:\Program Files',
    'Public'                   : r'C:\Users\Public',
    'SessionName'              : r'Console',
    'SystemDrive'              : r'C:',
    'SystemRoot'               : r'C:\WINDOWS',
    'Temp'                     : r'C:\Users\{u}\AppData\Local\Temp',
    'Tmp'                      : r'C:\Users\{u}\AppData\Local\Temp',
    'UserDomain'               : r'{h}',
    'UserDomainRoamingProfile' : r'{h}',
    'UserName'                 : r'{u}',
    'UserProfile'              : r'C:\Users\{u}',
    'WinDir'                   : r'C:\WINDOWS',
}


def make_win32_environment(
    username: str = 'Administrator',
    hostname: str | None = None,
) -> dict[str, str]:
    """
    Generate a default Windows environment variable dictionary.
    """
    if hostname is None:
        hostname = str(uuid4())
    return {
        key: value.format(h=hostname, u=username)
        for key, value in DEFAULT_ENVIRONMENT_TEMPLATE.items()
    }
