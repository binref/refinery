"""
Setup's rules for paths: Inno Setup's `PathFunc` unit, which Setup and its support functions use,
the wizard's tidying of folder and group names, and Windows' `GetFullPathName`, which both rest on.
Inno Setup 7 changed how drives and slashes are read; `PathFunc.of` gives the rules of a release.
"""
from __future__ import annotations

from refinery.lib.inno.delphi.strings import trim
from refinery.lib.inno.release import SetupRelease

_SLASHES = '\\/'

_DEVICES = frozenset({
    'AUX',
    'CON',
    'CONIN$',
    'CONOUT$',
    'NUL',
    'PRN',
    *(F'COM{k}' for k in '123456789\u00b9\u00b2\u00b3'),
    *(F'LPT{k}' for k in '123456789\u00b9\u00b2\u00b3'),
})
"""
The names of devices that Windows maps a path to, depending on its version.
"""


def _drive_root(folder: str) -> str:
    """
    The root of the drive or share of a full path: `C:\\` or `\\\\server\\share`.
    """
    if folder[:2] == '\\\\':
        server_end = folder.find('\\', 2)
        if server_end < 0:
            return folder
        share_end = folder.find('\\', server_end + 1)
        return folder if share_end < 0 else folder[:share_end]
    return F'{folder[:2]}\\'


def _components(text: str) -> list[str]:
    return [part for part in text.split('\\') if part]


def full_path_name(name: str, folder: str) -> str | None:
    """
    Windows' `GetFullPathName` for the given path and current folder, which is a full path; `None`
    where Windows fails, for a path that is empty or only spaces. Slashes become backslashes and
    repeated separators one; `.` and `..` parts go, never above the root of a drive or a share; a
    part before others that ends in one dot loses it, and the last part loses its trailing dots and
    spaces. A drive-relative path is relative to the current folder when it is on that drive, else
    to the root of the drive. Device names and the prefixes `\\\\?\\` and `\\\\.\\` are not modelled.
    """
    if not name.strip(' '):
        return None
    path = name.replace('/', '\\')
    if path[:3] in ('\\\\?', '\\\\.') and (len(path) == 3 or path[3] == '\\'):
        raise NotImplementedError(F'The emulator does not model the path {name}.')
    trailing = path.endswith('\\')
    if path[:2] == '\\\\':
        server_end = path.find('\\', 2)
        if server_end < 0:
            return F'\\\\{path[2:].rstrip(". ")}'
        share_start = server_end
        while share_start < len(path) and path[share_start] == '\\':
            share_start += 1
        share_end = path.find('\\', share_start)
        if share_end < 0:
            share = path[share_start:].rstrip('. ')
            return F'{path[:server_end]}\\{share}'
        root = F'{path[:server_end]}\\{path[share_start:share_end]}'
        stack: list[str] = []
        rest = path[share_end:]
    elif path[1:2] == ':':
        drive = path[:2]
        if path[2:3] == '\\':
            root = F'{drive}\\'
            stack = []
            rest = path[3:]
        else:
            if folder[1:2] == ':' and folder[0].upper() == drive[0].upper():
                root = _drive_root(folder)
                stack = _components(folder[len(root):])
            else:
                root = F'{drive}\\'
                stack = []
            rest = path[2:]
    else:
        root = _drive_root(folder)
        if path[:1] == '\\':
            stack = []
        else:
            stack = _components(folder[len(root):])
        rest = path
    for part in rest.split('\\'):
        if not part or part == '.':
            continue
        if part == '..':
            if stack:
                stack.pop()
            continue
        stack.append(part)
    middle = len(stack) if trailing else len(stack) - 1
    for index in range(middle):
        part = stack[index]
        if part.endswith('.') and not part.endswith('..'):
            stack[index] = part[:-1]
    if stack and not trailing:
        last = stack[-1].rstrip('. ')
        if last.split('.')[0].split(':')[0].rstrip(' ').upper() in _DEVICES:
            raise NotImplementedError(F'The emulator does not model the device name in the path {name}.')
        if last:
            stack[-1] = last
        else:
            stack.pop()
            trailing = True
    if not stack:
        return root if root.endswith('\\') or not trailing else F'{root}\\'
    full = '\\'.join((root.rstrip('\\'), *stack))
    return F'{full}\\' if trailing else full


class PathFunc:
    """
    The functions of Inno Setup's `PathFunc` unit that Setup and its support functions use, in one
    release: `inno7` selects the rules of Inno Setup 7, which reads the namespace prefixes
    `\\\\?\\` and `\\\\.\\` as part of a drive, keeps a third leading slash, and fails a path that
    it cannot expand instead of keeping it.
    """
    def __init__(self, inno7: bool):
        self.inno7 = inno7

    @staticmethod
    def of(release: SetupRelease) -> PathFunc:
        return PATH_FUNC_7 if release.since((7, 0, 0)) else PATH_FUNC_6

    def __repr__(self):
        return F'{self.__class__.__name__}({7 if self.inno7 else 6})'

    @staticmethod
    def add_backslash(text: str) -> str:
        if text and text[-1] not in _SLASHES:
            return F'{text}\\'
        return text

    @staticmethod
    def remove_backslash(text: str) -> str:
        return text.rstrip(_SLASHES)

    def remove_backslash_unless_root(self, text: str) -> str:
        drive = self.drive_part_length(text, True)
        end = len(text)
        while end > drive and text[end - 1] in _SLASHES:
            end -= 1
        return text[:end]

    def drive_part_length(self, name: str, significant_slash: bool = False) -> int:
        """
        `PathDrivePartLengthEx`: the length of `x:` or of `\\\\server\\share` at the start of the
        name; with `significant_slash`, also of the slash after `x:` and of a leading slash.
        """
        length = len(name)
        if length >= 2 and name[0] in _SLASHES and name[1] in _SLASHES:
            if self.inno7:
                return self._namespace_drive_part_length(name, significant_slash)
            index = 2
            separators = 0
            while index < length:
                if name[index] in _SLASHES:
                    separators += 1
                    if separators >= 2:
                        break
                    index += 1
                    while index < length and name[index] in _SLASHES:
                        index += 1
                else:
                    index += 1
            return index
        if length >= 1 and name[0] in _SLASHES:
            return 1 if significant_slash else 0
        if length >= 2 and name[1] == ':':
            if significant_slash and length >= 3 and name[2] in _SLASHES:
                return 3
            return 2
        return 0

    @staticmethod
    def _namespace_drive_part_length(name: str, significant_slash: bool) -> int:
        length = len(name)
        namespace = False
        drive = False
        components = 2
        current = 0
        start = index = 2
        while index < length:
            if name[index] not in _SLASHES:
                index += 1
                continue
            size = index - start
            if current == 0:
                if size == 1 and name[start] in '?.':
                    namespace = True
            elif current == 1 and namespace:
                if size == 2:
                    if name[start + 1] == ':':
                        drive = True
                elif size == 3 and name[start:start + 3].upper() == 'UNC':
                    components += 2
            current += 1
            if current >= components:
                if drive and significant_slash:
                    index += 1
                break
            index += 1
            while index < length and name[index] in _SLASHES:
                index += 1
            start = index
        return index

    def path_part_length(self, name: str, slashes_after: bool) -> int:
        """
        `PathPathPartLength`: the length of the path before the last part of the name, with the
        slashes after it when `slashes_after` is set, never less than the drive part.
        """
        result = self.drive_part_length(name, True)
        keep = result
        index = result
        while index < len(name):
            if name[index] in _SLASHES:
                result = index + 1 if slashes_after else keep
                index += 1
            else:
                index += 1
                keep = index
        return result

    def extension_position(self, name: str) -> int | None:
        """
        The index of the last dot in the last part of the name.
        """
        position = None
        for index in range(self.path_part_length(name, True), len(name)):
            if name[index] == '.':
                position = index
        return position

    def change_ext(self, name: str, extension: str) -> str:
        if (position := self.extension_position(name)) is None:
            return F'{name}{extension}'
        return F'{name[:position]}{extension}'

    def extract_dir(self, name: str) -> str:
        return name[:self.path_part_length(name, False)]

    def extract_drive(self, name: str) -> str:
        return name[:self.drive_part_length(name)]

    def extract_ext(self, name: str) -> str:
        if (position := self.extension_position(name)) is None:
            return ''
        return name[position:]

    def extract_name(self, name: str) -> str:
        return name[self.path_part_length(name, True):]

    def extract_path(self, name: str) -> str:
        return name[:self.path_part_length(name, True)]

    def normalize_slashes(self, text: str) -> str:
        """
        `PathNormalizeSlashes`: forward slashes become backslashes and repeated backslashes one,
        except for two at the start; Inno Setup 7 also keeps a third.
        """
        chars = list(text.replace('/', '\\'))
        if self.inno7:
            end = 3 if chars[:2] == ['\\', '\\'] else 1
            for index in range(len(chars) - 1, end - 1, -1):
                if chars[index] == '\\' and chars[index - 1] == '\\':
                    del chars[index]
        else:
            index = 0
            while index < len(chars) - 1:
                if chars[index] == '\\' and chars[index + 1] == '\\' and index > 0:
                    del chars[index + 1]
                else:
                    index += 1
        return ''.join(chars)

    def expand(self, name: str, folder: str) -> str:
        """
        `PathExpand`: the full path of the name in the given current folder. Before Inno Setup 7,
        a path that Windows cannot expand, or whose full path has 4096 characters or more, stays as
        it is; Inno Setup 7 gives an empty text for a path that is empty or only spaces and fails
        for any other path that it cannot expand.
        """
        full = full_path_name(name, folder)
        if self.inno7:
            if not name.strip(' '):
                return ''
            if full is None or len(name) > 0x7FFE or len(full) > 0x7FFE:
                raise PathFuncError(F'PathExpand: GetFullPathName failed (length: {len(name)})')
            return full
        if full is None or len(full) >= 4096:
            return name
        return full

    def extract_relative_path(self, base: str, destination: str) -> str:
        """
        Setup's `NewExtractRelativePath`: the path of the destination relative to the folder of
        the base, or the destination when the two are on different drives.
        """
        base = self.normalize_slashes(base)
        destination = self.normalize_slashes(destination)
        base_drive = self.extract_drive(base)
        destination_drive = self.extract_drive(destination)
        if base_drive.lower() != destination_drive.lower():
            return destination
        base_parts = _Cursor(self.extract_path(base)[len(base_drive):])
        destination_parts = _Cursor(self.extract_path(destination)[len(destination_drive):])
        base_part = base_parts.next()
        destination_part = destination_parts.next()
        while (
            base_part is not None
            and destination_part is not None
            and base_part.lower() == destination_part.lower()
        ):
            base_part = base_parts.next()
            destination_part = destination_parts.next()
        result = '..\\' * base_parts.remaining()
        if destination_part:
            result = F'{result}{destination_part}\\'
        return F'{result}{destination_parts.rest()}{self.extract_name(destination)}'

    def tidy_up_dir_name(self, path: str) -> str:
        """
        The wizard's `TidyUpDirName`: trims spaces, normalizes slashes and removes trailing
        backslashes until nothing changes.
        """
        while True:
            path = self.remove_backslash_unless_root(self.normalize_slashes(trim(path)))
            if len(path) == len(trim(path)):
                return path

    def tidy_up_group_name(self, path: str) -> str:
        """
        The wizard's `TidyUpGroupName`: trims spaces, removes leading, repeated and trailing
        backslashes until nothing changes.
        """
        while True:
            path = trim(path).lstrip(_SLASHES)
            path = self.remove_backslash(self.normalize_slashes(path))
            if len(path) == len(trim(path)):
                return path


def _components_end_in_spaces(path: str) -> bool:
    return any(part.endswith(' ') for part in path.split('\\'))


def _components_are_dots(path: str) -> bool:
    return any(part.strip(' ') and not part.strip(' ').strip('.') for part in path.split('\\'))


def _has_control_characters(path: str) -> bool:
    return any(c <= '\x1F' for c in path)


_BAD_CHARACTERS = frozenset('/:*?"<>|')


def valid_dir_name(path: str, allow_unc: bool, allow_root: bool) -> bool:
    """
    The checks of the wizard's `ValidateCustomDirEdit` on a tidied folder, but for the drive, which
    the emulated machine is taken to have: at most 240 characters; a UNC path only when allowed and
    with a backslash after the server; else a drive letter, a colon and a backslash, and more than
    the root unless allowed; no control character, no part that ends in a space or is only dots;
    none of the characters `/:*?"<>|` after the first two.
    """
    if len(path) > 240:
        return False
    if path[:2] == '\\\\':
        if not allow_unc or path.find('\\', 2) <= 2:
            return False
    elif (
        len(path) < (3 if allow_root else 4)
        or not 'A' <= path[0].upper() <= 'Z'
        or path[1] != ':'
        or path[2] != '\\'
    ):
        return False
    if _has_control_characters(path) or _components_end_in_spaces(path) or _components_are_dots(path):
        return False
    return not any(c in _BAD_CHARACTERS for c in path[2:])


def valid_group_name(name: str) -> bool:
    """
    The checks of the wizard's `ValidateGroupEdit` on a tidied group: at most 120 characters, no
    control character, no part that ends in a space, not empty, none of the characters
    `/:*?"<>|`.
    """
    if len(name) > 120 or _has_control_characters(name) or _components_end_in_spaces(name):
        return False
    return bool(name) and not any(c in _BAD_CHARACTERS for c in name)


class _Cursor:
    """
    Walks the parts of a path between backslashes as `NewExtractRelativePath` does.
    """
    def __init__(self, path: str):
        self.parts = path.split('\\')
        self.index: int | None = 0 if path else None

    def next(self) -> str | None:
        if (index := self.index) is None:
            return None
        self.index = index + 1 if index + 1 < len(self.parts) else None
        return self.parts[index]

    def remaining(self) -> int:
        if (index := self.index) is None:
            return 0
        return len(self.parts) - index

    def rest(self) -> str:
        if (index := self.index) is None:
            return ''
        return '\\'.join(self.parts[index:])


class PathFuncError(Exception):
    """
    The error of Inno Setup 7's `PathExpand` for a path that it cannot expand.
    """


def expand_file_name(name: str, folder: str) -> str:
    """
    Delphi's `ExpandFileName`, which Setup's `ExpandUNCFileName` uses on a machine without network
    drives: the full path, or an empty text where Windows fails.
    """
    full = full_path_name(name, folder)
    return '' if full is None else full


PATH_FUNC_6 = PathFunc(inno7=False)
PATH_FUNC_7 = PathFunc(inno7=True)
