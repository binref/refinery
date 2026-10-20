from refinery.lib.inno.installation import CurrentFolder, InstalledPaths
from refinery.lib.inno.pathfunc import PATH_FUNC_6, PATH_FUNC_7, PathFuncError, expand_file_name, full_path_name

from .. import TestBase

_WINDOWS = 'C:\\Windows'
"""
The current folder of the process that measured `_FULL_PATHS`; the cases of Inno Setup 7.1.0 below
take it for `GetCurrentDir`.
"""

_PART_LENGTHS_6 = [
    ('', 0, 0, 0, 0),
    ('\\', 0, 1, 1, 1),
    ('\\a', 0, 1, 1, 1),
    ('\\a\\', 0, 1, 2, 3),
    ('\\a\\b', 0, 1, 2, 3),
    ('a', 0, 0, 0, 0),
    ('a\\', 0, 0, 1, 2),
    ('a\\\\', 0, 0, 1, 3),
    ('a\\\\\\', 0, 0, 1, 4),
    ('a\\b', 0, 0, 1, 2),
    ('a\\b:c', 0, 0, 1, 2),
    ('1:', 2, 2, 2, 2),
    ('\\:', 0, 1, 1, 1),
    ('\\:stream', 0, 1, 1, 1),
    ('c:', 2, 2, 2, 2),
    ('c:a', 2, 2, 2, 2),
    ('c:\\', 2, 3, 3, 3),
    ('c:\\\\', 2, 3, 3, 4),
    ('c:\\\\\\', 2, 3, 3, 5),
    ('c:\\a', 2, 3, 3, 3),
    ('c:\\a\\', 2, 3, 4, 5),
    ('c:\\a\\\\', 2, 3, 4, 6),
    ('c:\\a\\\\\\', 2, 3, 4, 7),
    ('c:\\a\\b', 2, 3, 4, 5),
    ('c:\\a\\b:c', 2, 3, 4, 5),
    ('\\\\', 2, 2, 2, 2),
    ('\\\\\\', 3, 3, 3, 3),
    ('\\\\\\\\', 4, 4, 4, 4),
    ('\\\\\\\\\\', 5, 5, 5, 5),
    ('\\\\a', 3, 3, 3, 3),
    ('\\\\a\\', 4, 4, 4, 4),
    ('\\\\a\\b', 5, 5, 5, 5),
    ('\\\\a\\b\\', 5, 5, 5, 6),
    ('\\\\a\\b\\c', 5, 5, 5, 6),
    ('\\\\a\\b\\c\\', 5, 5, 7, 8),
    ('\\\\a\\b\\c\\d', 5, 5, 7, 8),
    ('\\\\a\\b\\c\\d:e', 5, 5, 7, 8),
    ('\\\\a\\\\\\b', 7, 7, 7, 7),
    ('\\\\a\\\\\\b\\\\\\', 7, 7, 7, 10),
    ('\\\\a\\\\\\b\\\\\\c', 7, 7, 7, 10),
    ('\\\\a\\\\\\b\\\\\\c\\\\\\', 7, 7, 11, 14),
]

_REMOVE_BACKSLASH_6 = [
    ('', ''),
    ('\\', ''),
    ('\\\\', ''),
    ('\\\\\\', ''),
    ('c:', 'c:'),
    ('c:\\', 'c:'),
    ('c:\\\\', 'c:'),
    ('c:\\\\\\', 'c:'),
]

_REMOVE_BACKSLASH_UNLESS_ROOT_6 = [
    ('', ''),
    ('\\', '\\'),
    ('\\\\', '\\\\'),
    ('\\\\\\', '\\\\\\'),
    ('\\\\\\\\', '\\\\\\\\'),
    ('a', 'a'),
    ('a\\', 'a'),
    ('a\\\\', 'a'),
    ('c:', 'c:'),
    ('c:\\', 'c:\\'),
    ('c:\\a', 'c:\\a'),
    ('c:\\a\\', 'c:\\a'),
    ('c:\\a\\\\', 'c:\\a'),
    ('\\\\a\\b', '\\\\a\\b'),
    ('\\\\a\\b\\', '\\\\a\\b'),
    ('\\\\a\\b\\\\', '\\\\a\\b'),
]

_CHANGE_EXT_6 = [
    ('c:', '.txt', 'c:.txt'),
    ('c:\\', '.txt', 'c:\\.txt'),
    ('c:\\a', '.txt', 'c:\\a.txt'),
    ('c:\\a.', '.txt', 'c:\\a.txt'),
    ('c:\\a.tar', '.txt', 'c:\\a.txt'),
    ('c:\\a.tar.gz', '.txt', 'c:\\a.tar.txt'),
    ('c:\\x.y\\a', '.txt', 'c:\\x.y\\a.txt'),
    ('\\\\x.y\\a', '.txt', '\\\\x.y\\a.txt'),
    ('\\\\x.y\\a\\', '.txt', '\\\\x.y\\a\\.txt'),
]

_EXTRACT_EXT_6 = [
    ('c:', ''),
    ('c:\\', ''),
    ('c:\\a', ''),
    ('c:\\a.', '.'),
    ('c:\\a.txt', '.txt'),
    ('c:\\a.txt.gz', '.gz'),
    ('c:\\x.y\\a', ''),
    ('\\\\x.y\\a', ''),
    ('\\\\x.y\\a.b', ''),
    ('\\\\x.y\\a.b\\c', ''),
    ('\\\\x.y\\a.b\\c.txt', '.txt'),
]

_PART_LENGTHS_7 = [
    ('', 0, 0, 0, 0),
    ('\\', 0, 1, 1, 1),
    ('/', 0, 1, 1, 1),
    ('\\a', 0, 1, 1, 1),
    ('\\a\\', 0, 1, 2, 3),
    ('\\a\\b', 0, 1, 2, 3),
    ('a', 0, 0, 0, 0),
    ('a\\', 0, 0, 1, 2),
    ('a\\\\', 0, 0, 1, 3),
    ('a\\\\\\', 0, 0, 1, 4),
    ('a\\b', 0, 0, 1, 2),
    ('a\\b:c', 0, 0, 1, 2),
    ('abc:def', 0, 0, 0, 0),
    ('1:', 2, 2, 2, 2),
    ('@:', 2, 2, 2, 2),
    ('\\:', 0, 1, 1, 1),
    ('\\:stream', 0, 1, 1, 1),
    ('c:', 2, 2, 2, 2),
    ('c:a', 2, 2, 2, 2),
    ('c:\\', 2, 3, 3, 3),
    ('c:\\\\', 2, 3, 3, 4),
    ('c:\\\\\\', 2, 3, 3, 5),
    ('c:\\a', 2, 3, 3, 3),
    ('c:/a', 2, 3, 3, 3),
    ('c:\\a\\', 2, 3, 4, 5),
    ('c:\\a\\\\', 2, 3, 4, 6),
    ('c:\\a\\\\\\', 2, 3, 4, 7),
    ('c:\\a\\b', 2, 3, 4, 5),
    ('c:\\a\\b:c', 2, 3, 4, 5),
    ('\\\\', 2, 2, 2, 2),
    ('\\\\\\', 3, 3, 3, 3),
    ('\\\\\\\\', 4, 4, 4, 4),
    ('\\\\\\\\\\', 5, 5, 5, 5),
    ('\\\\a', 3, 3, 3, 3),
    ('\\\\a\\', 4, 4, 4, 4),
    ('\\\\a\\b', 5, 5, 5, 5),
    ('\\\\a\\b\\', 5, 5, 5, 6),
    ('//a/b', 5, 5, 5, 5),
    ('//a/b/', 5, 5, 5, 6),
    ('\\\\a\\b\\c', 5, 5, 5, 6),
    ('\\\\a\\b\\c\\', 5, 5, 7, 8),
    ('\\\\a\\b\\c\\d', 5, 5, 7, 8),
    ('\\\\a\\b\\c\\d:e', 5, 5, 7, 8),
    ('\\\\a\\\\\\b', 7, 7, 7, 7),
    ('\\\\a\\\\\\b\\\\\\', 7, 7, 7, 10),
    ('\\\\a\\\\\\b\\\\\\c', 7, 7, 7, 10),
    ('\\\\a\\\\\\b\\\\\\c\\\\\\', 7, 7, 11, 14),
    ('\\\\?\\C:', 6, 6, 6, 6),
    ('\\\\?\\C:\\', 6, 7, 7, 7),
    ('\\\\?\\C:\\a', 6, 7, 7, 7),
    ('\\\\?\\C:\\a\\b', 6, 7, 8, 9),
    ('\\\\.\\C:', 6, 6, 6, 6),
    ('\\\\.\\C:\\a', 6, 7, 7, 7),
    ('\\\\?\\UNC\\server\\share', 20, 20, 20, 20),
    ('\\\\?\\UNC\\server\\share\\', 20, 20, 20, 21),
    ('\\\\?\\UNC\\server\\share\\dir', 20, 20, 20, 21),
    ('\\\\.\\UNC\\server\\share', 20, 20, 20, 20),
    ('\\\\.\\unc\\server\\share\\dir', 20, 20, 20, 21),
]

_REMOVE_BACKSLASH_7 = [
    ('', ''),
    ('\\', ''),
    ('\\\\', ''),
    ('\\\\\\', ''),
    ('a/', 'a'),
    ('c:', 'c:'),
    ('c:\\', 'c:'),
    ('c:\\\\', 'c:'),
    ('c:\\\\\\', 'c:'),
]

_REMOVE_BACKSLASH_UNLESS_ROOT_7 = [
    ('', ''),
    ('\\', '\\'),
    ('/', '/'),
    ('\\\\', '\\\\'),
    ('\\\\\\', '\\\\\\'),
    ('\\\\\\\\', '\\\\\\\\'),
    ('a', 'a'),
    ('a\\', 'a'),
    ('a\\\\', 'a'),
    ('c:', 'c:'),
    ('c:\\', 'c:\\'),
    ('c:/', 'c:/'),
    ('c:\\a', 'c:\\a'),
    ('c:\\a\\', 'c:\\a'),
    ('c:\\a\\\\', 'c:\\a'),
    ('c:\\a/', 'c:\\a'),
    ('\\\\a\\b', '\\\\a\\b'),
    ('\\\\a\\b\\', '\\\\a\\b'),
    ('\\\\a\\b\\\\', '\\\\a\\b'),
    ('//a/b/', '//a/b'),
]

_CHANGE_EXT_7 = [
    ('c:', '.txt', 'c:.txt'),
    ('c:\\', '.txt', 'c:\\.txt'),
    ('c:\\a', '.txt', 'c:\\a.txt'),
    ('c:\\a.', '.txt', 'c:\\a.txt'),
    ('c:\\a.tar', '.txt', 'c:\\a.txt'),
    ('c:\\a.tar.gz', '.txt', 'c:\\a.tar.txt'),
    ('c:\\x.y\\a', '.txt', 'c:\\x.y\\a.txt'),
    ('\\\\x.y\\a', '.txt', '\\\\x.y\\a.txt'),
    ('\\\\x.y\\a\\', '.txt', '\\\\x.y\\a\\.txt'),
    ('a', '.txt', 'a.txt'),
    ('a.tar', '.txt', 'a.txt'),
    ('a.tar', 'txt', 'atxt'),
    ('a..tar', '.txt', 'a..txt'),
    ('a.txt', '', 'a'),
]

_EXTRACT_EXT_7 = [
    ('c:', ''),
    ('c:\\', ''),
    ('c:\\a', ''),
    ('c:\\a.', '.'),
    ('c:\\a.txt', '.txt'),
    ('c:\\a.txt.gz', '.gz'),
    ('c:\\x.y\\a', ''),
    ('\\\\x.y\\a', ''),
    ('\\\\x.y\\a.b', ''),
    ('\\\\x.y\\a.b\\c', ''),
    ('\\\\x.y\\a.b\\c.txt', '.txt'),
]

_EXPAND_7 = [
    ('', ''),
    (' ', ''),
    ('   ', ''),
    ('...', 'C:\\Windows\\'),
    ('.. ', 'C:\\Windows\\'),
    ('\\\\', '\\\\'),
    ('\\\\localhost', '\\\\localhost'),
    ('\\\\localhost ', '\\\\localhost'),
    ('\\\\localhost.', '\\\\localhost'),
    ('\\\\localhost\\.', '\\\\localhost\\'),
    ('\\\\localhost\\..', '\\\\localhost\\'),
    ('\\\\localhost\\...', '\\\\localhost\\'),
    ('\\\\localhost\\.\\abc', '\\\\localhost\\.\\abc'),
    ('\\\\localhost\\..\\abc', '\\\\localhost\\..\\abc'),
    ('\\\\localhost\\...\\abc', '\\\\localhost\\...\\abc'),
    ('\\\\..\\localhost', '\\\\..\\localhost'),
    ('C:\\abc\\def\\.', 'C:\\abc\\def'),
    ('C:\\abc\\def\\..', 'C:\\abc'),
    ('C:\\abc\\def\\...', 'C:\\abc\\def\\'),
    ('C:\\..\\abc\\def', 'C:\\abc\\def'),
    ('C:\\abc\\def   ', 'C:\\abc\\def'),
    ('C:\\abc\\def...', 'C:\\abc\\def'),
    ('C:\\abc\\def . . ', 'C:\\abc\\def'),
    ('C:\\abc.\\def', 'C:\\abc\\def'),
    ('C:\\abc..\\def', 'C:\\abc..\\def'),
    ('C:\\abc \\def', 'C:\\abc \\def'),
    ('\\\\localhost\\share\\..\\abc\\def', '\\\\localhost\\share\\abc\\def'),
]

_EXPAND_NOT_MODELLED_7 = [
    ('NUL', '\\\\.\\NUL'),
    ('\\\\.', '\\\\.\\'),
    ('\\\\?', '\\\\?\\'),
    ('\\\\?\\C:\\..\\abc\\def', '\\\\?\\abc\\def'),
    ('\\\\?\\C:\\..\\..\\abc\\def', '\\\\?\\abc\\def'),
    ('\\\\?\\UNC\\localhost\\share\\..\\abc\\def', '\\\\?\\UNC\\localhost\\abc\\def'),
    ('\\\\?\\UNC\\localhost\\share\\..\\..\\..\\abc\\def', '\\\\?\\abc\\def'),
    ('\\\\?\\UNC\\localhost\\share\\..\\..\\..\\..\\abc\\def', '\\\\?\\abc\\def'),
]

_EXPAND_AND_NORMALIZE_SLASHES_7 = [
    ('C:\\abc\\def', 'C:\\abc\\def'),
    ('C:\\abc\\def\\', 'C:\\abc\\def\\'),
    ('C:\\abc\\def\\\\', 'C:\\abc\\def\\'),
    ('C:/abc\\def', 'C:\\abc\\def'),
    ('C:\\\\\\abc////def', 'C:\\abc\\def'),
    ('\\\\\\?\\C:\\Windows', '\\\\\\?\\C:\\Windows'),
    ('\\\\\\\\?\\C:\\Windows', '\\\\\\?\\C:\\Windows'),
    ('\\\\\\\\\\?\\C:\\Windows', '\\\\\\?\\C:\\Windows'),
    ('\\\\\\?\\\\C:\\\\Windows', '\\\\\\?\\C:\\Windows'),
]

_EXPAND_AND_NORMALIZE_SLASHES_NOT_MODELLED_7 = [
    ('\\\\?\\C:\\Windows', '\\\\?\\C:\\Windows'),
    ('\\\\?\\\\C:\\\\Windows', '\\\\?\\C:\\Windows'),
]

_NORMALIZE_SLASHES_7 = [
    ('a/\\b', 'a\\b'),
    ('a\\\\b', 'a\\b'),
    ('\\\\a\\\\\\b', '\\\\a\\b'),
    ('\\\\', '\\\\'),
    ('a/b', 'a\\b'),
    ('a//b', 'a\\b'),
    ('///', '\\\\\\'),
    ('////server//share', '\\\\\\server\\share'),
    ('', ''),
    ('/', '\\'),
]

_ADD_BACKSLASH_7 = [
    ('', ''),
    ('a', 'a\\'),
    ('a\\', 'a\\'),
    ('a/', 'a/'),
    ('\\', '\\'),
]

_EXTRACTS_7 = [
    ('c:\\dir\\file.txt', 'file.txt', 'c:\\dir\\', 'c:\\dir', 'c:'),
    ('c:/dir/file.txt', 'file.txt', 'c:/dir/', 'c:/dir', 'c:'),
    ('c:\\dir\\', '', 'c:\\dir\\', 'c:\\dir', 'c:'),
    ('c:\\', '', 'c:\\', 'c:\\', 'c:'),
    ('C:file', 'file', 'C:', 'C:', 'C:'),
    ('\\\\s\\sh\\file', 'file', '\\\\s\\sh\\', '\\\\s\\sh', '\\\\s\\sh'),
    ('\\\\s\\sh', '', '\\\\s\\sh', '\\\\s\\sh', '\\\\s\\sh'),
    ('\\\\?\\C:\\x', 'x', '\\\\?\\C:\\', '\\\\?\\C:\\', '\\\\?\\C:'),
    ('\\\\.\\C:\\x', 'x', '\\\\.\\C:\\', '\\\\.\\C:\\', '\\\\.\\C:'),
    ('file.txt', 'file.txt', '', '', ''),
    ('\\file', 'file', '\\', '\\', ''),
    ('', '', '', '', ''),
    ('a\\b:c', 'b:c', 'a\\', 'a', ''),
    ('abc:def', 'abc:def', '', '', ''),
]

_EXTENSION_POSITION_7 = [
    ('', 0),
    ('file', 0),
    ('file.txt', 5),
    ('a.b.c', 4),
    ('c:\\dir.x\\a', 0),
    ('c:\\dir.x\\a.txt', 11),
    ('.hidden', 1),
    ('a.', 2),
]

_FULL_PATHS = [
    ('C:\\x\\a\\z', 'C:\\x\\a\\z'),
    ('C:\\x\\a\\z.', 'C:\\x\\a\\z'),
    ('C:\\x\\a\\z..', 'C:\\x\\a\\z'),
    ('C:\\x\\a\\z ', 'C:\\x\\a\\z'),
    ('C:\\x\\a\\z .', 'C:\\x\\a\\z'),
    ('C:\\x\\a\\z. ', 'C:\\x\\a\\z'),
    ('C:\\x\\a\\.', 'C:\\x\\a'),
    ('C:\\x\\a\\..', 'C:\\x'),
    ('C:\\x\\a\\...', 'C:\\x\\a\\'),
    ('C:\\x\\a\\ ', 'C:\\x\\a\\'),
    ('C:\\x\\a.\\z', 'C:\\x\\a\\z'),
    ('C:\\x\\a.\\z.', 'C:\\x\\a\\z'),
    ('C:\\x\\a.\\z..', 'C:\\x\\a\\z'),
    ('C:\\x\\a.\\z ', 'C:\\x\\a\\z'),
    ('C:\\x\\a.\\z .', 'C:\\x\\a\\z'),
    ('C:\\x\\a.\\z. ', 'C:\\x\\a\\z'),
    ('C:\\x\\a.\\.', 'C:\\x\\a'),
    ('C:\\x\\a.\\..', 'C:\\x'),
    ('C:\\x\\a.\\...', 'C:\\x\\a\\'),
    ('C:\\x\\a.\\ ', 'C:\\x\\a\\'),
    ('C:\\x\\a..\\z', 'C:\\x\\a..\\z'),
    ('C:\\x\\a..\\z.', 'C:\\x\\a..\\z'),
    ('C:\\x\\a..\\z..', 'C:\\x\\a..\\z'),
    ('C:\\x\\a..\\z ', 'C:\\x\\a..\\z'),
    ('C:\\x\\a..\\z .', 'C:\\x\\a..\\z'),
    ('C:\\x\\a..\\z. ', 'C:\\x\\a..\\z'),
    ('C:\\x\\a..\\.', 'C:\\x\\a'),
    ('C:\\x\\a..\\..', 'C:\\x'),
    ('C:\\x\\a..\\...', 'C:\\x\\a..\\'),
    ('C:\\x\\a..\\ ', 'C:\\x\\a..\\'),
    ('C:\\x\\a...\\z', 'C:\\x\\a...\\z'),
    ('C:\\x\\a...\\z.', 'C:\\x\\a...\\z'),
    ('C:\\x\\a...\\z..', 'C:\\x\\a...\\z'),
    ('C:\\x\\a...\\z ', 'C:\\x\\a...\\z'),
    ('C:\\x\\a...\\z .', 'C:\\x\\a...\\z'),
    ('C:\\x\\a...\\z. ', 'C:\\x\\a...\\z'),
    ('C:\\x\\a...\\.', 'C:\\x\\a'),
    ('C:\\x\\a...\\..', 'C:\\x'),
    ('C:\\x\\a...\\...', 'C:\\x\\a...\\'),
    ('C:\\x\\a...\\ ', 'C:\\x\\a...\\'),
    ('C:\\x\\a \\z', 'C:\\x\\a \\z'),
    ('C:\\x\\a \\z.', 'C:\\x\\a \\z'),
    ('C:\\x\\a \\z..', 'C:\\x\\a \\z'),
    ('C:\\x\\a \\z ', 'C:\\x\\a \\z'),
    ('C:\\x\\a \\z .', 'C:\\x\\a \\z'),
    ('C:\\x\\a \\z. ', 'C:\\x\\a \\z'),
    ('C:\\x\\a \\.', 'C:\\x\\a'),
    ('C:\\x\\a \\..', 'C:\\x'),
    ('C:\\x\\a \\...', 'C:\\x\\a \\'),
    ('C:\\x\\a \\ ', 'C:\\x\\a \\'),
    ('C:\\x\\a  \\z', 'C:\\x\\a  \\z'),
    ('C:\\x\\a  \\z.', 'C:\\x\\a  \\z'),
    ('C:\\x\\a  \\z..', 'C:\\x\\a  \\z'),
    ('C:\\x\\a  \\z ', 'C:\\x\\a  \\z'),
    ('C:\\x\\a  \\z .', 'C:\\x\\a  \\z'),
    ('C:\\x\\a  \\z. ', 'C:\\x\\a  \\z'),
    ('C:\\x\\a  \\.', 'C:\\x\\a'),
    ('C:\\x\\a  \\..', 'C:\\x'),
    ('C:\\x\\a  \\...', 'C:\\x\\a  \\'),
    ('C:\\x\\a  \\ ', 'C:\\x\\a  \\'),
    ('C:\\x\\a .\\z', 'C:\\x\\a \\z'),
    ('C:\\x\\a .\\z.', 'C:\\x\\a \\z'),
    ('C:\\x\\a .\\z..', 'C:\\x\\a \\z'),
    ('C:\\x\\a .\\z ', 'C:\\x\\a \\z'),
    ('C:\\x\\a .\\z .', 'C:\\x\\a \\z'),
    ('C:\\x\\a .\\z. ', 'C:\\x\\a \\z'),
    ('C:\\x\\a .\\.', 'C:\\x\\a'),
    ('C:\\x\\a .\\..', 'C:\\x'),
    ('C:\\x\\a .\\...', 'C:\\x\\a \\'),
    ('C:\\x\\a .\\ ', 'C:\\x\\a \\'),
    ('C:\\x\\a. \\z', 'C:\\x\\a. \\z'),
    ('C:\\x\\a. \\z.', 'C:\\x\\a. \\z'),
    ('C:\\x\\a. \\z..', 'C:\\x\\a. \\z'),
    ('C:\\x\\a. \\z ', 'C:\\x\\a. \\z'),
    ('C:\\x\\a. \\z .', 'C:\\x\\a. \\z'),
    ('C:\\x\\a. \\z. ', 'C:\\x\\a. \\z'),
    ('C:\\x\\a. \\.', 'C:\\x\\a'),
    ('C:\\x\\a. \\..', 'C:\\x'),
    ('C:\\x\\a. \\...', 'C:\\x\\a. \\'),
    ('C:\\x\\a. \\ ', 'C:\\x\\a. \\'),
    ('C:\\x\\a . \\z', 'C:\\x\\a . \\z'),
    ('C:\\x\\a . \\z.', 'C:\\x\\a . \\z'),
    ('C:\\x\\a . \\z..', 'C:\\x\\a . \\z'),
    ('C:\\x\\a . \\z ', 'C:\\x\\a . \\z'),
    ('C:\\x\\a . \\z .', 'C:\\x\\a . \\z'),
    ('C:\\x\\a . \\z. ', 'C:\\x\\a . \\z'),
    ('C:\\x\\a . \\.', 'C:\\x\\a'),
    ('C:\\x\\a . \\..', 'C:\\x'),
    ('C:\\x\\a . \\...', 'C:\\x\\a . \\'),
    ('C:\\x\\a . \\ ', 'C:\\x\\a . \\'),
    ('C:\\x\\.\\z', 'C:\\x\\z'),
    ('C:\\x\\.\\z.', 'C:\\x\\z'),
    ('C:\\x\\.\\z..', 'C:\\x\\z'),
    ('C:\\x\\.\\z ', 'C:\\x\\z'),
    ('C:\\x\\.\\z .', 'C:\\x\\z'),
    ('C:\\x\\.\\z. ', 'C:\\x\\z'),
    ('C:\\x\\.\\.', 'C:\\x'),
    ('C:\\x\\.\\..', 'C:\\'),
    ('C:\\x\\.\\...', 'C:\\x\\'),
    ('C:\\x\\.\\ ', 'C:\\x\\'),
    ('C:\\x\\..\\z', 'C:\\z'),
    ('C:\\x\\..\\z.', 'C:\\z'),
    ('C:\\x\\..\\z..', 'C:\\z'),
    ('C:\\x\\..\\z ', 'C:\\z'),
    ('C:\\x\\..\\z .', 'C:\\z'),
    ('C:\\x\\..\\z. ', 'C:\\z'),
    ('C:\\x\\..\\.', 'C:\\'),
    ('C:\\x\\..\\..', 'C:\\'),
    ('C:\\x\\..\\...', 'C:\\'),
    ('C:\\x\\..\\ ', 'C:\\'),
    ('C:\\x\\...\\z', 'C:\\x\\...\\z'),
    ('C:\\x\\...\\z.', 'C:\\x\\...\\z'),
    ('C:\\x\\...\\z..', 'C:\\x\\...\\z'),
    ('C:\\x\\...\\z ', 'C:\\x\\...\\z'),
    ('C:\\x\\...\\z .', 'C:\\x\\...\\z'),
    ('C:\\x\\...\\z. ', 'C:\\x\\...\\z'),
    ('C:\\x\\...\\.', 'C:\\x\\'),
    ('C:\\x\\...\\..', 'C:\\x'),
    ('C:\\x\\...\\...', 'C:\\x\\...\\'),
    ('C:\\x\\...\\ ', 'C:\\x\\...\\'),
    ('C:\\x\\. .\\z', 'C:\\x\\. \\z'),
    ('C:\\x\\. .\\z.', 'C:\\x\\. \\z'),
    ('C:\\x\\. .\\z..', 'C:\\x\\. \\z'),
    ('C:\\x\\. .\\z ', 'C:\\x\\. \\z'),
    ('C:\\x\\. .\\z .', 'C:\\x\\. \\z'),
    ('C:\\x\\. .\\z. ', 'C:\\x\\. \\z'),
    ('C:\\x\\. .\\.', 'C:\\x\\'),
    ('C:\\x\\. .\\..', 'C:\\x'),
    ('C:\\x\\. .\\...', 'C:\\x\\. \\'),
    ('C:\\x\\. .\\ ', 'C:\\x\\. \\'),
    ('C:\\x\\. \\z', 'C:\\x\\. \\z'),
    ('C:\\x\\. \\z.', 'C:\\x\\. \\z'),
    ('C:\\x\\. \\z..', 'C:\\x\\. \\z'),
    ('C:\\x\\. \\z ', 'C:\\x\\. \\z'),
    ('C:\\x\\. \\z .', 'C:\\x\\. \\z'),
    ('C:\\x\\. \\z. ', 'C:\\x\\. \\z'),
    ('C:\\x\\. \\.', 'C:\\x\\'),
    ('C:\\x\\. \\..', 'C:\\x'),
    ('C:\\x\\. \\...', 'C:\\x\\. \\'),
    ('C:\\x\\. \\ ', 'C:\\x\\. \\'),
    ('C:\\x\\ .\\z', 'C:\\x\\ \\z'),
    ('C:\\x\\ .\\z.', 'C:\\x\\ \\z'),
    ('C:\\x\\ .\\z..', 'C:\\x\\ \\z'),
    ('C:\\x\\ .\\z ', 'C:\\x\\ \\z'),
    ('C:\\x\\ .\\z .', 'C:\\x\\ \\z'),
    ('C:\\x\\ .\\z. ', 'C:\\x\\ \\z'),
    ('C:\\x\\ .\\.', 'C:\\x\\'),
    ('C:\\x\\ .\\..', 'C:\\x'),
    ('C:\\x\\ .\\...', 'C:\\x\\ \\'),
    ('C:\\x\\ .\\ ', 'C:\\x\\ \\'),
    ('C:\\x\\ \\z', 'C:\\x\\ \\z'),
    ('C:\\x\\ \\z.', 'C:\\x\\ \\z'),
    ('C:\\x\\ \\z..', 'C:\\x\\ \\z'),
    ('C:\\x\\ \\z ', 'C:\\x\\ \\z'),
    ('C:\\x\\ \\z .', 'C:\\x\\ \\z'),
    ('C:\\x\\ \\z. ', 'C:\\x\\ \\z'),
    ('C:\\x\\ \\.', 'C:\\x\\'),
    ('C:\\x\\ \\..', 'C:\\x'),
    ('C:\\x\\ \\...', 'C:\\x\\ \\'),
    ('C:\\x\\ \\ ', 'C:\\x\\ \\'),
    ('C:\\x\\.a\\z', 'C:\\x\\.a\\z'),
    ('C:\\x\\.a\\z.', 'C:\\x\\.a\\z'),
    ('C:\\x\\.a\\z..', 'C:\\x\\.a\\z'),
    ('C:\\x\\.a\\z ', 'C:\\x\\.a\\z'),
    ('C:\\x\\.a\\z .', 'C:\\x\\.a\\z'),
    ('C:\\x\\.a\\z. ', 'C:\\x\\.a\\z'),
    ('C:\\x\\.a\\.', 'C:\\x\\.a'),
    ('C:\\x\\.a\\..', 'C:\\x'),
    ('C:\\x\\.a\\...', 'C:\\x\\.a\\'),
    ('C:\\x\\.a\\ ', 'C:\\x\\.a\\'),
    ('C:\\x\\a.b\\z', 'C:\\x\\a.b\\z'),
    ('C:\\x\\a.b\\z.', 'C:\\x\\a.b\\z'),
    ('C:\\x\\a.b\\z..', 'C:\\x\\a.b\\z'),
    ('C:\\x\\a.b\\z ', 'C:\\x\\a.b\\z'),
    ('C:\\x\\a.b\\z .', 'C:\\x\\a.b\\z'),
    ('C:\\x\\a.b\\z. ', 'C:\\x\\a.b\\z'),
    ('C:\\x\\a.b\\.', 'C:\\x\\a.b'),
    ('C:\\x\\a.b\\..', 'C:\\x'),
    ('C:\\x\\a.b\\...', 'C:\\x\\a.b\\'),
    ('C:\\x\\a.b\\ ', 'C:\\x\\a.b\\'),
    ('C:\\x\\a.b.\\z', 'C:\\x\\a.b\\z'),
    ('C:\\x\\a.b.\\z.', 'C:\\x\\a.b\\z'),
    ('C:\\x\\a.b.\\z..', 'C:\\x\\a.b\\z'),
    ('C:\\x\\a.b.\\z ', 'C:\\x\\a.b\\z'),
    ('C:\\x\\a.b.\\z .', 'C:\\x\\a.b\\z'),
    ('C:\\x\\a.b.\\z. ', 'C:\\x\\a.b\\z'),
    ('C:\\x\\a.b.\\.', 'C:\\x\\a.b'),
    ('C:\\x\\a.b.\\..', 'C:\\x'),
    ('C:\\x\\a.b.\\...', 'C:\\x\\a.b\\'),
    ('C:\\x\\a.b.\\ ', 'C:\\x\\a.b\\'),
    ('C:\\x\\a\\', 'C:\\x\\a\\'),
    ('C:\\x\\a', 'C:\\x\\a'),
    ('\\\\srv\\share\\a\\z', '\\\\srv\\share\\a\\z'),
    ('\\x\\a\\z', 'C:\\x\\a\\z'),
    ('a\\z', 'C:\\Windows\\a\\z'),
    ('C:\\x\\a.\\', 'C:\\x\\a\\'),
    ('C:\\x\\a.', 'C:\\x\\a'),
    ('\\\\srv\\share\\a.\\z', '\\\\srv\\share\\a\\z'),
    ('\\x\\a.\\z', 'C:\\x\\a\\z'),
    ('a.\\z', 'C:\\Windows\\a\\z'),
    ('C:\\x\\a..\\', 'C:\\x\\a..\\'),
    ('C:\\x\\a..', 'C:\\x\\a'),
    ('\\\\srv\\share\\a..\\z', '\\\\srv\\share\\a..\\z'),
    ('\\x\\a..\\z', 'C:\\x\\a..\\z'),
    ('a..\\z', 'C:\\Windows\\a..\\z'),
    ('C:\\x\\a...\\', 'C:\\x\\a...\\'),
    ('C:\\x\\a...', 'C:\\x\\a'),
    ('\\\\srv\\share\\a...\\z', '\\\\srv\\share\\a...\\z'),
    ('\\x\\a...\\z', 'C:\\x\\a...\\z'),
    ('a...\\z', 'C:\\Windows\\a...\\z'),
    ('C:\\x\\a \\', 'C:\\x\\a \\'),
    ('C:\\x\\a ', 'C:\\x\\a'),
    ('\\\\srv\\share\\a \\z', '\\\\srv\\share\\a \\z'),
    ('\\x\\a \\z', 'C:\\x\\a \\z'),
    ('a \\z', 'C:\\Windows\\a \\z'),
    ('C:\\x\\a  \\', 'C:\\x\\a  \\'),
    ('C:\\x\\a  ', 'C:\\x\\a'),
    ('\\\\srv\\share\\a  \\z', '\\\\srv\\share\\a  \\z'),
    ('\\x\\a  \\z', 'C:\\x\\a  \\z'),
    ('a  \\z', 'C:\\Windows\\a  \\z'),
    ('C:\\x\\a .\\', 'C:\\x\\a \\'),
    ('C:\\x\\a .', 'C:\\x\\a'),
    ('\\\\srv\\share\\a .\\z', '\\\\srv\\share\\a \\z'),
    ('\\x\\a .\\z', 'C:\\x\\a \\z'),
    ('a .\\z', 'C:\\Windows\\a \\z'),
    ('C:\\x\\a. \\', 'C:\\x\\a. \\'),
    ('C:\\x\\a. ', 'C:\\x\\a'),
    ('\\\\srv\\share\\a. \\z', '\\\\srv\\share\\a. \\z'),
    ('\\x\\a. \\z', 'C:\\x\\a. \\z'),
    ('a. \\z', 'C:\\Windows\\a. \\z'),
    ('C:\\x\\a . \\', 'C:\\x\\a . \\'),
    ('C:\\x\\a . ', 'C:\\x\\a'),
    ('\\\\srv\\share\\a . \\z', '\\\\srv\\share\\a . \\z'),
    ('\\x\\a . \\z', 'C:\\x\\a . \\z'),
    ('a . \\z', 'C:\\Windows\\a . \\z'),
    ('C:\\x\\.\\', 'C:\\x\\'),
    ('C:\\x\\.', 'C:\\x'),
    ('\\\\srv\\share\\.\\z', '\\\\srv\\share\\z'),
    ('\\x\\.\\z', 'C:\\x\\z'),
    ('.\\z', 'C:\\Windows\\z'),
    ('C:\\x\\..\\', 'C:\\'),
    ('C:\\x\\..', 'C:\\'),
    ('\\\\srv\\share\\..\\z', '\\\\srv\\share\\z'),
    ('\\x\\..\\z', 'C:\\z'),
    ('..\\z', 'C:\\z'),
    ('C:\\x\\...\\', 'C:\\x\\...\\'),
    ('C:\\x\\...', 'C:\\x\\'),
    ('\\\\srv\\share\\...\\z', '\\\\srv\\share\\...\\z'),
    ('\\x\\...\\z', 'C:\\x\\...\\z'),
    ('...\\z', 'C:\\Windows\\...\\z'),
    ('C:\\x\\. .\\', 'C:\\x\\. \\'),
    ('C:\\x\\. .', 'C:\\x\\'),
    ('\\\\srv\\share\\. .\\z', '\\\\srv\\share\\. \\z'),
    ('\\x\\. .\\z', 'C:\\x\\. \\z'),
    ('. .\\z', 'C:\\Windows\\. \\z'),
    ('C:\\x\\. \\', 'C:\\x\\. \\'),
    ('C:\\x\\. ', 'C:\\x\\'),
    ('\\\\srv\\share\\. \\z', '\\\\srv\\share\\. \\z'),
    ('\\x\\. \\z', 'C:\\x\\. \\z'),
    ('. \\z', 'C:\\Windows\\. \\z'),
    ('C:\\x\\ .\\', 'C:\\x\\ \\'),
    ('C:\\x\\ .', 'C:\\x\\'),
    ('\\\\srv\\share\\ .\\z', '\\\\srv\\share\\ \\z'),
    ('\\x\\ .\\z', 'C:\\x\\ \\z'),
    (' .\\z', 'C:\\Windows\\ \\z'),
    ('C:\\x\\ \\', 'C:\\x\\ \\'),
    ('C:\\x\\ ', 'C:\\x\\'),
    ('\\\\srv\\share\\ \\z', '\\\\srv\\share\\ \\z'),
    ('\\x\\ \\z', 'C:\\x\\ \\z'),
    (' \\z', 'C:\\Windows\\ \\z'),
    ('C:\\x\\.a\\', 'C:\\x\\.a\\'),
    ('C:\\x\\.a', 'C:\\x\\.a'),
    ('\\\\srv\\share\\.a\\z', '\\\\srv\\share\\.a\\z'),
    ('\\x\\.a\\z', 'C:\\x\\.a\\z'),
    ('.a\\z', 'C:\\Windows\\.a\\z'),
    ('C:\\x\\a.b\\', 'C:\\x\\a.b\\'),
    ('C:\\x\\a.b', 'C:\\x\\a.b'),
    ('\\\\srv\\share\\a.b\\z', '\\\\srv\\share\\a.b\\z'),
    ('\\x\\a.b\\z', 'C:\\x\\a.b\\z'),
    ('a.b\\z', 'C:\\Windows\\a.b\\z'),
    ('C:\\x\\a.b.\\', 'C:\\x\\a.b\\'),
    ('C:\\x\\a.b.', 'C:\\x\\a.b'),
    ('\\\\srv\\share\\a.b.\\z', '\\\\srv\\share\\a.b\\z'),
    ('\\x\\a.b.\\z', 'C:\\x\\a.b\\z'),
    ('a.b.\\z', 'C:\\Windows\\a.b\\z'),
    ('C:', 'C:\\Windows'),
    ('C:\\', 'C:\\'),
    ('C:.', 'C:\\Windows'),
    ('C:..', 'C:\\'),
    ('C:foo', 'C:\\Windows\\foo'),
    ('D:foo', 'D:\\foo'),
    ('C:\\..', 'C:\\'),
    ('C:\\..\\..\\a', 'C:\\a'),
    ('C:/a//b\\\\c', 'C:\\a\\b\\c'),
    ('C:\\a\\\\\\b', 'C:\\a\\b'),
    ('\\\\srv\\share', '\\\\srv\\share'),
    ('\\\\srv\\share\\', '\\\\srv\\share\\'),
    ('\\\\srv\\share\\..\\x', '\\\\srv\\share\\x'),
    ('\\\\srv\\share\\.\\x', '\\\\srv\\share\\x'),
    ('\\\\srv', '\\\\srv'),
    ('\\\\srv\\', '\\\\srv\\'),
    ('//srv/share/a', '\\\\srv\\share\\a'),
    ('\\', 'C:\\'),
    ('', None),
    (' ', None),
    ('.', 'C:\\Windows'),
    ('..', 'C:\\'),
    ('C:\\a\\CON\\b', 'C:\\a\\CON\\b'),
    ('C:\\Program Files\\Acme Inc.\\Tool', 'C:\\Program Files\\Acme Inc\\Tool'),
    (' C:\\a', 'C:\\Windows\\ C:\\a'),
    ('C:\\a\\ b', 'C:\\a\\ b'),
    ('C:\\a\\b\\', 'C:\\a\\b\\'),
    ('C:\\a\\b\\\\', 'C:\\a\\b\\'),
    ('C:\\a\\b/', 'C:\\a\\b\\'),
    ('klcp12345', 'C:\\Windows\\klcp12345'),
    ('\\\\srv\\share\\a.\\b', '\\\\srv\\share\\a\\b'),
    ('C:\\' + 'a' * 300, 'C:\\' + 'a' * 300),
    ('C:' + '\\abcdefgh' * 500, 'C:' + '\\abcdefgh' * 500),
    ('c:\\A\\b', 'c:\\A\\b'),
    ('c:', 'C:\\Windows'),
    ('c:foo', 'C:\\Windows\\foo'),
    ('C:\\a\\b\\..\\..\\..', 'C:\\'),
    ('C:\\a\\.\\.\\b', 'C:\\a\\b'),
    ('C:\\a\\b. .\\c', 'C:\\a\\b. \\c'),
    ('C:\\a\\b.. \\c', 'C:\\a\\b.. \\c'),
    ('C:\\a\\ .\\c', 'C:\\a\\ \\c'),
    ('C:\\a\\b ..\\c', 'C:\\a\\b ..\\c'),
    ('C:\\a\\.. .\\c', 'C:\\a\\.. \\c'),
    ('C:\\a\\.. \\c', 'C:\\a\\.. \\c'),
    ('C:\\a\\. \\c', 'C:\\a\\. \\c'),
    ('C:\\a\\.. ', 'C:\\a\\'),
    ('C:\\a\\. ', 'C:\\a\\'),
    ('C:\\a\\..\\', 'C:\\'),
    ('\\\\\\x\\y\\z', '\\\\\\x\\y\\z'),
    ('\\\\\\\\x\\y', '\\\\\\x\\y'),
    ('\\\\srv\\share\\a\\.', '\\\\srv\\share\\a'),
    ('\\\\srv\\share\\a\\..', '\\\\srv\\share'),
    ('\\\\srv\\share\\..', '\\\\srv\\share'),
    ('\\\\srv\\share\\.', '\\\\srv\\share'),
    ('\\\\srv\\\\share\\a', '\\\\srv\\share\\a'),
    ('\\\\srv\\share\\\\a', '\\\\srv\\share\\a'),
    ('C:\\a\\b\\c.\\.', 'C:\\a\\b\\c'),
    ('C:\\a\\b\\c. ', 'C:\\a\\b\\c'),
    ('C:\\a\\b\\c\t', 'C:\\a\\b\\c\t'),
    ('C:\\a\\b\\c\t.', 'C:\\a\\b\\c\t'),
    ('\\\\srv\\share\\a.', '\\\\srv\\share\\a'),
    ('\\\\srv\\share\\a ', '\\\\srv\\share\\a'),
    ('\\..\\a', 'C:\\a'),
    ('\\.\\a', 'C:\\a'),
    ('C:\\a\\b:c', 'C:\\a\\b:c'),
    ('C:\\a:b\\c', 'C:\\a:b\\c'),
    ('C:\\a\\b\\LPT0', 'C:\\a\\b\\LPT0'),
    ('\\\\X', '\\\\X'),
]

_FULL_PATHS_NOT_MODELLED = [
    '\\\\?\\C:\\a\\..\\b',
    '\\\\.\\C:\\a\\..\\b',
    'C:\\a\\CON',
    'C:\\a\\con.txt',
    'C:\\a\\NUL',
    'C:\\a\\COM1',
    'C:\\a\\LPT1',
    'C:\\a\\AUX',
    'C:\\a\\PRN',
    'CON',
    'C:\\a\\CONIN$',
    'C:\\a\\b\\con',
    'C:\\a\\b\\con.txt',
    'C:\\a\\b\\NUL.txt',
    'C:\\a\\b\\nul ',
    'C:\\a\\b\\COM1.txt',
    'C:\\a\\b\\COM¹',
    'C:\\a\\b\\CONOUT$',
    'C:\\a\\b\\prn.',
    'C:\\a\\b\\aux:x',
    '\\\\.\\x',
    '\\\\?\\x',
    '\\\\.',
    '\\\\?',
]


class TestSetupsPathFunctionsPassTheTestsOfInnoSetup(TestBase):
    """
    The cases of the test units of Inno Setup's `PathFunc` unit: `PathFuncTest.pas` of 6.5.0 for
    the rules before Inno Setup 7, `PathFunc.Test.pas` of 7.1.0 for those of Inno Setup 7.
    """

    def test_the_parts_of_drive_and_path(self):
        for path_func, cases in ((PATH_FUNC_6, _PART_LENGTHS_6), (PATH_FUNC_7, _PART_LENGTHS_7)):
            for path, *lengths in cases:
                with self.subTest(inno7=path_func.inno7, path=path):
                    self.assertEqual([
                        path_func.drive_part_length(path),
                        path_func.drive_part_length(path, True),
                        path_func.path_part_length(path, False),
                        path_func.path_part_length(path, True),
                    ], lengths)

    def test_removing_backslashes(self):
        for path_func, cases in ((PATH_FUNC_6, _REMOVE_BACKSLASH_6), (PATH_FUNC_7, _REMOVE_BACKSLASH_7)):
            for path, removed in cases:
                with self.subTest(inno7=path_func.inno7, path=path):
                    self.assertEqual(path_func.remove_backslash(path), removed)

    def test_removing_backslashes_unless_at_the_root(self):
        for path_func, cases in (
            (PATH_FUNC_6, _REMOVE_BACKSLASH_UNLESS_ROOT_6),
            (PATH_FUNC_7, _REMOVE_BACKSLASH_UNLESS_ROOT_7),
        ):
            for path, removed in cases:
                with self.subTest(inno7=path_func.inno7, path=path):
                    self.assertEqual(path_func.remove_backslash_unless_root(path), removed)

    def test_adding_a_backslash(self):
        for path, added in _ADD_BACKSLASH_7:
            with self.subTest(path=path):
                self.assertEqual(PATH_FUNC_7.add_backslash(path), added)

    def test_changing_an_extension(self):
        for path_func, cases in ((PATH_FUNC_6, _CHANGE_EXT_6), (PATH_FUNC_7, _CHANGE_EXT_7)):
            for path, extension, changed in cases:
                with self.subTest(inno7=path_func.inno7, path=path, extension=extension):
                    self.assertEqual(path_func.change_ext(path, extension), changed)

    def test_extracting_an_extension(self):
        for path_func, cases in ((PATH_FUNC_6, _EXTRACT_EXT_6), (PATH_FUNC_7, _EXTRACT_EXT_7)):
            for path, extension in cases:
                with self.subTest(inno7=path_func.inno7, path=path):
                    self.assertEqual(path_func.extract_ext(path), extension)

    def test_the_position_of_an_extension_counted_from_one(self):
        for path, position in _EXTENSION_POSITION_7:
            found = PATH_FUNC_7.extension_position(path)
            with self.subTest(path=path):
                self.assertEqual(0 if found is None else found + 1, position)

    def test_extracting_name_path_folder_and_drive(self):
        for path, *parts in _EXTRACTS_7:
            with self.subTest(path=path):
                self.assertEqual([
                    PATH_FUNC_7.extract_name(path),
                    PATH_FUNC_7.extract_path(path),
                    PATH_FUNC_7.extract_dir(path),
                    PATH_FUNC_7.extract_drive(path),
                ], parts)

    def test_normalizing_slashes(self):
        for path, normalized in _NORMALIZE_SLASHES_7 + _EXPAND_AND_NORMALIZE_SLASHES_7:
            with self.subTest(path=path):
                self.assertEqual(PATH_FUNC_7.normalize_slashes(path), normalized)
        for path, normalized in _EXPAND_AND_NORMALIZE_SLASHES_NOT_MODELLED_7:
            with self.subTest(path=path):
                self.assertEqual(PATH_FUNC_7.normalize_slashes(path), normalized)

    def test_expanding_a_path(self):
        for path, expanded in _EXPAND_7 + _EXPAND_AND_NORMALIZE_SLASHES_7:
            with self.subTest(path=path):
                self.assertEqual(PATH_FUNC_7.expand(path, _WINDOWS), expanded)

    def test_a_path_that_names_a_device_or_a_namespace_is_not_modelled(self):
        for path, _ in _EXPAND_NOT_MODELLED_7 + _EXPAND_AND_NORMALIZE_SLASHES_NOT_MODELLED_7:
            with self.subTest(path=path), self.assertRaises(NotImplementedError):
                PATH_FUNC_7.expand(path, _WINDOWS)


class TestSetupExpandsPathsAsWindowsDoes(TestBase):
    """
    `GetFullPathName` of Windows 11, which Setup's `PathExpand` and Delphi's `ExpandFileName` call,
    gave `_FULL_PATHS` in the current folder `_WINDOWS`. Windows 10 maps device names to devices
    in more places; the emulator models no device name.
    """

    def test_each_full_path_is_the_one_that_windows_gave(self):
        for path, full in _FULL_PATHS:
            with self.subTest(path=path):
                self.assertEqual(full_path_name(path, _WINDOWS), full)

    def test_a_path_that_names_a_device_or_a_namespace_is_not_modelled(self):
        for path in _FULL_PATHS_NOT_MODELLED:
            with self.subTest(path=path), self.assertRaises(NotImplementedError):
                full_path_name(path, _WINDOWS)

    def test_setup_before_inno_setup_7_keeps_a_path_that_windows_cannot_expand(self):
        self.assertEqual(PATH_FUNC_6.expand('   ', _WINDOWS), '   ')

    def test_setup_before_inno_setup_7_keeps_a_path_whose_full_path_has_4096_characters(self):
        """
        Setup's buffer for the full path holds 4096 characters with the closing NUL.
        """
        self.assertEqual(len(F'{_WINDOWS}\\') + 4085, 4096)
        self.assertEqual(PATH_FUNC_6.expand('a' * 4085, _WINDOWS), 'a' * 4085)
        self.assertEqual(PATH_FUNC_6.expand('a' * 4084, _WINDOWS), F'{_WINDOWS}\\{"a" * 4084}')

    def test_inno_setup_7_fails_for_a_path_that_windows_cannot_expand(self):
        with self.assertRaises(PathFuncError):
            PATH_FUNC_7.expand('a' * 0x8000, _WINDOWS)

    def test_delphi_expands_a_path_that_windows_cannot_expand_to_an_empty_text(self):
        self.assertEqual(expand_file_name('   ', _WINDOWS), '')

    def test_the_installed_paths_are_compared_by_their_full_path_without_case(self):
        paths = InstalledPaths(CurrentFolder(_WINDOWS))
        paths.add_directory('C:\\a\\dir')
        paths.add_file('C:\\a\\dir\\file.txt')
        self.assertTrue(paths.directory_exists('c:\\A\\dir.'))
        self.assertTrue(paths.file_exists('C:/a/dir/./FILE.TXT '))
        self.assertTrue(paths.file_exists('..\\a\\dir\\file.txt'))
