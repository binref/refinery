from __future__ import annotations

import difflib
import re
import struct

from typing import NamedTuple

from refinery.lib import json
from refinery.lib.cab import Cabinet
from refinery.lib.lcid import DEFAULT_CODEPAGE, LCID
from refinery.lib.structures import StructReader
from refinery.units.formats.archive import ArchiveUnit


class SIMOffsets(NamedTuple):
    archive_end: int
    strings_offset: int = 0
    runtime_length: int = 0
    runtime_offset: int = 0
    content_offset: int = 0
    runtime_is_cab: bool = False
    nr_of_runtime: int = 0
    nr_of_strings: int = 0
    sim_signature: int = 0

    def rebase(self, strings_offset: int):
        delta = strings_offset - self.strings_offset
        a, s, n, r, c, p1, p2, p3, p4 = self
        s += delta
        r += delta
        c += delta
        return SIMOffsets(a, s, n, r, c, p1, p2, p3, p4)


def tojson(cls):
    class mix(cls):
        def json(self: NamedTuple):
            return dict(zip(self._fields, self))
    return mix


_SIMNAME = b'Smart Install Maker v.'
_SIGBYTE = 0xF1


def longest_common_substring(string1: str, string2: str):
    return difflib.SequenceMatcher(
        None, string1, string2
    ).find_longest_match(
        0, len(string1),
        0, len(string2),
    ).size


class xtsim(ArchiveUnit, docs='{0}{s}{PathExtractorUnit}'):
    """
    Extract files from Smart Install Maker (SIM) executables.
    """

    _RUNTIME_MAPPING = {
        '4.tmp'  : 'header.png',
        '5.tmp'  : 'wizard.bmp',
        '6.tmp'  : 'background.bmp',
        '7.tmp'  : 'folder.png',
        '8.tmp'  : 'group.png',
        '9.tmp'  : 'password.png',
        '15.tmp' : 'license1.rtf',
        '16.tmp' : 'information.rtf',
        '20.tmp' : 'license2.rtf',
    }

    _DIRECTORY_MASKS = {
        '@$&%01': 'ProgramFiles',
        '@$&%02': 'WindowsDir',
        '@$&%03': 'SystemDir',
        '@$&%04': 'InstallPath',
        '@$&%05': 'TempDir',
        '@$&%06': 'Desktop',
        '@$&%07': 'QuickLaunch',
        '@$&%08': 'ProgramsDir',
        '@$&%09': 'StartMenu',
        '@$&%10': 'MyDocuments',
        '@$&%11': 'Favorites',
        '@$&%12': 'SendTo',
        '@$&%13': 'UserProfile',
        '@$&%14': 'StartUp',
        '@$&%15': 'FontsDir',
        '@$&%16': 'CommonFiles',
        '@$&%17': 'SystemDrive',
        '@$&%18': 'CurrentDirectory',
        '@$&%20': 'UserName',
        '@$&%21': 'Language',
        '@$&%22': 'ComputerName',
        '@$&%26': 'AppData',
        '@$&%27': 'CommonAppData',
        '@$&%28': 'CommonDesktop',
        '@$&%29': 'CommonDocuments',
        '@$&%30': 'CommonFavourites',
        '@$&%31': 'CommonPrograms',
        '@$&%32': 'CommonStartMenu',
        '@$&%33': 'CommonStartup',
        '@$&%34': 'Templates',
        '@$&%35': 'CommonTemplates',
        '@$&%36': 'ProgramFiles64',
    }

    def unpack(self, data):
        mem = memoryview(data)
        sim = self.get_offsets(data)

        if sim is None:
            return B''

        strings = StructReader(mem[sim.strings_offset:sim.runtime_offset])
        runtime = StructReader(mem[sim.runtime_offset:sim.content_offset])
        content = StructReader(mem[sim.content_offset:sim.archive_end])

        def read_str():
            return bytes(strings.read_c_string())

        header: list = [read_str() for _ in range(sim.nr_of_strings)]
        tables: dict[str, list[list]] = {}
        unknown_tables: dict[str, list[list]] = {}

        def sc(k: int):
            return int(header[k])

        for size, index, name in [
            (4, 98, None),
            (7, 50, 'registry'),    # (2=HKLM/1=HKCU,key)
            (3, 96, None),
            (2, 31, 'fonts'),
            (8, 54, 'shortcuts'),   # (?,0=Menu/1=Desktop,filename,target_path,comment,icon_path1,icon_path2)
            (3, 67, 'filenames'),
            (2, 93, None),
            (6, 40, 'install'),     #
            (6, 25, 'uninstall'),
            (6, 24, 'ini'),         # 34991da998ece07d4a941394c6630ce74955fb4800e5915f6766180d12a8dc61
            (2, 45, None),
            (2, 20, None),
            (4, 26, 'languages'),
        ]:
            count = sc(index)
            if not count:
                continue
            table = [[
                read_str() for _ in range(size)
            ] for _ in range(count)]
            if name is None:
                unknown_tables[F'T{index}'] = table
            else:
                tables[name] = table

        unknown_marker = read_str()

        language_count = sc(26)
        message_matrix = [[
            read_str() for _ in range(sc(57))
        ] for _ in range(language_count)]

        len_chunks = sc(117)
        chunk_size = sc(95)
        chunk_rest = sc(118)

        def check_empty_reader(r: StructReader, name: str):
            if _c := r.remaining_bytes:
                self.log_warn(F'{name} reader had 0x{_c:08X} bytes remaining:', r.peek(), clip=True)

        check_empty_reader(strings, 'strings')

        lngid = tables['languages'][0]
        lid: bytes = lngid[2]
        if not lid.isdigit():
            _lname: bytes = lngid[1]
            lname = _lname.decode('latin1')
            lngid = max(LCID, key=lambda k: longest_common_substring(LCID[k], lname))
        else:
            lngid = int(lngid[2])

        codec = DEFAULT_CODEPAGE.get(lngid, 'latin1')

        def decode(_cell: bytes, codec: str):
            try:
                cell = _cell.decode(codec)
            except UnicodeDecodeError:
                cell = _cell.decode('latin1')
                self.log_debug('failed to decode string:', cell, clip=True)
            if cell.isdigit():
                return int(cell)
            if not cell:
                return None
            for key, val in self._DIRECTORY_MASKS.items():
                cell = cell.replace(key, F'${val}')
            return cell

        header[:] = [decode(s, codec) for s in header]

        for t in (tables, unknown_tables):
            for name, table in t.items():
                for row in table:
                    row[:] = [decode(cell, codec) for cell in row]

        messages = {}

        for array, lng in zip(message_matrix, tables['languages']):
            lng_codec = DEFAULT_CODEPAGE.get(lng[2], 'latin1')
            messages[lng[1]] = [decode(cell, lng_codec) for cell in array]

        tables['messages'] = messages
        tables['header'] = header

        if unknown_tables:
            tables['unknown_tables'] = unknown_tables
        if unknown_marker:
            tables['unknown_marker'] = decode(unknown_marker, codec)

        yield self._pack('setup.json', None, json.dumps(tables))

        def runtime_path(name: str):
            root, backslash, temp = name.rpartition('\\')
            if backslash and root == '$inst' and (t := self._RUNTIME_MAPPING.get(temp)):
                name = t
            return F'runtime/{name}'

        if sim.runtime_is_cab:
            runtime_cab = Cabinet(runtime.read(), no_magic=True)
            for file in runtime_cab.process().get_files():
                yield self._pack(runtime_path(file.name), file.timestamp, lambda f=file: f.decompress())
        else:
            for _ in range(sim.nr_of_runtime):
                name = decode(runtime.read_c_string(), codec)
                assert isinstance(name, str)
                path = runtime_path(name)
                size = int(runtime.read_c_string())
                yield self._pack(path, None, runtime.read(size))
            check_empty_reader(runtime, 'runtime')

        def no_abs_path(p: str):
            drive, d, rest = p.partition(':\\')
            if d and len(drive) == 1:
                return F'$Drive{drive.upper()}\\{rest}'
            return p

        if len_chunks + chunk_rest == 0:
            for file in tables['filenames']:
                path = no_abs_path(file[1])
                content.u32() # unknown
                size = content.u32()
                content.u32() # unknown
                content.u32() # unknown
                content.u32() # unknown
                content.u32() # unknown
                yield self._pack(F'data/{path}', None, content.read(size))
        else:
            content_cab = Cabinet(no_magic=True)
            content_cab.extend(content.read(chunk_size) for _ in range(len_chunks))
            if chunk_rest > 0:
                content_cab.append(content.read(chunk_rest))
            for file in content_cab.process().get_files():
                try:
                    path = tables['filenames'][int(file.name)][1]
                except Exception:
                    path = file.name
                path = F'content/{no_abs_path(path)}'
                yield self._pack(path, file.timestamp, lambda f=file: f.decompress())

        check_empty_reader(content, 'content')

    @classmethod
    def get_offsets(cls, data: bytes | bytearray) -> SIMOffsets | None:
        if len(data) < 0x1000:
            return None

        def sane(offsets: SIMOffsets):
            if offsets.sim_signature != _SIGBYTE:
                return False
            for offset in (
                offsets.strings_offset,
                offsets.runtime_offset,
                offsets.content_offset,
            ):
                if offset not in range(0x1000, 0x100000000):
                    return False
            if offsets.strings_offset >= offsets.runtime_offset:
                return False
            return offsets.content_offset >= offsets.runtime_offset + offsets.runtime_length

        end = len(data) - 0x24
        offsets = SIMOffsets(end, *struct.unpack('<QQQQ?BBB', data[end:]))

        if sane(offsets):
            pos = offsets.strings_offset
            end = pos + len(_SIMNAME)
            if data[pos:end] == _SIMNAME:
                return offsets
            pos = data.rfind(_SIMNAME)
            if pos > 0:
                return offsets.rebase(pos)

        view = memoryview(data)

        for stub in re.finditer(rb'MZ.{78}This program must be run under Win', data):
            pos_zero = stub.start()
            pos_data = data.find(_SIMNAME, pos_zero)
            if pos_data < 0:
                continue
            pattern = re.escape((pos_data - pos_zero).to_bytes(8, 'little')) + B'.{27}\\xF1'
            if match := re.search(pattern, view[pos_zero:]):
                end = match.start()
                offsets = SIMOffsets(end, *struct.unpack('<QQQQ?BBB', match[0]))
                if sane(offsets):
                    return offsets.rebase(pos_zero)

    @classmethod
    def handles(cls, data) -> bool | None:
        if isinstance(data, (bytes, bytearray)):
            return cls.get_offsets(data) is not None
