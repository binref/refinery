from __future__ import annotations

import codecs
import collections
import enum
import re
import struct

from functools import cached_property
from typing import NamedTuple

from refinery.lib import chunks, json
from refinery.lib.cab import Cabinet
from refinery.lib.id import buffer_offset, is_likely_msi, is_likely_pe
from refinery.lib.structures import StructReader
from refinery.lib.types import Param, buf
from refinery.units import Arg
from refinery.units.formats.csv import csv
from refinery.units.formats.office.xtdoc import UnpackResult, xtdoc


class MsiType(enum.IntEnum):
    """
    Known data types for MSI table cell entries.
    """

    Long = 0x104
    Short = 0x502
    Binary = 0x900
    String = 0xD00
    StringLocalized = 0xF00
    Unknown = 0

    def __str__(self):
        return self.name


class MSITableColumnInfo(NamedTuple):
    """
    Represents information about an MSI table column. See also:
    https://doxygen.reactos.org/db/de4/msipriv_8h.html
    """
    number: int
    attributes: int

    @property
    def type(self) -> MsiType:
        try:
            if self.is_integer:
                return MsiType(self.attributes & 0xFFF)
            else:
                return MsiType(self.attributes & 0xF00)
        except Exception:
            return MsiType.Unknown

    @property
    def is_integer(self) -> bool:
        return self.attributes & 0x0F00 < 0x800

    @property
    def is_key(self) -> bool:
        return self.attributes & 0x2000 == 0x2000

    @property
    def is_nullable(self) -> bool:
        return self.attributes & 0x1000 == 0x1000

    @property
    def length(self) -> int:
        vt = self.type
        if vt is MsiType.Long:
            return 4
        if vt is MsiType.Short:
            return 2
        return self.attributes & 0xFF

    @property
    def struct_format(self) -> str:
        vt = self.type
        if vt is MsiType.Long:
            return 'I'
        elif vt is MsiType.Short:
            return 'H'
        else:
            return 'H'


_NEGATED_MSI_SIGNATURE = B'\x2F\x30\xEE\x1F\x5E\x4E\xE5\x1E'


class MSIStringData:
    def __init__(self, string_data: buf, string_pool: buf):
        data = StructReader(string_data)
        pool = StructReader(string_pool)
        self.strings: list[bytes] = []
        self.provided_ref_count: list[int] = []
        self.computed_ref_count: list[int] = []
        self.codepage = pool.u16()
        self._unknown = pool.u16()
        while not pool.eof:
            size = pool.u16()
            rc = pool.u16()
            if size == 0 and rc != 0:
                size = pool.u32()
            string = data.read_bytes(size)
            self.strings.append(string)
            self.provided_ref_count.append(rc)
            self.computed_ref_count.append(0)

    @cached_property
    def codec(self):
        try:
            return codecs.lookup(F'cp{self.codepage}').name
        except Exception:
            xtmsi.log_info('failed looking up codec', self.codepage)
            return 'latin1'

    def __len__(self):
        return len(self.strings)

    def __iter__(self):
        yield from range(1, len(self) + 1)

    def __contains__(self, index):
        return 0 < index <= len(self)

    def ref(self, index: int, increment=True) -> str:
        assert index > 0
        index -= 1
        if increment:
            self.computed_ref_count[index] += 1
        string = self.strings[index]
        try:
            return string.decode(self.codec)
        except UnicodeDecodeError:
            return string.decode('latin1')


class xtmsi(xtdoc):
    """
    Extract files and metadata from Microsoft Installer (MSI) archives. The synthetic file {FN} contains
    parsed MSI table information, similar to the output of the Orca tool. Binary streams are placed in a
    virtual folder called "Binary", and extracted scripts from custom actions are separately extracted in
    a virtual folder named "Action".
    """

    _SYNTHETIC_STREAMS_FILENAME = 'MsiTables.json'
    _SYNTHETIC_STREAMS_TOPLEVEL = 'MsiTables'

    # https://learn.microsoft.com/en-us/windows/win32/msi/summary-list-of-all-custom-action-types
    _CUSTOM_ACTION_TYPES = {
        0x01: 'DLL file stored in a Binary table stream.',
        0x02: 'EXE file stored in a Binary table stream.',
        0x05: 'JScript file stored in a Binary table stream.',
        0x06: 'VBScript file stored in a Binary table stream.',
        0x11: 'DLL file that is installed with a product.',
        0x12: 'EXE file that is installed with a product.',
        0x13: 'Displays a specified error message and returns failure, terminating the installation.',
        0x15: 'JScript file that is installed with a product.',
        0x16: 'VBScript file that is installed with a product.',
        0x22: 'EXE file having a path referencing a directory.',
        0x23: 'Directory set with formatted text.',
        0x25: 'JScript text stored in this sequence table.',
        0x26: 'VBScript text stored in this sequence table.',
        0x32: 'EXE file having a path specified by a property value.',
        0x33: 'Property set with formatted text.',
        0x35: 'JScript text specified by a property value.',
        0x36: 'VBScript text specified by a property value.',
    }

    def __init__(
        self, *paths,
        list=False, path=b'path', join_path=False, drop_path=False, fuzzy=0, exact=False, regex=False,
        nocab: Param[bool, Arg.Switch('-N', help='Do not list and extract embedded CAB archives.')] = False,
        **keywords,
    ):
        super().__init__(
            *paths,
            list=list,
            path=path,
            join_path=join_path,
            drop_path=drop_path,
            nocab=nocab,
            fuzzy=fuzzy,
            exact=exact,
            regex=regex,
            **keywords,
        )

    def unpack(self, data: buf):
        streams = {
            result.path: result
            for result in super().unpack(self.get_msi_from_overlay(data))
        }

        def stream(name: str):
            return streams.pop(name).get_data()

        def column_formats(table: dict[str, MSITableColumnInfo]) -> str:
            return ''.join(v.struct_format for v in table.values())

        def stream_to_rows(data: buf, row_format: str):
            row_size = struct.calcsize(F'<{row_format}')
            row_count = int(len(data) / row_size)
            reader = StructReader(data)
            columns = [reader.read_struct(F'<{sc * row_count}') for sc in row_format]
            for i in range(row_count):
                yield [int(c[i]) for c in columns]

        tables: dict[str, dict[str, MSITableColumnInfo]] = collections.defaultdict(collections.OrderedDict)
        strings = MSIStringData(stream('!_StringData'), stream('!_StringPool'))

        for tbl_name_id, col_number, col_name_id, col_attributes in stream_to_rows(stream('!_Columns'), 'HHHH'):
            tbl_name = strings.ref(tbl_name_id)
            col_name = strings.ref(col_name_id)
            tables[tbl_name][col_name] = MSITableColumnInfo(col_number, col_attributes)

        table_names_given = {strings.ref(k) for k in chunks.unpack(stream('!_Tables'), 2, False)}
        table_names_known = set(tables)

        for name in table_names_known - table_names_given:
            self.log_warn(F'table name known but not given: {name}')
        for name in table_names_given - table_names_known:
            self.log_warn(F'table name given but not known: {name}')

        class ScriptItem(NamedTuple):
            row_index: int
            extension: str | None

        processed_table_data: dict[str, list[dict[str, str]]] = {}
        tbl_properties: dict[str, str] = {}
        tbl_files: dict[str, str] = {}
        tbl_components: dict[str, str] = {}
        postprocessing: list[ScriptItem] = []

        def format_string(string: str):
            # https://learn.microsoft.com/en-us/windows/win32/msi/formatted
            def _replace(match: re.Match[str]):
                nonlocal _replace_done
                _replace_done = False
                prefix, name = match.groups()
                if not prefix:
                    tbl = tbl_properties
                elif prefix in '%':
                    name = name.rstrip('%').upper()
                    return F'%{name}%'
                elif prefix in '!#':
                    tbl = tbl_files
                elif prefix in '$':
                    tbl = tbl_components
                else:
                    raise ValueError
                return tbl.get(name, '')
            while True:
                _replace_done = True
                string = re.sub(R'''(?x)
                    \[             # open square bracket
                      (?![~\\])    # not followed by escapes
                      ([%$!#]?)    # any of the valid prefix characters
                      ([^[\]{}]+)  # no brackets or braces
                    \]''', _replace, string)
                if _replace_done:
                    break
            string = re.sub(r'\[\\(.)\]', r'\1', string)
            string = string.replace('[~]', '\0')
            return string

        for table_name, table in tables.items():
            stream_name = F'!{table_name}'
            if stream_name not in streams:
                continue
            processed = []
            info = list(table.values())
            keys = list(table.keys())
            temp = [k.strip('_') for k in keys]
            if len(set(keys)) == len(set(temp)):
                keys = temp
            for r, row in enumerate(stream_to_rows(stream(stream_name), column_formats(table))):
                values = []
                for index, value in enumerate(row):
                    vt = info[index].type
                    if vt is MsiType.Long:
                        if value != 0:
                            value -= 0x80000000
                    elif vt is MsiType.Short:
                        if value != 0:
                            value -= 0x8000
                    elif value in strings:
                        value = strings.ref(value)
                    elif not info[index].is_integer:
                        value = ''
                    values.append(value)
                if table_name == 'Property':
                    tbl_properties[values[0]] = values[1]
                if table_name == 'File':
                    tbl_properties[values[0]] = values[2]
                if table_name == 'Component':
                    tbl_properties[values[0]] = F'%{values[2]}%'
                entry = dict(zip(keys, values))
                einfo = {t: i for t, i in zip(keys, info)}
                if table_name == 'MsiFileHash':
                    entry['Hash'] = struct.pack(
                        '<IIII',
                        row[2] ^ 0x80000000,
                        row[3] ^ 0x80000000,
                        row[4] ^ 0x80000000,
                        row[5] ^ 0x80000000,
                    ).hex()
                if table_name == 'CustomAction':
                    code = row[1] & 0x3F
                    try:
                        entry['Comment'] = self._CUSTOM_ACTION_TYPES[code]
                    except LookupError:
                        pass
                    t = einfo.get('Target')
                    c = {0x25: 'js', 0x26: 'vbs', 0x33: None}
                    if code in c and t and not t.is_integer:
                        postprocessing.append(ScriptItem(r, c[code]))
                processed.append(entry)
            if processed:
                processed_table_data[table_name] = processed

        if ca := processed_table_data.get('CustomAction'):
            for item in postprocessing:
                entry = ca[item.row_index]
                try:
                    action: str = entry['Action']
                    target: str = entry['Target']
                except KeyError:
                    continue
                root = F'Action/{action}'
                if item.extension:
                    action = F'{root}.{item.extension}'
                    streams[action] = UnpackResult(action, target.encode(self.codec))
                    continue
                target = format_string(target)
                parts = [part.partition('\x02') for part in target.split('\x01')]
                if not all(part[1] == '\x02' for part in parts):
                    continue
                for name, _, script in parts:
                    if not name.lower().startswith('script'):
                        continue
                    if not script:
                        continue
                    action = F'{root}.{name}'
                    streams[action] = UnpackResult(action, script.encode(self.codec))

        for ignored_stream in [
            'SummaryInformation',
            'DocumentSummaryInformation',
            'DigitalSignature',
            'MsiDigitalSignatureEx'
        ]:
            if r := streams.pop(F'[5]{ignored_stream}', None):
                r.path = F'Meta/{ignored_stream}'
                yield r

        inconsistencies = 0
        w1 = len(str(len(strings)))
        w2 = len(str(max(max(strings.computed_ref_count), max(strings.provided_ref_count))))
        for k in range(len(strings)):
            c = strings.computed_ref_count[k]
            p = strings.provided_ref_count[k]
            if c != p and not self.log_debug(F'string {k:0{w1}d} reference count computed={c:0{w2}d} provided={p:0{w2}d}'):
                inconsistencies += 1
        if inconsistencies:
            self.log_info(F'found {inconsistencies} incorrect string reference counts')

        def fix_msi_path(path: str):
            prefix, dot, name = path.partition('.')
            if dot == '.' and prefix in processed_table_data:
                path = F'{prefix}/{name}'
            return path

        if self.args.nocab:
            cabs = {}
        else:
            def _iscab(path):
                return media_info and any(item.get('Cabinet', '') == F'#{path}' for item in media_info)
            media_info = processed_table_data.get('Media', [])
            cabs: dict[str, UnpackResult] = {
                path: item for path, item in streams.items() if _iscab(path)}
            for cab in cabs:
                self.log_info(F'found cab file: {cab}')
        if cabs:
            file_names: dict[str, str] = {}

            for file_info in processed_table_data.get('File', []):
                try:
                    src_name = file_info['File']
                    dst_name = file_info['FileName']
                except KeyError:
                    continue
                _, _, long = dst_name.partition('|')
                dst_name = long or dst_name
                file_names[src_name] = dst_name

            for path, cab in cabs.items():
                try:
                    _cabinet = Cabinet(memoryview(cab.get_data()))
                    unpacked = _cabinet.process().get_files()
                except Exception as e:
                    self.log_info(F'unable to extract embedded cab file: {e!s}')
                    continue
                base, dot, ext = path.rpartition('.')
                if dot == '.' and ext.lower() == 'cab':
                    path = base
                else:
                    del streams[path]
                    cab.path = F'{path}.cab'
                    streams[cab.path] = cab
                for result in unpacked:
                    sub_path = file_names.get(result.name, result.name)
                    sub_path = self._get_path_separator().join((path, sub_path))
                    streams[sub_path] = UnpackResult(sub_path, lambda r=result: r.decompress())

        streams = {fix_msi_path(path): item for path, item in streams.items()}
        ds = UnpackResult(self._SYNTHETIC_STREAMS_FILENAME, json.dumps(processed_table_data))
        streams[ds.path] = ds

        converter = csv()
        for key, jd in processed_table_data.items():
            sk = key.strip('_')
            if sk not in processed_table_data:
                key = sk
            try:
                tbl = UnpackResult(F'{self._SYNTHETIC_STREAMS_TOPLEVEL}/{key}.csv', converter.json_to_csv(jd))
            except Exception:
                continue
            streams[tbl.path] = tbl

        for path in sorted(streams):
            streams[path].path = path
            yield streams[path]

    @classmethod
    def get_msi_from_overlay(cls, data: buf) -> buf:
        if is_likely_pe(data):
            from refinery.units.formats.pe import get_pe_size
            view = memoryview(data)
            overlay = view[get_pe_size(data):]
            if is_likely_msi(overlay):
                return overlay
            if (start := buffer_offset(overlay, _NEGATED_MSI_SIGNATURE, 0, 0x1000)) >= 0:
                if (nulls := buffer_offset(overlay, bytes(8), start, start + 0x1000)) >= 0:
                    from refinery.units.blockwise.neg import neg
                    decoded = overlay[start:nulls] | neg | bytearray
                    decoded.extend(overlay[nulls:])
                    if is_likely_msi(decoded):
                        return decoded
        return data

    @classmethod
    def handles(cls, data):
        if is_likely_msi(data):
            return True
        if is_likely_pe(data):
            from refinery.units.formats.pe import get_pe_size
            view = memoryview(data)
            overlay = view[get_pe_size(data):]
            if is_likely_msi(overlay):
                return True
            if overlay[:8] == _NEGATED_MSI_SIGNATURE:
                return True
        return False


if _d := xtmsi.__doc__:
    xtmsi.__doc__ = _d.format(FN=xtmsi._SYNTHETIC_STREAMS_FILENAME)
