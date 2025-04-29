#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import itertools
import json

from contextlib import suppress
from importlib import resources
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from enum import Enum

from refinery.lib import lief
from refinery.lib.dotnet.header import DotNetHeader
from refinery.units import Arg, Unit
from refinery.units.sinks.ppjson import ppjson
from refinery.units.formats.pe import get_pe_size
from refinery.lib.tools import date_from_timestamp
from refinery.lib.lcid import LCID

from refinery import data


def _FILETIME(value: int) -> datetime:
    s, ns100 = divmod(value - 116444736000000000, 10000000)
    return datetime.fromtimestamp(s, timezone.utc).replace(microsecond=(ns100 // 10))


def _STRING(value: str | bytes, dll: bool = False) -> str:
    if not isinstance(value, str):
        value, _, _ = value.partition(B'\0')
        value = value.decode('utf8')
    if dll and value.lower().endswith('.dll'):
        value = value[~3:]
    return value


class VIT(str, Enum):
    ERR = 'unknown'
    OBJ = 'object file from C'
    CPP = 'object file from C++'
    ASM = 'object file from assembler'
    RES = 'object from CVTRES'
    LNK = 'linker version'
    IMP = 'dll import in library file'
    EXP = 'dll export in library file'

    @property
    def tag(self) -> str:
        if self in (VIT.OBJ, VIT.CPP, VIT.ASM, VIT.RES):
            return 'object'
        if self is VIT.IMP:
            return 'import'
        if self is VIT.EXP:
            return 'export'
        if self is VIT.LNK:
            return 'linker'
        else:
            return 'unknown'


@dataclass
class VersionInfo:
    pid: str
    ver: str
    err: bool

    def __str__(self):
        return F'{self.ver} [{self.pid.upper()}]'

    def __bool__(self):
        return not self.err


with resources.path(data, 'rich.json') as path:
    with path.open('r') as stream:
        RICH = json.load(stream)


class ShortPID(str, Enum):
    UTC = 'STDLIB' # STDLIBC
    RES = 'CVTRES' # Cvt/RES
    OMF = 'CVTOMF' # Cvt/OMF
    PGD = 'CVTPGD' # Cvt/PGD
    LNK = 'LINKER' # Linker
    EXP = 'EXPORT' # Exports
    IMP = 'IMPORT' # Imports
    OBJ = 'OBJECT' # Object
    PHX = 'PHOENX' # Phoenix
    ASM = 'MASM'   # MASM
    MIL = 'MSIL'   # MSIL
    VB6 = 'VB6OBJ' # VB6

    def __str__(self):
        width = max(len(item.value) for item in self.__class__)
        return F'{self.value:>{width}}'


def get_rich_short_pid(pid: str) -> ShortPID:
    pid = pid.upper()
    if pid.startswith('UTC'):
        return ShortPID.UTC
    if pid.startswith('CVTRES'):
        return ShortPID.RES
    if pid.startswith('CVTOMF'):
        return ShortPID.OMF
    if pid.startswith('CVTPGD'):
        return ShortPID.PGD
    if pid.startswith('LINKER'):
        return ShortPID.LNK
    if pid.startswith('EXPORT'):
        return ShortPID.EXP
    if pid.startswith('IMPORT'):
        return ShortPID.IMP
    if pid.startswith('IMPLIB'):
        return ShortPID.IMP
    if pid.startswith('ALIASOBJ'):
        return ShortPID.OBJ
    if pid.startswith('RESOURCE'):
        return ShortPID.RES
    if pid.startswith('PHX'):
        return ShortPID.PHX
    if pid.startswith('PHOENIX'):
        return ShortPID.PHX
    if pid.startswith('MASM'):
        return ShortPID.ASM
    if pid.startswith('ILASM'):
        return ShortPID.MIL
    if pid.startswith('VISUALBASIC'):
        return ShortPID.VB6
    raise LookupError(pid)


def get_rich_info(vid: int) -> VersionInfo:
    pid = vid >> 0x10
    ver = vid & 0xFFFF
    ver = RICH['ver'].get(F'{ver:04X}')
    pid = RICH['pid'].get(F'{pid:04X}')
    err = ver is None and pid is None
    if ver is not None:
        suffix = ver.get('ver')
        ver = ver['ide']
        if suffix:
            ver = F'{ver} {suffix}'
    else:
        ver = 'Unknown Version'
    pid = pid or 'Unknown Type'
    return VersionInfo(pid, ver, err)


class pemeta(Unit):
    """
    Extract metadata from PE files. By default, all information except for imports and exports are
    extracted.
    """
    def __init__(
        self, custom : Arg('-c', '--custom',
            help='Unless enabled, all default categories will be extracted.') = False,
        debug      : Arg.Switch('-D', help='Parse the PDB path from the debug directory.') = False,
        dotnet     : Arg.Switch('-N', help='Parse the .NET header.') = False,
        signatures : Arg.Switch('-S', help='Parse digital signatures.') = False,
        timestamps : Arg.Counts('-T', help='Extract time stamps. Specify twice for more detail.') = 0,
        version    : Arg.Switch('-V', help='Parse the VERSION resource.') = False,
        header     : Arg.Switch('-H', help='Parse base data from the PE header.') = False,
        exports    : Arg.Counts('-E', help='List all exported functions. Specify twice to include addresses.') = 0,
        imports    : Arg.Counts('-I', help='List all imported functions. Specify twice to include addresses.') = 0,
        tabular    : Arg.Switch('-t', help='Print information in a table rather than as JSON') = False,
        timeraw    : Arg.Switch('-r', help='Extract time stamps as numbers instead of human-readable format.') = False,
    ):
        if not custom and not any((debug, dotnet, signatures, timestamps, version, header)):
            debug = dotnet = signatures = timestamps = version = header = True
        super().__init__(
            debug=debug,
            dotnet=dotnet,
            signatures=signatures,
            timestamps=timestamps,
            version=version,
            header=header,
            imports=imports,
            exports=exports,
            timeraw=timeraw,
            tabular=tabular,
        )

    @classmethod
    def handles(self, data):
        return data[:2] == B'MZ'

    @classmethod
    def _ensure_string(cls, x):
        if not isinstance(x, str):
            x = repr(x) if not isinstance(x, bytes) else x.decode(cls.codec, 'backslashreplace')
        return x

    @classmethod
    def _parse_pedict(cls, bin):
        return dict((
            cls._ensure_string(key).replace(" ", ""),
            cls._ensure_string(val)
        ) for key, val in bin.items() if val)

    @classmethod
    def parse_signature(cls, data: bytearray) -> dict:
        """
        Extracts a JSON-serializable and human-readable dictionary with information about
        time stamp and code signing certificates that are attached to the input PE file.
        """
        from refinery.units.formats.pkcs7 import pkcs7

        try:
            signature = data | pkcs7 | json.loads
        except Exception as E:
            raise ValueError(F'PKCS7 parser failed with error: {E!s}')

        info = {}

        def _value(doc: dict, require_type=None):
            if require_type is not None:
                if doc.get('type', None) != require_type:
                    raise LookupError
            value = doc.get('value', None)
            value = [value] if value else doc.get('values', [])
            if not value:
                raise LookupError
            return value[0]

        def find_timestamps(entry) -> dict:
            if isinstance(entry, dict):
                try:
                    return {'Timestamp': _value(entry, 'signing_time')}
                except LookupError:
                    pass
                for value in entry.values():
                    result = find_timestamps(value)
                    if result is None:
                        continue
                    with suppress(KeyError):
                        result.setdefault('TimestampIssuer', entry['sid']['issuer']['common_name'])
                    return result
            elif isinstance(entry, list):
                for value in entry:
                    result = find_timestamps(value)
                    if result is None:
                        continue
                    return result

        timestamp_info = find_timestamps(signature)
        if timestamp_info is not None:
            info.update(timestamp_info)

        try:
            certificates = signature['content']['certificates']
        except KeyError:
            return info

        if len(certificates) == 1:
            main_certificate = certificates[0]
        else:
            certificates_with_extended_use = []
            main_certificate = None
            for certificate in certificates:
                with suppress(Exception):
                    crt = certificate['tbs_certificate']
                    ext = [e for e in crt['extensions'] if e['extn_id'] == 'extended_key_usage' and e['extn_value'] != ['time_stamping']]
                    key = [e for e in crt['extensions'] if e['extn_id'] == 'key_usage']
                    if ext:
                        certificates_with_extended_use.append(certificate)
                    if any('key_cert_sign' in e['extn_value'] for e in key):
                        continue
                    if any('code_signing' in e['extn_value'] for e in ext):
                        main_certificate = certificate
                        break
            if main_certificate is None and len(certificates_with_extended_use) == 1:
                main_certificate = certificates_with_extended_use[0]
        if main_certificate:
            crt = main_certificate['tbs_certificate']
            serial = crt['serial_number']
            if isinstance(serial, int):
                serial = F'{serial:x}'
            if len(serial) % 2 != 0:
                serial = F'0{serial}'
            assert bytes.fromhex(serial) in data
            subject = crt['subject']
            location = [subject.get(t, '') for t in ('locality_name', 'state_or_province_name', 'country_name')]
            info.update(Subject=subject['common_name'])
            if any(location):
                info.update(SubjectLocation=', '.join(filter(None, location)))
            for signer_info in signature['content'].get('signer_infos', ()):
                try:
                    if signer_info['sid']['serial_number'] != crt['serial_number']:
                        continue
                    for attr in signer_info['signed_attrs']:
                        if attr['type'] == 'authenticode_info':
                            auth = _value(attr)
                            info.update(ProgramName=auth['programName'])
                            info.update(MoreInfo=auth['moreInfo'])
                except KeyError:
                    continue
            try:
                valid_from = crt['validity']['not_before']
                valid_until = crt['validity']['not_after']
            except KeyError:
                pass
            else:
                info.update(ValidFrom=valid_from, ValidUntil=valid_until)
            info.update(
                Issuer=crt['issuer']['common_name'], Fingerprint=main_certificate['fingerprint'], Serial=serial)
            return info
        return info

    def _pe_characteristics(self, pe: lief.PE.Binary):
        characteristics = {F'IMAGE_FILE_{flag.name}' for flag in lief.PE.Header.CHARACTERISTICS
            if pe.header.characteristics & flag.value}
        if pe.header.characteristics & 0x40:
            # TODO: Missing from LIEF
            characteristics.add('IMAGE_FILE_16BIT_MACHINE')
        return characteristics

    def _pe_address_width(self, pe: lief.PE.Binary, default=16) -> int:
        # TODO: missing from LIEF
        IMAGE_FILE_16BIT_MACHINE = 0x40
        if pe.header.characteristics & IMAGE_FILE_16BIT_MACHINE:
            return 4
        elif pe.header.machine == lief.PE.Header.MACHINE_TYPES.I386:
            return 8
        elif pe.header.machine in (
            lief.PE.Header.MACHINE_TYPES.AMD64,
            lief.PE.Header.MACHINE_TYPES.IA64,
        ):
            return 16
        else:
            return default

    def _vint(self, pe: lief.PE.Binary, value: int):
        if not self.args.tabular:
            return value
        aw = self._pe_address_width(pe)
        return F'0x{value:0{aw}X}'

    def parse_version(self, pe: lief.PE.Binary, data=None) -> dict:
        """
        Extracts a JSON-serializable and human-readable dictionary with information about
        the version resource of an input PE file, if available.
        """
        version_info = {}
        if not pe.resources_manager.has_version:
            return None
        version = pe.resources_manager.version

        if info := version.string_file_info:
            for lng in info.langcode_items:
                version_info.update({
                    k.replace(' ', ''): _STRING(v) for k, v in lng.items.items()
                })
                version_info.update(
                    CodePage=lng.code_page.name,
                    LangID=self._vint(pe, lng.lang << 0x10 | lng.sublang),
                    Language=LCID.get(lng.lang, 'Language Neutral'),
                    Charset=self._CHARSET.get(lng.sublang, 'Unknown Charset'),
                )

        def _to_version_string(hi: int, lo: int):
            a = hi >> 0x10
            b = hi & 0xFFFF
            c = lo >> 0x10
            d = lo & 0xFFFF
            return F'{a}.{b}.{c}.{d}'

        # TODO: Missing: Version.CompanyName
        # TODO: Missing: Version.FileDescription
        # TODO: Missing: Version.LegalCopyright
        # TODO: Missing: Version.ProductName

        if info := version.fixed_file_info:
            version_info.update(
                OSName=info.file_os.name,
                FileType=info.file_type.name,
            )
            if (s := info.file_subtype).value:
                version_info.update(FileSubType=s)
            if t := info.file_date_MS << 32 | info.file_date_LS:
                version_info.update(Timestamp=_FILETIME(t))
            version_info.update(
                ProductVersion=_to_version_string(info.product_version_MS, info.product_version_LS),
                FileVersion=_to_version_string(info.file_version_MS, info.file_version_LS),
            )

        if info := version.var_file_info:
            ...

        return version_info or None

    def parse_exports(self, pe: lief.PE.Binary, data=None, include_addresses=False) -> list:
        base = pe.optional_header.imagebase
        info = []
        if not pe.has_exports:
            return None
        for k, exp in enumerate(pe.get_export().entries):
            name = exp.demangled_name
            if not name:
                name = exp.name
            if not name:
                name = F'@{k}'
            if not isinstance(name, str):
                name = name.decode('latin1')
            item = {
                'Name': name, 'Address': self._vint(pe, exp.address + base)
            } if include_addresses else name
            info.append(item)
        return info

    def parse_imports(self, pe: lief.PE.Binary, data=None, include_addresses=False) -> list:
        info = {}
        for idd in itertools.chain(pe.imports, pe.delay_imports):
            dll = _STRING(idd.name)
            if dll.lower().endswith('.dll'):
                dll = dll[:~3]
            imports: list[str] = info.setdefault(dll, [])
            for imp in idd.entries:
                name = _STRING(imp.name) or F'@{imp.ordinal}'
                imports.append(dict(
                    Name=name, Address=self._vint(pe, imp.value)
                ) if include_addresses else name)
        return info

    def parse_header(self, pe: lief.PE.Binary, data=None) -> dict:
        major = pe.optional_header.major_operating_system_version
        minor = pe.optional_header.minor_operating_system_version
        version = self._WINVER.get(major, {0: 'Unknown'})

        try:
            MinimumOS = version[minor]
        except LookupError:
            MinimumOS = version[0]
        header_information = {
            'Machine': pe.header.machine.name,
            'Subsystem': pe.optional_header.subsystem.name,
            'MinimumOS': MinimumOS,
        }
        if pe.has_exports:
            export_name = _STRING(pe.get_export().name)
            if export_name.isprintable():
                header_information['ExportName'] = export_name

        if pe.has_rich_header:
            rich = []
            if self.args.tabular:
                cw = max(len(F'{entry.count:d}') for entry in pe.rich_header.entries)
            for entry in pe.rich_header.entries:
                idv = entry.id
                count = entry.count
                info = get_rich_info(idv)
                if not info:
                    continue
                pid = info.pid.upper()
                if self.args.tabular:
                    short_pid = get_rich_short_pid(pid)
                    rich.append(F'[{idv:08x}] {count:>0{cw}d} {short_pid!s} {info.ver}')
                else:
                    rich.append({
                        'Counter': count,
                        'Encoded': F'{idv:08x}',
                        'Library': pid,
                        'Product': info.ver,
                    })
            header_information['RICH'] = rich

        characteristics = self._pe_characteristics(pe)
        for typespec, flag in {
            'EXE': 'IMAGE_FILE_EXECUTABLE_IMAGE',
            'DLL': 'IMAGE_FILE_DLL',
            'SYS': 'IMAGE_FILE_SYSTEM'
        }.items():
            if flag in characteristics:
                header_information['Type'] = typespec

        base = pe.optional_header.imagebase
        header_information['ImageBase'] = self._vint(pe, base)
        header_information['ImageSize'] = self._vint(pe, pe.optional_header.sizeof_image)
        header_information['ComputedSize'] = get_pe_size(pe)
        header_information['Bits'] = 4 * self._pe_address_width(pe, 16)
        header_information['EntryPoint'] = self._vint(pe, pe.optional_header.addressof_entrypoint + base)
        return header_information

    def parse_time_stamps(self, pe: lief.PE.Binary, raw_time_stamps: bool, more_detail: bool) -> dict:
        """
        Extracts time stamps from the PE header (link time), as well as from the imports,
        exports, debug, and resource directory. The resource time stamp is also parsed as
        a DOS time stamp and returned as the "Delphi" time stamp.
        """
        def _id(x): return x
        dt = _id if raw_time_stamps else date_from_timestamp
        info = {}

        with suppress(AttributeError):
            info.update(Linker=dt(pe.header.time_date_stamps))

        import_timestamps = {}
        for entry in pe.imports:
            ts = entry.timedatestamp
            if ts == 0 or ts == 0xFFFFFFFF:
                continue
            import_timestamps[_STRING(entry.name, True)] = dt(ts)

        symbol_timestamps = {}
        for entry in pe.delay_imports:
            ts = entry.timestamp
            if ts == 0 or ts == 0xFFFFFFFF:
                continue
            symbol_timestamps[_STRING(entry.name, True)] = dt(ts)

        for key, impts in [
            ('Import', import_timestamps),
            ('Symbol', symbol_timestamps),
        ]:
            if not impts:
                continue
            if not more_detail:
                dmin = min(impts.values())
                dmax = max(impts.values())
                small_delta = 2 * 60 * 60
                if not raw_time_stamps:
                    small_delta = timedelta(seconds=small_delta)
                if dmax - dmin < small_delta:
                    impts = dmin
            info[key] = impts

        if pe.has_exports and (ts := pe.get_export().timestamp):
            info.update(Export=dt(ts))

        if pe.has_resources and pe.resources.is_directory:
            rsrc: lief.PE.ResourceDirectory = pe.resources
            if res_timestamp := rsrc.time_date_stamp:
                with suppress(ValueError):
                    from refinery.units.misc.datefix import datefix
                    dos = datefix.dostime(res_timestamp)
                    info.update(Delphi=dos)
                    info.update(RsrcTS=dt(res_timestamp))

        def norm(value):
            if isinstance(value, list):
                return [norm(v) for v in value]
            if isinstance(value, dict):
                return {k: norm(v) for k, v in value.items()}
            if isinstance(value, int):
                return value
            return str(value)

        return {key: norm(value) for key, value in info.items()}

    def parse_dotnet(self, pe: lief.PE.Binary, data):
        """
        Extracts a JSON-serializable and human-readable dictionary with information about
        the .NET metadata of an input PE file.
        """
        header = DotNetHeader(data, pe)
        tables = header.meta.Streams.Tables
        info = dict(
            RuntimeVersion=F'{header.head.MajorRuntimeVersion}.{header.head.MinorRuntimeVersion}',
            Version=F'{header.meta.MajorVersion}.{header.meta.MinorVersion}',
            VersionString=header.meta.VersionString
        )

        info['Flags'] = [name for name, check in header.head.KnownFlags.items() if check]

        if len(tables.Assembly) == 1:
            assembly = tables.Assembly[0]
            info.update(
                AssemblyName=assembly.Name,
                Release='{}.{}.{}.{}'.format(
                    assembly.MajorVersion,
                    assembly.MinorVersion,
                    assembly.BuildNumber,
                    assembly.RevisionNumber
                )
            )

        try:
            entry = self._vint(pe, header.head.EntryPointToken + pe.optional_header.imagebase)
            info.update(EntryPoint=entry)
        except AttributeError:
            pass

        if len(tables.Module) == 1:
            module = tables.Module[0]
            info.update(ModuleName=module.Name)

        return info

    def parse_debug(self, pe: lief.PE.Binary, data=None):
        result = []
        if not pe.has_debug:
            return None
        for entry in pe.debug:
            if entry.type != lief.PE.Debug.TYPES.CODEVIEW:
                continue
            try:
                entry: lief.PE.CodeViewPDB
                result.append(dict(
                    PdbPath=_STRING(entry.filename),
                    PdbGUID=entry.guid,
                    PdbAge=entry.age,
                ))
            except AttributeError:
                continue
        if len(result) == 1:
            result = result[0]
        return result

    def process(self, data):
        result = {}

        pe = lief.load_pe(
            data,
            parse_exports=self.args.exports,
            parse_imports=self.args.imports,
            parse_rsrc=self.args.version,
            parse_reloc=False,
            parse_signature=self.args.timestamps or self.args.signatures,
        )

        if pe is None:
            raise ValueError('Input not recognized as a PE file.')

        for switch, resolver, name in [
            (self.args.debug,   self.parse_debug,    'Debug'),    # noqa
            (self.args.dotnet,  self.parse_dotnet,   'DotNet'),   # noqa
            (self.args.header,  self.parse_header,   'Header'),   # noqa
            (self.args.version, self.parse_version,  'Version'),  # noqa
            (self.args.imports, self.parse_imports,  'Imports'),  # noqa
            (self.args.exports, self.parse_exports,  'Exports'),  # noqa
        ]:
            if not switch:
                continue
            self.log_debug(F'parsing: {name}')
            args = pe, data
            if switch > 1:
                args = *args, True
            try:
                info = resolver(*args)
            except Exception as E:
                self.log_info(F'failed to obtain {name}: {E!s}')
                continue
            if info:
                result[name] = info

        signature = {}

        if self.args.timestamps or self.args.signatures:
            with suppress(Exception):
                from refinery.units.formats.pe.pesig import pesig
                signature = self.parse_signature(next(data | pesig))

        if signature:
            try:
                verification = pe.verify_signature()
            except Exception:
                pass
            else:
                from lief.PE import Signature
                if verification == Signature.VERIFICATION_FLAGS.OK:
                    signature['Match'] = True
                else:
                    signature['Flags'] = [
                        vf.name for vf in Signature.VERIFICATION_FLAGS if vf & verification == vf]
                    signature['Match'] = False

        if self.args.timestamps:
            ts = self.parse_time_stamps(pe, self.args.timeraw, self.args.timestamps > 1)
            with suppress(KeyError):
                ts.update(Signed=signature['Timestamp'])
            result.update(TimeStamp=ts)

        if signature and self.args.signatures:
            result['Signature'] = signature

        if result:
            yield from ppjson(tabular=self.args.tabular)._pretty_output(result, indent=4, ensure_ascii=False)

    _CHARSET = {
        0x0000: '7-bit ASCII',
        0x03A4: 'Japan (Shift ? JIS X-0208)',
        0x03B5: 'Korea (Shift ? KSC 5601)',
        0x03B6: 'Taiwan (Big5)',
        0x04B0: 'Unicode',
        0x04E2: 'Latin-2 (Eastern European)',
        0x04E3: 'Cyrillic',
        0x04E4: 'Multilingual',
        0x04E5: 'Greek',
        0x04E6: 'Turkish',
        0x04E7: 'Hebrew',
        0x04E8: 'Arabic',
    }

    _WINVER = {
        3: {
            0x00: 'Windows NT 3',
            0x0A: 'Windows NT 3.1',
            0x32: 'Windows NT 3.5',
            0x33: 'Windows NT 3.51',
        },
        4: {
            0x00: 'Windows 95',
            0x0A: 'Windows 98',
        },
        5: {
            0x00: 'Windows 2000',
            0x5A: 'Windows Me',
            0x01: 'Windows XP',
            0x02: 'Windows Server 2003',
        },
        6: {
            0x00: 'Windows Vista',
            0x01: 'Windows 7',
            0x02: 'Windows 8',
            0x03: 'Windows 8.1',
        },
        10: {
            0x00: 'Windows 10',
        }
    }
