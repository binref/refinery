from __future__ import annotations

import codecs
import itertools
import json

from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

from refinery.lib import lief
from refinery.lib.dotnet.header import DotNetHeader
from refinery.lib.id import is_likely_pe
from refinery.lib.lcid import LCID
from refinery.lib.resources import datapath
from refinery.lib.tools import NoLoggingProxy, date_from_timestamp, unwrap
from refinery.lib.types import Param
from refinery.units import Arg, Unit
from refinery.units.formats.pe import get_pe_size
from refinery.units.sinks.ppjson import ppjson


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


with datapath('rich.json').open('r') as stream:
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
        self,
        custom: Param[bool, Arg('-c', '--custom',
            help='Unless enabled, all default categories will be extracted.')] = False,
        debug: Param[bool, Arg.Switch('-D',
            help='Parse the PDB path from the debug directory.')] = False,
        dotnet: Param[bool, Arg.Switch('-N',
            help='Parse the .NET header.')] = False,
        signatures: Param[bool, Arg.Switch('-S',
            help='Parse digital signatures.')] = False,
        timestamps: Param[int, Arg.Counts('-T',
            help='Extract time stamps. Specify twice for more detail.')] = 0,
        version: Param[bool, Arg.Switch('-V',
            help='Parse the VERSION resource.')] = False,
        header: Param[bool, Arg.Switch('-H',
            help='Parse base data from the PE header.')] = False,
        exports: Param[int, Arg.Counts('-E',
            help='List all exported functions. Specify twice to include addresses.')] = 0,
        imports: Param[int, Arg.Counts('-I',
            help='List all imported functions. Specify twice to include addresses.')] = 0,
        tabular: Param[bool, Arg.Switch('-t',
            help='Print information in a table rather than as JSON')] = False,
        timeraw: Param[bool, Arg.Switch('-r',
            help='Extract time stamps as numbers instead of human-readable format.')] = False,
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
    def handles(cls, data):
        return is_likely_pe(data)

    @classmethod
    def _ensure_string(cls, x):
        if not isinstance(x, str):
            x = repr(x) if not isinstance(x, bytes) else x.decode(cls.codec, 'backslashreplace')
        return x

    @classmethod
    def _parse_pedict(cls, bin: dict):
        return {
            cls._ensure_string(key).replace(" ", ""): cls._ensure_string(val)
            for key, val in bin.items() if val}

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

        def find_timestamps(entry) -> dict | None:
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
            signer_infos = signature['content']['signer_infos']
        except KeyError:
            return info

        try:
            signer_serials = {info['sid']['serial_number']: info for info in signer_infos}
        except KeyError:
            return info

        signer_certificates = []

        for certificate in certificates:
            with suppress(Exception):
                crt = certificate['tbs_certificate']
                serial = crt['serial_number']
                signer = signer_serials[serial]

                if not isinstance(serial, int):
                    try:
                        serial = int(serial, 0)
                    except ValueError:
                        serial = int(serial, 16)

                length, rest = divmod(serial.bit_length(), 8)
                if rest > 0:
                    length += 1
                serial_bytes = serial.to_bytes(length, 'big', signed=(serial < 0))
                if serial_bytes not in data:
                    continue

                serial = serial_bytes.hex().lower()

                subject: dict = crt['subject']
                location = [subject.get(t, '') for t in (
                    'locality_name', 'state_or_province_name', 'country_name')]
                cert_info = {}
                cert_info.update(Subject=subject['common_name'])
                with suppress(KeyError):
                    cert_info.update(SubjectEmail=subject['email_address'])
                if any(location):
                    cert_info.update(SubjectLocation=', '.join(filter(None, location)))
                with suppress(KeyError):
                    cert_info.update(SubjectOrg=subject['organization_name'])
                for attr in signer['signed_attrs']:
                    if attr['type'] == 'authenticode_info':
                        auth = _value(attr)
                        cert_info.update(ProgramName=auth['programName'])
                        cert_info.update(MoreInfo=auth['moreInfo'])
                try:
                    valid_since = crt['validity']['not_before']
                    valid_until = crt['validity']['not_after']
                except KeyError:
                    pass
                else:
                    cert_info.update(ValidSince=valid_since, ValidUntil=valid_until)
                cert_info.update(Serial=serial)
                with suppress(KeyError):
                    cert_info.update(Issuer=crt['issuer']['common_name'])
                with suppress(KeyError):
                    cert_info.update(IssuerOrg=crt['issuer']['organization_name'])
                with suppress(KeyError):
                    cert_info.update(Fingerprint=certificate['fingerprint'])
                signer_certificates.append(cert_info)

        if len(signer_certificates) == 1:
            info.update(signer_certificates[0])
        if len(signer_certificates) >= 2:
            info['Signer'] = signer_certificates
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

    def parse_version(self, pe: lief.PE.Binary, data=None) -> dict | None:
        """
        Extracts a JSON-serializable and human-readable dictionary with information about
        the version resource of an input PE file, if available.
        """
        version_info = {}
        rsrc = unwrap(pe.resources_manager)
        if isinstance(rsrc, lief.lib.lief_errors) or not rsrc.has_version:
            return None
        version = rsrc.version[0]

        if info := version.string_file_info:
            for child in info.children:
                entries = {e.key: e.value for e in child.entries}
                version_info.update({
                    k.replace(' ', ''): _STRING(v) for k, v in entries.items()
                })

        if rsrc.has_icons:
            icon = next(iter(rsrc.icons))
            version_info.update(
                LangID=self._vint(pe, icon.lang << 0x10 | icon.sublang),
                Language=LCID.get(icon.lang, 'Language Neutral'),
                Charset=self._CHARSET.get(icon.sublang, 'Unknown Charset'),
            )

        def _code_pages(d: lief.PE.ResourceDirectory | lief.PE.ResourceData):
            if isinstance(d, lief.PE.ResourceData):
                yield d.code_page
                return
            for child in d.childs:
                yield from _code_pages(child)

        code_pages: set[int] = set()

        for t in rsrc.types:
            code_pages.update(_code_pages(rsrc.get_node_type(t)))

        if len(code_pages) == 1:
            cp = next(iter(code_pages))
            version_info.update(CodePage=cp)

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

        if info := version.file_info:
            for name, val, T in (
                ('FileType', info.file_type, info.FILE_TYPE),
                ('OSName', info.file_os, info.VERSION_OS),
                ('FileSubType', info.file_subtype, info.FILE_TYPE_DETAILS),
            ):
                if not val:
                    continue
                try:
                    version_info[name] = T(val).name
                except Exception:
                    continue
            if t := info.file_date_ms << 32 | info.file_date_ls:
                version_info.update(Timestamp=_FILETIME(t))
            version_info.update(
                ProductVersion=_to_version_string(info.product_version_ms, info.product_version_ls),
                FileVersion=_to_version_string(info.file_version_ms, info.file_version_ls),
            )

        if info := version.var_file_info:
            ...

        return version_info or None

    def parse_exports(self, pe: lief.PE.Binary, data=None, include_addresses=False) -> list | None:
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
                name = codecs.decode(name, 'latin1')
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
        header_information: dict[str, int | str | list] = {
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
                idv = entry.build_id | (entry.id << 0x10)
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
        dt = (lambda x: x) if raw_time_stamps else date_from_timestamp
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
        info: dict[str, str | int | list[str]] = dict(
            RuntimeVersion=F'{header.head.MajorRuntimeVersion}.{header.head.MinorRuntimeVersion}',
            Version=F'{header.meta.MajorVersion}.{header.meta.MinorVersion}',
            VersionString=header.meta.VersionString
        )

        info['Flags'] = [repr(flag) for flag in header.head.KnownFlags]

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
            parse_exports=True,
            parse_imports=self.args.imports,
            parse_rsrc=self.args.version,
            parse_reloc=False,
            parse_signature=self.args.timestamps or self.args.signatures,
        )

        if pe is None:
            raise ValueError('Input not recognized as a PE file.')

        pe = NoLoggingProxy(pe)

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
                    signature['IsValid'] = True
                else:
                    signature['Flags'] = [
                        vf.name for vf in Signature.VERIFICATION_FLAGS if vf & verification]
                    signature['IsValid'] = False

        if self.args.timestamps:
            ts = self.parse_time_stamps(pe, self.args.timeraw, self.args.timestamps > 1)
            with suppress(KeyError):
                ts.update(Signed=signature['Timestamp'])
            result.update(TimeStamp=ts)

        if signature and self.args.signatures:
            result['Signature'] = signature

        if result:
            yield from ppjson(tabular=self.args.tabular)._pretty_output(result)

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
