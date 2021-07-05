#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

from contextlib import suppress
from datetime import datetime, timezone
from dataclasses import dataclass
from enum import Enum

from pefile import (
    DEBUG_TYPE,
    DIRECTORY_ENTRY,
    image_characteristics,
    MACHINE_TYPE,
    SUBSYSTEM_TYPE,
    PE,
)

from ....lib.dotnet.header import DotNetHeader
from ... import arg, Unit
from ...sinks.ppjson import ppjson


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
    type: VIT
    description: str
    interpolated: bool = False

    def __str__(self):
        suffix = ' (*)' if self.interpolated else ''
        return F'[{self.type.tag}] {self.description}{suffix}'

    def __bool__(self):
        return self.type is not VIT.ERR


def guess_version(vid: int) -> VersionInfo:
    vtype = {
        0x0104: VIT.OBJ,
        0x0103: VIT.ASM,
        0x0105: VIT.CPP,
        0x00ff: VIT.RES,
        0x0102: VIT.LNK,
        0x0101: VIT.IMP,
        0x0100: VIT.EXP,
    }.get(vid >> 16, VIT.ERR)
    vmain = {
        0x06: 'VS1997 / VS1998',
        0x0b: 'VS2003 (.NET)',
        0x0c: 'VS2003 (.NET)',
        0x0f: 'Windows Server 2003 SP1 DDK',
        0x17: 'VS2003 (.NET) SP1',
        0x1c: 'VS97 (5.0) SP3 link 5.10.7303',
        0x1f: 'VS98 (6.0)',
        0x20: 'VC++ 6.0 SP5 imp/exp',
        0x23: 'VC++ 6.0 SP5',
        0x24: 'VS2002 (.NET)',
        0x26: 'VS98 (6.0) SP6',
        0x50: 'VS2008 / VS2010',
        0x51: 'VS2013 RC [12.0]',
        0x52: 'VS2008 / VS2010 / VS2013',
        0x59: 'VS2015 [14.0]',
        0x5b: 'VS2015 UPD1',
        0x5d: 'VS2015 UPD2',
        0x5e: 'VS2015 UPD3',
        0x61: 'VS2017 v15.0',
        0x63: 'VS2017 v15',
        0x64: 'VS2017 v15',
        0x66: 'VS2017 v15',
        0x67: 'VS2017 v15',
        0x68: 'VS2017 v15',
        0x69: 'VS2017 v15',
        0x6b: 'VS2019 v16',
        0x6c: 'VS2019 v16',
        0x6d: 'VS2019 v16',
        0x6e: 'VS2019 v16',
        0x6f: 'VS2019 v16',
        0x70: 'VS2019 v16',
        0x71: 'VS2019 v16',
        0x72: 'VS2019 v16',
        0x74: 'VS2019 v16',
        0x76: 'VS2010 / VS2013',
        0x77: 'VS2013',
        0x78: 'VS2008 / VS2013',
        0x79: 'VS2013',
        0x9d: 'VS2010',
        0x9e: 'VS2005 / VS2013',
        0xc4: 'VS2005',
        0xc6: 'VS2005 / VS2012',
        0xc7: 'VS2012',
        0xeb: 'VS2012',
        0xec: 'VS2012',
        0xee: 'VS2012',
    }.get(vid >> 8 & 0xFF, 'Unknown Product')
    return VersionInfo(vtype, vmain, True)


class pemeta(Unit):
    """
    Extract metadata from PE files. By default, all information except for imports and exports are
    extracted.
    """
    def __init__(
        self, all : arg('-c', '--custom',
            help='Unless enabled, all default categories will be extracted.') = True,
        debug      : arg('-D', help='Parse the PDB path from the debug directory.') = False,
        dotnet     : arg('-N', help='Parse the .NET header.') = False,
        signatures : arg('-S', help='Parse digital signatures.') = False,
        timestamps : arg('-T', help='Extract time stamps.') = False,
        version    : arg('-V', help='Parse the VERSION resource.') = False,
        header     : arg('-H', help='Parse data from the PE header.') = False,
        exports    : arg('-E', help='List all exported functions.') = False,
        imports    : arg('-I', help='List all imported functions.') = False,
        tabular    : arg('-t', help='Print information in a table rather than as JSON') = False,
        timeraw    : arg('-r', help='Extract time stamps as numbers instead of human-readable format.') = False,
    ):
        super().__init__(
            debug=all or debug,
            dotnet=all or dotnet,
            signatures=all or signatures,
            timestamps=all or timestamps,
            version=all or version,
            header=all or header,
            imports=imports,
            exports=exports,
            timeraw=timeraw,
            tabular=tabular,
        )

    @classmethod
    def _ensure_string(cls, x):
        if not isinstance(x, str):
            x = repr(x) if not isinstance(x, bytes) else x.decode(cls.codec, 'backslashreplace')
        return x

    @classmethod
    def _parse_pedict(cls, bin):
        return dict((
            cls._ensure_string(key),
            cls._ensure_string(val)
        ) for key, val in bin.items() if val)

    @classmethod
    def parse_signature(cls, data: bytearray) -> dict:
        """
        Extracts a JSON-serializable and human readable dictionary with information about
        time stamp and code signing certificates that are attached to the input PE file.
        """
        from refinery.units.formats.pkcs7 import pkcs7
        from refinery.units.formats.pe.pesig import pesig

        try:
            signature = data | pesig | pkcs7 | json.loads
        except Exception as E:
            raise ValueError(F'PKCS7 parser failed with error: {E!s}')

        info = {}

        def find_timestamps(entry):
            if isinstance(entry, dict):
                if set(entry.keys()) == {'type', 'value'}:
                    if entry['type'] == 'signing_time':
                        return {'Timestamp': entry['value']}
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
            main_certificate = certificates[0]['tbs_certificate']
        else:
            certificates_with_extended_use = []
            main_certificate = None
            for certificate in certificates:
                with suppress(Exception):
                    crt = certificate['tbs_certificate']
                    ext = [e for e in crt['extensions'] if e['extn_id'] == 'extended_key_usage' and e['extn_value'] != ['time_stamping']]
                    key = [e for e in crt['extensions'] if e['extn_id'] == 'key_usage']
                    if ext:
                        certificates_with_extended_use.append(crt)
                    if any('key_cert_sign' in e['extn_value'] for e in key):
                        continue
                    if any('code_signing' in e['extn_value'] for e in ext):
                        main_certificate = crt
                        break
            if main_certificate is None and len(certificates_with_extended_use) == 1:
                main_certificate = certificates_with_extended_use[0]
        if main_certificate:
            serial = main_certificate['serial_number']
            if not isinstance(serial, int):
                serial = int(serial, 0)
            serial = F'{serial:x}'
            if len(serial) % 2:
                serial = '0' + serial
            subject = main_certificate['subject']
            location = [subject.get(t, '') for t in ('locality_name', 'state_or_province_name', 'country_name')]
            info.update(Subject=subject['common_name'])
            if any(location):
                info.update(SubjectLocation=', '.join(filter(None, location)))
            info.update(Issuer=main_certificate['issuer']['common_name'], Serial=serial)
            return info
        return info

    @classmethod
    def parse_version(cls, pe: PE, data=None) -> dict:
        """
        Extracts a JSON-serializable and human readable dictionary with information about
        the version resource of an input PE file, if available.
        """
        pe.parse_data_directories(directories=[DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
        for FileInfo in pe.FileInfo:
            for FileInfoEntry in FileInfo:
                with suppress(AttributeError):
                    for StringTableEntry in FileInfoEntry.StringTable:
                        StringTableEntryParsed = cls._parse_pedict(StringTableEntry.entries)
                        with suppress(AttributeError):
                            LangID = StringTableEntry.entries.get('LangID', None) or StringTableEntry.LangID
                            LangID = int(LangID, 0x10) if not isinstance(LangID, int) else LangID
                            LangHi = LangID >> 0x10
                            LangLo = LangID & 0xFFFF
                            Language = cls._LCID.get(LangHi, 'Language Neutral')
                            Charset = cls._CHARSET.get(LangLo, 'Unknown Charset')
                            StringTableEntryParsed.update(
                                LangID=F'{LangID:08X}',
                                Charset=Charset,
                                Language=Language
                            )
                        return StringTableEntryParsed

    @classmethod
    def parse_exports(cls, pe: PE, data=None) -> list:
        pe.parse_data_directories(directories=[DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        info = []
        for k, exp in enumerate(pe.DIRECTORY_ENTRY_EXPORT.symbols):
            if not exp.name:
                info.append(F'@{k}')
            else:
                info.append(exp.name.decode('ascii'))
        return info

    @classmethod
    def parse_imports(cls, pe: PE, data=None) -> list:
        pe.parse_data_directories(directories=[DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        info = {}
        for idd in pe.DIRECTORY_ENTRY_IMPORT:
            dll = idd.dll.decode('ascii')
            if dll.lower().endswith('.dll'):
                dll = dll[:-4]
            imports = info.setdefault(dll, [])
            for imp in idd.imports:
                imports.append(imp.name.decode('ascii'))
        return info

    def parse_header(cls, pe: PE, data=None) -> dict:
        def format_macro_name(name: str, prefix, convert=True):
            name = name.split('_')[prefix:]
            if convert:
                for k, part in enumerate(name):
                    name[k] = part.upper() if len(part) <= 3 else part.capitalize()
            return ' '.join(name)

        major = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        minor = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        version = cls._WINVER.get(major, {0: 'Unknown'})

        try:
            MinimumOS = version[minor]
        except LookupError:
            MinimumOS = version[0]
        header_information = {
            'Machine': format_macro_name(MACHINE_TYPE[pe.FILE_HEADER.Machine], 3, False),
            'Subsystem': format_macro_name(SUBSYSTEM_TYPE[pe.OPTIONAL_HEADER.Subsystem], 2),
            'MinimumOS': MinimumOS,
        }

        rich_header = pe.parse_rich_header()
        rich = []
        if rich_header:
            it = rich_header.get('values', [])
            for idv in it[0::2]:
                info = cls._RICH_HEADER.get(idv, None)
                if info is None:
                    info = guess_version(idv)
                if not info:
                    continue
                rich.append(str(info))
            header_information['RICH'] = rich

        characteristics = [
            name for name, mask in image_characteristics
            if pe.FILE_HEADER.Characteristics & mask
        ]
        for typespec, flag in {
            'EXE': 'IMAGE_FILE_EXECUTABLE_IMAGE',
            'DLL': 'IMAGE_FILE_DLL',
            'SYS': 'IMAGE_FILE_SYSTEM'
        }.items():
            if flag in characteristics:
                header_information['Type'] = typespec
        address_width = None
        if 'IMAGE_FILE_16BIT_MACHINE' in characteristics:
            address_width = 4
        elif pe.FILE_HEADER.Machine == MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            address_width = 8
        elif pe.FILE_HEADER.Machine == MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            address_width = 16
        if address_width:
            header_information['Bits'] = 4 * address_width
        else:
            address_width = 16
        header_information['ImageBase'] = F'0x{pe.OPTIONAL_HEADER.ImageBase:0{address_width}}'
        return header_information

    @classmethod
    def parse_time_stamps(cls, pe: PE, raw_time_stamps: bool) -> dict:
        """
        Extracts time stamps from the PE header (link time), as well as from the imports,
        exports, debug, and resource directory. The resource time stamp is also parsed as
        a DOS time stamp and returned as the "Delphi" time stamp.
        """
        if raw_time_stamps:
            def dt(ts): return ts
        else:
            def dt(ts):
                # parse as UTC but then forget time zone information
                return datetime.fromtimestamp(
                    ts,
                    tz=timezone.utc
                ).replace(tzinfo=None)

        pe.parse_data_directories(directories=[
            DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
            DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
            DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG'],
            DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']
        ])

        info = {}

        with suppress(AttributeError):
            info.update(Linker=dt(pe.FILE_HEADER.TimeDateStamp))

        with suppress(AttributeError):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                info.update(Import=dt(entry.TimeDateStamp()))

        with suppress(AttributeError):
            for entry in pe.DIRECTORY_ENTRY_DEBUG:
                info.update(DbgDir=dt(entry.struct.TimeDateStamp))

        with suppress(AttributeError):
            Export = pe.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp
            if Export: info.update(Export=dt(Export))

        with suppress(AttributeError):
            res_timestamp = pe.DIRECTORY_ENTRY_RESOURCE.struct.TimeDateStamp
            if res_timestamp:
                with suppress(ValueError):
                    from ...misc.datefix import datefix
                    dos = datefix.dostime(res_timestamp)
                    info.update(Delphi=dos)
                    info.update(RsrcTS=dt(res_timestamp))

        def norm(value):
            if isinstance(value, int):
                return value
            return str(value)

        return {key: norm(value) for key, value in info.items()}

    @classmethod
    def parse_dotnet(cls, pe: PE, data):
        """
        Extracts a JSON-serializable and human readable dictionary with information about
        the .NET metadata of an input PE file.
        """
        header = DotNetHeader(data, pe=pe)
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
            entry = header.head.EntryPointToken + pe.OPTIONAL_HEADER.ImageBase
            info.update(EntryPoint=F'0x{entry:08X}')
        except AttributeError:
            pass

        if len(tables.Module) == 1:
            module = tables.Module[0]
            info.update(ModuleName=module.Name)

        return info

    @classmethod
    def parse_debug(cls, pe: PE, data=None):
        result = {}
        pe.parse_data_directories(directories=[
            DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']])
        for dbg in pe.DIRECTORY_ENTRY_DEBUG:
            if DEBUG_TYPE.get(dbg.struct.Type, None) != 'IMAGE_DEBUG_TYPE_CODEVIEW':
                continue
            with suppress(Exception):
                pdb = dbg.entry.PdbFileName
                if 0 in pdb:
                    pdb = pdb[:pdb.index(0)]
                result.update(
                    PdbPath=pdb.decode(cls.codec),
                    PdbAge=dbg.entry.Age
                )
        return result

    def process(self, data):
        result = {}
        pe = PE(data=data, fast_load=True)

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
            try:
                info = resolver(pe, data)
            except Exception as E:
                self.log_info(F'failed to obtain {name}: {E!s}')
                continue
            if info:
                result[name] = info

        signature = {}

        if self.args.timestamps or self.args.signatures:
            with suppress(Exception):
                signature = self.parse_signature(data)

        if self.args.timestamps:
            ts = self.parse_time_stamps(pe, self.args.timeraw)
            with suppress(KeyError):
                ts.update(Signed=signature['Timestamp'])
            result.update(TimeStamp=ts)

        if signature and self.args.signatures:
            result['Signature'] = signature

        if result:
            yield from ppjson(tabular=self.args.tabular)._pretty_output(result, indent=4, ensure_ascii=False)

    _LCID = {
        0x0436: 'Afrikaans-South Africa',
        0x041c: 'Albanian-Albania',
        0x045e: 'Amharic-Ethiopia',
        0x0401: 'Arabic (Saudi Arabia)',
        0x1401: 'Arabic (Algeria)',
        0x3c01: 'Arabic (Bahrain)',
        0x0c01: 'Arabic (Egypt)',
        0x0801: 'Arabic (Iraq)',
        0x2c01: 'Arabic (Jordan)',
        0x3401: 'Arabic (Kuwait)',
        0x3001: 'Arabic (Lebanon)',
        0x1001: 'Arabic (Libya)',
        0x1801: 'Arabic (Morocco)',
        0x2001: 'Arabic (Oman)',
        0x4001: 'Arabic (Qatar)',
        0x2801: 'Arabic (Syria)',
        0x1c01: 'Arabic (Tunisia)',
        0x3801: 'Arabic (U.A.E.)',
        0x2401: 'Arabic (Yemen)',
        0x042b: 'Armenian-Armenia',
        0x044d: 'Assamese',
        0x082c: 'Azeri (Cyrillic)',
        0x042c: 'Azeri (Latin)',
        0x042d: 'Basque',
        0x0423: 'Belarusian',
        0x0445: 'Bengali (India)',
        0x0845: 'Bengali (Bangladesh)',
        0x141A: 'Bosnian (Bosnia/Herzegovina)',
        0x0402: 'Bulgarian',
        0x0455: 'Burmese',
        0x0403: 'Catalan',
        0x045c: 'Cherokee-United States',
        0x0804: 'Chinese (People\'s Republic of China)',
        0x1004: 'Chinese (Singapore)',
        0x0404: 'Chinese (Taiwan)',
        0x0c04: 'Chinese (Hong Kong SAR)',
        0x1404: 'Chinese (Macao SAR)',
        0x041a: 'Croatian',
        0x101a: 'Croatian (Bosnia/Herzegovina)',
        0x0405: 'Czech',
        0x0406: 'Danish',
        0x0465: 'Divehi',
        0x0413: 'Dutch-Netherlands',
        0x0813: 'Dutch-Belgium',
        0x0466: 'Edo',
        0x0409: 'English (United States)',
        0x0809: 'English (United Kingdom)',
        0x0c09: 'English (Australia)',
        0x2809: 'English (Belize)',
        0x1009: 'English (Canada)',
        0x2409: 'English (Caribbean)',
        0x3c09: 'English (Hong Kong SAR)',
        0x4009: 'English (India)',
        0x3809: 'English (Indonesia)',
        0x1809: 'English (Ireland)',
        0x2009: 'English (Jamaica)',
        0x4409: 'English (Malaysia)',
        0x1409: 'English (New Zealand)',
        0x3409: 'English (Philippines)',
        0x4809: 'English (Singapore)',
        0x1c09: 'English (South Africa)',
        0x2c09: 'English (Trinidad)',
        0x3009: 'English (Zimbabwe)',
        0x0425: 'Estonian',
        0x0438: 'Faroese',
        0x0429: 'Farsi',
        0x0464: 'Filipino',
        0x040b: 'Finnish',
        0x040c: 'French (France)',
        0x080c: 'French (Belgium)',
        0x2c0c: 'French (Cameroon)',
        0x0c0c: 'French (Canada)',
        0x240c: 'French (Democratic Rep. of Congo)',
        0x300c: 'French (Cote d\'Ivoire)',
        0x3c0c: 'French (Haiti)',
        0x140c: 'French (Luxembourg)',
        0x340c: 'French (Mali)',
        0x180c: 'French (Monaco)',
        0x380c: 'French (Morocco)',
        0xe40c: 'French (North Africa)',
        0x200c: 'French (Reunion)',
        0x280c: 'French (Senegal)',
        0x100c: 'French (Switzerland)',
        0x1c0c: 'French (West Indies)',
        0x0462: 'Frisian-Netherlands',
        0x0467: 'Fulfulde-Nigeria',
        0x042f: 'FYRO Macedonian',
        0x083c: 'Gaelic (Ireland)',
        0x043c: 'Gaelic (Scotland)',
        0x0456: 'Galician',
        0x0437: 'Georgian',
        0x0407: 'German (Germany)',
        0x0c07: 'German (Austria)',
        0x1407: 'German (Liechtenstein)',
        0x1007: 'German (Luxembourg)',
        0x0807: 'German (Switzerland)',
        0x0408: 'Greek',
        0x0474: 'Guarani-Paraguay',
        0x0447: 'Gujarati',
        0x0468: 'Hausa-Nigeria',
        0x0475: 'Hawaiian (United States)',
        0x040d: 'Hebrew',
        0x0439: 'Hindi',
        0x040e: 'Hungarian',
        0x0469: 'Ibibio-Nigeria',
        0x040f: 'Icelandic',
        0x0470: 'Igbo-Nigeria',
        0x0421: 'Indonesian',
        0x045d: 'Inuktitut',
        0x0410: 'Italian (Italy)',
        0x0810: 'Italian (Switzerland)',
        0x0411: 'Japanese',
        0x044b: 'Kannada',
        0x0471: 'Kanuri-Nigeria',
        0x0860: 'Kashmiri',
        0x0460: 'Kashmiri (Arabic)',
        0x043f: 'Kazakh',
        0x0453: 'Khmer',
        0x0457: 'Konkani',
        0x0412: 'Korean',
        0x0440: 'Kyrgyz (Cyrillic)',
        0x0454: 'Lao',
        0x0476: 'Latin',
        0x0426: 'Latvian',
        0x0427: 'Lithuanian',
        0x043e: 'Malay-Malaysia',
        0x083e: 'Malay-Brunei Darussalam',
        0x044c: 'Malayalam',
        0x043a: 'Maltese',
        0x0458: 'Manipuri',
        0x0481: 'Maori-New Zealand',
        0x044e: 'Marathi',
        0x0450: 'Mongolian (Cyrillic)',
        0x0850: 'Mongolian (Mongolian)',
        0x0461: 'Nepali',
        0x0861: 'Nepali-India',
        0x0414: 'Norwegian (Bokmål)',
        0x0814: 'Norwegian (Nynorsk)',
        0x0448: 'Oriya',
        0x0472: 'Oromo',
        0x0479: 'Papiamentu',
        0x0463: 'Pashto',
        0x0415: 'Polish',
        0x0416: 'Portuguese-Brazil',
        0x0816: 'Portuguese-Portugal',
        0x0446: 'Punjabi',
        0x0846: 'Punjabi (Pakistan)',
        0x046B: 'Quecha (Bolivia)',
        0x086B: 'Quecha (Ecuador)',
        0x0C6B: 'Quecha (Peru)',
        0x0417: 'Rhaeto-Romanic',
        0x0418: 'Romanian',
        0x0818: 'Romanian (Moldava)',
        0x0419: 'Russian',
        0x0819: 'Russian (Moldava)',
        0x043b: 'Sami (Lappish)',
        0x044f: 'Sanskrit',
        0x046c: 'Sepedi',
        0x0c1a: 'Serbian (Cyrillic)',
        0x081a: 'Serbian (Latin)',
        0x0459: 'Sindhi (India)',
        0x0859: 'Sindhi (Pakistan)',
        0x045b: 'Sinhalese-Sri Lanka',
        0x041b: 'Slovak',
        0x0424: 'Slovenian',
        0x0477: 'Somali',
        0x042e: 'Sorbian',
        0x0c0a: 'Spanish (Modern Sort)',
        0x040a: 'Spanish (Traditional Sort)',
        0x2c0a: 'Spanish (Argentina)',
        0x400a: 'Spanish (Bolivia)',
        0x340a: 'Spanish (Chile)',
        0x240a: 'Spanish (Colombia)',
        0x140a: 'Spanish (Costa Rica)',
        0x1c0a: 'Spanish (Dominican Republic)',
        0x300a: 'Spanish (Ecuador)',
        0x440a: 'Spanish (El Salvador)',
        0x100a: 'Spanish (Guatemala)',
        0x480a: 'Spanish (Honduras)',
        0x580a: 'Spanish (Latin America)',
        0x080a: 'Spanish (Mexico)',
        0x4c0a: 'Spanish (Nicaragua)',
        0x180a: 'Spanish (Panama)',
        0x3c0a: 'Spanish (Paraguay)',
        0x280a: 'Spanish (Peru)',
        0x500a: 'Spanish (Puerto Rico)',
        0x540a: 'Spanish (United States)',
        0x380a: 'Spanish (Uruguay)',
        0x200a: 'Spanish (Venezuela)',
        0x0430: 'Sutu',
        0x0441: 'Swahili',
        0x041d: 'Swedish',
        0x081d: 'Swedish-Finland',
        0x045a: 'Syriac',
        0x0428: 'Tajik',
        0x045f: 'Tamazight (Arabic)',
        0x085f: 'Tamazight (Latin)',
        0x0449: 'Tamil',
        0x0444: 'Tatar',
        0x044a: 'Telugu',
        0x041e: 'Thai',
        0x0851: 'Tibetan (Bhutan)',
        0x0451: 'Tibetan (People\'s Republic of China)',
        0x0873: 'Tigrigna (Eritrea)',
        0x0473: 'Tigrigna (Ethiopia)',
        0x0431: 'Tsonga',
        0x0432: 'Tswana',
        0x041f: 'Turkish',
        0x0442: 'Turkmen',
        0x0480: 'Uighur-China',
        0x0422: 'Ukrainian',
        0x0420: 'Urdu',
        0x0820: 'Urdu-India',
        0x0843: 'Uzbek (Cyrillic)',
        0x0443: 'Uzbek (Latin)',
        0x0433: 'Venda',
        0x042a: 'Vietnamese',
        0x0452: 'Welsh',
        0x0434: 'Xhosa',
        0x0478: 'Yi',
        0x043d: 'Yiddish',
        0x046a: 'Yoruba',
        0x0435: 'Zulu',
        0x04ff: 'HID (Human Interface DeVITe)'
    }

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

    # copy of https://raw.githubusercontent.com/dishather/richprint/master/comp_id.txt
    _RICH_HEADER = {
        # Objects without @comp.id are collected under this record
        0x00010000: VersionInfo(VIT.ERR, 'Unmarked objects'),
        0x00000000: VersionInfo(VIT.ERR, 'Unmarked objects (old)'),

        # MSVS2019 v16.9.2
        0x010474d9: VersionInfo(VIT.OBJ, 'VS2019 v16.9.2 build 29913'),
        0x010374d9: VersionInfo(VIT.ASM, 'VS2019 v16.9.2 build 29913'),
        0x010574d9: VersionInfo(VIT.CPP, 'VS2019 v16.9.2 build 29913'),
        0x00ff74d9: VersionInfo(VIT.RES, 'VS2019 v16.9.2 build 29913'),
        0x010274d9: VersionInfo(VIT.LNK, 'VS2019 v16.9.2 build 29913'),
        0x010074d9: VersionInfo(VIT.EXP, 'VS2019 v16.9.2 build 29913'),
        0x010174d9: VersionInfo(VIT.IMP, 'VS2019 v16.9.2 build 29913'),

        # MSVS2019 v16.9.2
        # from https://walbourn.github.io/vs-2019-update-9/
        0x010474d6: VersionInfo(VIT.OBJ, 'VS2019 v16.9.0 build 29910', interpolated=True),
        0x010374d6: VersionInfo(VIT.ASM, 'VS2019 v16.9.0 build 29910', interpolated=True),
        0x010574d6: VersionInfo(VIT.CPP, 'VS2019 v16.9.0 build 29910', interpolated=True),
        0x00ff74d6: VersionInfo(VIT.RES, 'VS2019 v16.9.0 build 29910', interpolated=True),
        0x010274d6: VersionInfo(VIT.LNK, 'VS2019 v16.9.0 build 29910', interpolated=True),
        0x010074d6: VersionInfo(VIT.EXP, 'VS2019 v16.9.0 build 29910', interpolated=True),
        0x010174d6: VersionInfo(VIT.IMP, 'VS2019 v16.9.0 build 29910', interpolated=True),

        # MSVS2019 v16.8.5
        0x01047299: VersionInfo(VIT.OBJ, 'VS2019 v16.8.5 build 29337'),
        0x01037299: VersionInfo(VIT.ASM, 'VS2019 v16.8.5 build 29337'),
        0x01057299: VersionInfo(VIT.CPP, 'VS2019 v16.8.5 build 29337'),
        0x00ff7299: VersionInfo(VIT.RES, 'VS2019 v16.8.5 build 29337'),
        0x01027299: VersionInfo(VIT.LNK, 'VS2019 v16.8.5 build 29337'),
        0x01007299: VersionInfo(VIT.EXP, 'VS2019 v16.8.5 build 29337'),
        0x01017299: VersionInfo(VIT.IMP, 'VS2019 v16.8.5 build 29337'),

        # MSVS2019 v16.8.4
        0x01047298: VersionInfo(VIT.OBJ, 'VS2019 v16.8.4 build 29336'),
        0x01037298: VersionInfo(VIT.ASM, 'VS2019 v16.8.4 build 29336'),
        0x01057298: VersionInfo(VIT.CPP, 'VS2019 v16.8.4 build 29336'),
        0x00ff7298: VersionInfo(VIT.RES, 'VS2019 v16.8.4 build 29336'),
        0x01027298: VersionInfo(VIT.LNK, 'VS2019 v16.8.4 build 29336'),
        0x01007298: VersionInfo(VIT.EXP, 'VS2019 v16.8.4 build 29336'),
        0x01017298: VersionInfo(VIT.IMP, 'VS2019 v16.8.4 build 29336'),

        # MSVS2019 v16.8.3
        0x01047297: VersionInfo(VIT.OBJ, 'VS2019 v16.8.3 build 29335'),
        0x01037297: VersionInfo(VIT.ASM, 'VS2019 v16.8.3 build 29335'),
        0x01057297: VersionInfo(VIT.CPP, 'VS2019 v16.8.3 build 29335'),
        0x00ff7297: VersionInfo(VIT.RES, 'VS2019 v16.8.3 build 29335'),
        0x01027297: VersionInfo(VIT.LNK, 'VS2019 v16.8.3 build 29335'),
        0x01007297: VersionInfo(VIT.EXP, 'VS2019 v16.8.3 build 29335'),
        0x01017297: VersionInfo(VIT.IMP, 'VS2019 v16.8.3 build 29335'),

        # MSVS2019 v16.8.2
        0x01047296: VersionInfo(VIT.OBJ, 'VS2019 v16.8.2 build 29334'),
        0x01037296: VersionInfo(VIT.ASM, 'VS2019 v16.8.2 build 29334'),
        0x01057296: VersionInfo(VIT.CPP, 'VS2019 v16.8.2 build 29334'),
        0x00ff7296: VersionInfo(VIT.RES, 'VS2019 v16.8.2 build 29334'),
        0x01027296: VersionInfo(VIT.LNK, 'VS2019 v16.8.2 build 29334'),
        0x01007296: VersionInfo(VIT.EXP, 'VS2019 v16.8.2 build 29334'),
        0x01017296: VersionInfo(VIT.IMP, 'VS2019 v16.8.2 build 29334'),

        # MSVS2019 v16.8.0
        # from https://walbourn.github.io/vs-2019-update-8/
        0x01047295: VersionInfo(VIT.OBJ, 'VS2019 v16.8.0 build 29333', interpolated=True),
        0x01037295: VersionInfo(VIT.ASM, 'VS2019 v16.8.0 build 29333', interpolated=True),
        0x01057295: VersionInfo(VIT.CPP, 'VS2019 v16.8.0 build 29333', interpolated=True),
        0x00ff7295: VersionInfo(VIT.RES, 'VS2019 v16.8.0 build 29333', interpolated=True),
        0x01027295: VersionInfo(VIT.LNK, 'VS2019 v16.8.0 build 29333', interpolated=True),
        0x01007295: VersionInfo(VIT.EXP, 'VS2019 v16.8.0 build 29333', interpolated=True),
        0x01017295: VersionInfo(VIT.IMP, 'VS2019 v16.8.0 build 29333', interpolated=True),

        # MSVS2019 v16.7.5
        0x010471b8: VersionInfo(VIT.OBJ, 'VS2019 v16.7.5 build 29112'),
        0x010371b8: VersionInfo(VIT.ASM, 'VS2019 v16.7.5 build 29112'),
        0x010571b8: VersionInfo(VIT.CPP, 'VS2019 v16.7.5 build 29112'),
        0x00ff71b8: VersionInfo(VIT.RES, 'VS2019 v16.7.5 build 29112'),
        0x010271b8: VersionInfo(VIT.LNK, 'VS2019 v16.7.5 build 29112'),
        0x010071b8: VersionInfo(VIT.EXP, 'VS2019 v16.7.5 build 29112'),
        0x010171b8: VersionInfo(VIT.IMP, 'VS2019 v16.7.5 build 29112'),

        # MSVS2019 v16.7.1 .. 16.7.4
        0x010471b7: VersionInfo(VIT.OBJ, 'VS2019 v16.7.1 build 29111'),
        0x010371b7: VersionInfo(VIT.ASM, 'VS2019 v16.7.1 build 29111'),
        0x010571b7: VersionInfo(VIT.CPP, 'VS2019 v16.7.1 build 29111'),
        0x00ff71b7: VersionInfo(VIT.RES, 'VS2019 v16.7.1 build 29111'),
        0x010271b7: VersionInfo(VIT.LNK, 'VS2019 v16.7.1 build 29111'),
        0x010071b7: VersionInfo(VIT.EXP, 'VS2019 v16.7.1 build 29111'),
        0x010171b7: VersionInfo(VIT.IMP, 'VS2019 v16.7.1 build 29111'),

        # MSVS2019 v16.7.0
        0x010471b6: VersionInfo(VIT.OBJ, 'VS2019 v16.7.0 build 29110'),
        0x010371b6: VersionInfo(VIT.ASM, 'VS2019 v16.7.0 build 29110'),
        0x010571b6: VersionInfo(VIT.CPP, 'VS2019 v16.7.0 build 29110'),
        0x00ff71b6: VersionInfo(VIT.RES, 'VS2019 v16.7.0 build 29110'),
        0x010271b6: VersionInfo(VIT.LNK, 'VS2019 v16.7.0 build 29110'),
        0x010071b6: VersionInfo(VIT.EXP, 'VS2019 v16.7.0 build 29110'),
        0x010171b6: VersionInfo(VIT.IMP, 'VS2019 v16.7.0 build 29110'),

        # MSVS2019 v16.6.2 ... 16.6.5
        0x01047086: VersionInfo(VIT.OBJ, 'VS2019 v16.6.2 build 28806'),
        0x01037086: VersionInfo(VIT.ASM, 'VS2019 v16.6.2 build 28806'),
        0x01057086: VersionInfo(VIT.CPP, 'VS2019 v16.6.2 build 28806'),
        0x00ff7086: VersionInfo(VIT.RES, 'VS2019 v16.6.2 build 28806'),
        0x01027086: VersionInfo(VIT.LNK, 'VS2019 v16.6.2 build 28806'),
        0x01007086: VersionInfo(VIT.EXP, 'VS2019 v16.6.2 build 28806'),
        0x01017086: VersionInfo(VIT.IMP, 'VS2019 v16.6.2 build 28806'),

        # MSVS2019 v16.6.0
        0x01047085: VersionInfo(VIT.OBJ, 'VS2019 v16.6.0 build 28805'),
        0x01037085: VersionInfo(VIT.ASM, 'VS2019 v16.6.0 build 28805'),
        0x01057085: VersionInfo(VIT.CPP, 'VS2019 v16.6.0 build 28805'),
        0x00ff7085: VersionInfo(VIT.RES, 'VS2019 v16.6.0 build 28805'),
        0x01027085: VersionInfo(VIT.LNK, 'VS2019 v16.6.0 build 28805'),
        0x01007085: VersionInfo(VIT.EXP, 'VS2019 v16.6.0 build 28805'),
        0x01017085: VersionInfo(VIT.IMP, 'VS2019 v16.6.0 build 28805'),

        # MSVS2019 v16.5.5 (also 16.5.4)
        0x01046fc6: VersionInfo(VIT.OBJ, 'VS2019 v16.5.5 build 28614'),
        0x01036fc6: VersionInfo(VIT.ASM, 'VS2019 v16.5.5 build 28614'),
        0x01056fc6: VersionInfo(VIT.CPP, 'VS2019 v16.5.5 build 28614'),
        0x00ff6fc6: VersionInfo(VIT.RES, 'VS2019 v16.5.5 build 28614'),
        0x01026fc6: VersionInfo(VIT.LNK, 'VS2019 v16.5.5 build 28614'),
        0x01006fc6: VersionInfo(VIT.EXP, 'VS2019 v16.5.5 build 28614'),
        0x01016fc6: VersionInfo(VIT.IMP, 'VS2019 v16.5.5 build 28614'),

        # Visual Studio 2019 version 16.5.2 (values are interpolated)
        # source: https://walbourn.github.io/vs-2019-update-5/
        0x01046fc4: VersionInfo(VIT.OBJ, 'VS2019 v16.5.2 build 28612', interpolated=True),
        0x01036fc4: VersionInfo(VIT.ASM, 'VS2019 v16.5.2 build 28612', interpolated=True),
        0x01056fc4: VersionInfo(VIT.CPP, 'VS2019 v16.5.2 build 28612', interpolated=True),
        0x00ff6fc4: VersionInfo(VIT.RES, 'VS2019 v16.5.2 build 28612', interpolated=True),
        0x01026fc4: VersionInfo(VIT.LNK, 'VS2019 v16.5.2 build 28612', interpolated=True),
        0x01016fc4: VersionInfo(VIT.IMP, 'VS2019 v16.5.2 build 28612', interpolated=True),
        0x01006fc4: VersionInfo(VIT.EXP, 'VS2019 v16.5.2 build 28612', interpolated=True),

        # Visual Studio 2019 version 16.5.1 (values are interpolated)
        0x01046fc3: VersionInfo(VIT.OBJ, 'VS2019 v16.5.1 build 28611', interpolated=True),
        0x01036fc3: VersionInfo(VIT.ASM, 'VS2019 v16.5.1 build 28611', interpolated=True),
        0x01056fc3: VersionInfo(VIT.CPP, 'VS2019 v16.5.1 build 28611', interpolated=True),
        0x00ff6fc3: VersionInfo(VIT.RES, 'VS2019 v16.5.1 build 28611', interpolated=True),
        0x01026fc3: VersionInfo(VIT.LNK, 'VS2019 v16.5.1 build 28611', interpolated=True),
        0x01016fc3: VersionInfo(VIT.IMP, 'VS2019 v16.5.1 build 28611', interpolated=True),
        0x01006fc3: VersionInfo(VIT.EXP, 'VS2019 v16.5.1 build 28611', interpolated=True),

        # Visual Studio 2019 version 16.5.0 (values are interpolated)
        # source: https://walbourn.github.io/vs-2019-update-5/
        0x01046fc2: VersionInfo(VIT.OBJ, 'VS2019 v16.5.0 build 28610', interpolated=True),
        0x01036fc2: VersionInfo(VIT.ASM, 'VS2019 v16.5.0 build 28610', interpolated=True),
        0x01056fc2: VersionInfo(VIT.CPP, 'VS2019 v16.5.0 build 28610', interpolated=True),
        0x00ff6fc2: VersionInfo(VIT.RES, 'VS2019 v16.5.0 build 28610', interpolated=True),
        0x01026fc2: VersionInfo(VIT.LNK, 'VS2019 v16.5.0 build 28610', interpolated=True),
        0x01016fc2: VersionInfo(VIT.IMP, 'VS2019 v16.5.0 build 28610', interpolated=True),
        0x01006fc2: VersionInfo(VIT.EXP, 'VS2019 v16.5.0 build 28610', interpolated=True),

        # MSVS2019 v16.4.6 (values are interpolated)
        # source: https://walbourn.github.io/vs-2019-update-4/
        0x01046e9f: VersionInfo(VIT.OBJ, 'VS2019 v16.4.6 build 28319', interpolated=True),
        0x01036e9f: VersionInfo(VIT.ASM, 'VS2019 v16.4.6 build 28319', interpolated=True),
        0x01056e9f: VersionInfo(VIT.CPP, 'VS2019 v16.4.6 build 28319', interpolated=True),
        0x00ff6e9f: VersionInfo(VIT.RES, 'VS2019 v16.4.6 build 28319', interpolated=True),
        0x01026e9f: VersionInfo(VIT.LNK, 'VS2019 v16.4.6 build 28319', interpolated=True),
        0x01006e9f: VersionInfo(VIT.EXP, 'VS2019 v16.4.6 build 28319', interpolated=True),
        0x01016e9f: VersionInfo(VIT.IMP, 'VS2019 v16.4.6 build 28319', interpolated=True),

        # MSVS2019 v16.4.4 (values are interpolated)
        # source: https://walbourn.github.io/vs-2019-update-4/
        0x01046e9c: VersionInfo(VIT.OBJ, 'VS2019 v16.4.4 build 28316', interpolated=True),
        0x01036e9c: VersionInfo(VIT.ASM, 'VS2019 v16.4.4 build 28316', interpolated=True),
        0x01056e9c: VersionInfo(VIT.CPP, 'VS2019 v16.4.4 build 28316', interpolated=True),
        0x00ff6e9c: VersionInfo(VIT.RES, 'VS2019 v16.4.4 build 28316', interpolated=True),
        0x01026e9c: VersionInfo(VIT.LNK, 'VS2019 v16.4.4 build 28316', interpolated=True),
        0x01006e9c: VersionInfo(VIT.EXP, 'VS2019 v16.4.4 build 28316', interpolated=True),
        0x01016e9c: VersionInfo(VIT.IMP, 'VS2019 v16.4.4 build 28316', interpolated=True),

        # MSVS2019 v16.4.3
        0x01046e9b: VersionInfo(VIT.OBJ, 'VS2019 v16.4.3 build 28315'),
        0x01036e9b: VersionInfo(VIT.ASM, 'VS2019 v16.4.3 build 28315'),
        0x01056e9b: VersionInfo(VIT.CPP, 'VS2019 v16.4.3 build 28315'),
        0x00ff6e9b: VersionInfo(VIT.RES, 'VS2019 v16.4.3 build 28315'),
        0x01026e9b: VersionInfo(VIT.LNK, 'VS2019 v16.4.3 build 28315'),
        0x01006e9b: VersionInfo(VIT.EXP, 'VS2019 v16.4.3 build 28315'),
        0x01016e9b: VersionInfo(VIT.IMP, 'VS2019 v16.4.3 build 28315'),

        # Visual Studio 2019 version 16.4.0 (values are interpolated)
        0x01046e9a: VersionInfo(VIT.OBJ, 'VS2019 v16.4.0 build 28314', interpolated=True),
        0x01036e9a: VersionInfo(VIT.ASM, 'VS2019 v16.4.0 build 28314', interpolated=True),
        0x01056e9a: VersionInfo(VIT.CPP, 'VS2019 v16.4.0 build 28314', interpolated=True),
        0x00ff6e9a: VersionInfo(VIT.RES, 'VS2019 v16.4.0 build 28314', interpolated=True),
        0x01026e9a: VersionInfo(VIT.LNK, 'VS2019 v16.4.0 build 28314', interpolated=True),
        0x01016e9a: VersionInfo(VIT.IMP, 'VS2019 v16.4.0 build 28314', interpolated=True),
        0x01006e9a: VersionInfo(VIT.EXP, 'VS2019 v16.4.0 build 28314', interpolated=True),

        # Visual Studio 2019 version 16.3.2 (values are interpolated)
        0x01046dc9: VersionInfo(VIT.OBJ, 'VS2019 v16.3.2 build 28105', interpolated=True),
        0x01036dc9: VersionInfo(VIT.ASM, 'VS2019 v16.3.2 build 28105', interpolated=True),
        0x01056dc9: VersionInfo(VIT.CPP, 'VS2019 v16.3.2 build 28105', interpolated=True),
        0x00ff6dc9: VersionInfo(VIT.RES, 'VS2019 v16.3.2 build 28105', interpolated=True),
        0x01026dc9: VersionInfo(VIT.LNK, 'VS2019 v16.3.2 build 28105', interpolated=True),
        0x01016dc9: VersionInfo(VIT.IMP, 'VS2019 v16.3.2 build 28105', interpolated=True),
        0x01006dc9: VersionInfo(VIT.EXP, 'VS2019 v16.3.2 build 28105', interpolated=True),

        # Visual Studio 2019 version 16.2.3 (values are interpolated)
        0x01046d01: VersionInfo(VIT.OBJ, 'VS2019 v16.2.3 build 27905', interpolated=True),
        0x01036d01: VersionInfo(VIT.ASM, 'VS2019 v16.2.3 build 27905', interpolated=True),
        0x01056d01: VersionInfo(VIT.CPP, 'VS2019 v16.2.3 build 27905', interpolated=True),
        0x00ff6d01: VersionInfo(VIT.RES, 'VS2019 v16.2.3 build 27905', interpolated=True),
        0x01026d01: VersionInfo(VIT.LNK, 'VS2019 v16.2.3 build 27905', interpolated=True),
        0x01016d01: VersionInfo(VIT.IMP, 'VS2019 v16.2.3 build 27905', interpolated=True),
        0x01006d01: VersionInfo(VIT.EXP, 'VS2019 v16.2.3 build 27905', interpolated=True),

        # Visual Studio 2019 version 16.1.2 (values are interpolated)
        0x01046c36: VersionInfo(VIT.OBJ, 'VS2019 v16.1.2 build 27702', interpolated=True),
        0x01036c36: VersionInfo(VIT.ASM, 'VS2019 v16.1.2 build 27702', interpolated=True),
        0x01056c36: VersionInfo(VIT.CPP, 'VS2019 v16.1.2 build 27702', interpolated=True),
        0x00ff6c36: VersionInfo(VIT.RES, 'VS2019 v16.1.2 build 27702', interpolated=True),
        0x01026c36: VersionInfo(VIT.LNK, 'VS2019 v16.1.2 build 27702', interpolated=True),
        0x01016c36: VersionInfo(VIT.IMP, 'VS2019 v16.1.2 build 27702', interpolated=True),
        0x01006c36: VersionInfo(VIT.EXP, 'VS2019 v16.1.2 build 27702', interpolated=True),

        # MSVS2019 v16.0.0
        0x01046b74: VersionInfo(VIT.OBJ, 'VS2019 v16.0.0 build 27508'),
        0x01036b74: VersionInfo(VIT.ASM, 'VS2019 v16.0.0 build 27508'),
        0x01056b74: VersionInfo(VIT.CPP, 'VS2019 v16.0.0 build 27508'),
        0x00ff6b74: VersionInfo(VIT.RES, 'VS2019 v16.0.0 build 27508'),
        0x01026b74: VersionInfo(VIT.LNK, 'VS2019 v16.0.0 build 27508'),
        0x01006b74: VersionInfo(VIT.EXP, 'VS2019 v16.0.0 build 27508'),
        0x01016b74: VersionInfo(VIT.IMP, 'VS2019 v16.0.0 build 27508'),

        # Visual Studio 2017 version 15.9.11 (values are interpolated)
        0x01046996: VersionInfo(VIT.OBJ, 'VS2017 v15.9.11 build 27030', interpolated=True),
        0x01036996: VersionInfo(VIT.ASM, 'VS2017 v15.9.11 build 27030', interpolated=True),
        0x01056996: VersionInfo(VIT.CPP, 'VS2017 v15.9.11 build 27030', interpolated=True),
        0x00ff6996: VersionInfo(VIT.RES, 'VS2017 v15.9.11 build 27030', interpolated=True),
        0x01026996: VersionInfo(VIT.LNK, 'VS2017 v15.9.11 build 27030', interpolated=True),
        0x01016996: VersionInfo(VIT.IMP, 'VS2017 v15.9.11 build 27030', interpolated=True),
        0x01006996: VersionInfo(VIT.EXP, 'VS2017 v15.9.11 build 27030', interpolated=True),

        # Visual Studio 2017 version 15.9.7 (values are interpolated)
        0x01046993: VersionInfo(VIT.OBJ, 'VS2017 v15.9.7 build 27027', interpolated=True),
        0x01036993: VersionInfo(VIT.ASM, 'VS2017 v15.9.7 build 27027', interpolated=True),
        0x01056993: VersionInfo(VIT.CPP, 'VS2017 v15.9.7 build 27027', interpolated=True),
        0x00ff6993: VersionInfo(VIT.RES, 'VS2017 v15.9.7 build 27027', interpolated=True),
        0x01026993: VersionInfo(VIT.LNK, 'VS2017 v15.9.7 build 27027', interpolated=True),
        0x01016993: VersionInfo(VIT.IMP, 'VS2017 v15.9.7 build 27027', interpolated=True),
        0x01006993: VersionInfo(VIT.EXP, 'VS2017 v15.9.7 build 27027', interpolated=True),

        # Visual Studio 2017 version 15.9.5 (values are interpolated)
        0x01046992: VersionInfo(VIT.OBJ, 'VS2017 v15.9.5 build 27026', interpolated=True),
        0x01036992: VersionInfo(VIT.ASM, 'VS2017 v15.9.5 build 27026', interpolated=True),
        0x01056992: VersionInfo(VIT.CPP, 'VS2017 v15.9.5 build 27026', interpolated=True),
        0x00ff6992: VersionInfo(VIT.RES, 'VS2017 v15.9.5 build 27026', interpolated=True),
        0x01026992: VersionInfo(VIT.LNK, 'VS2017 v15.9.5 build 27026', interpolated=True),
        0x01016992: VersionInfo(VIT.IMP, 'VS2017 v15.9.5 build 27026', interpolated=True),
        0x01006992: VersionInfo(VIT.EXP, 'VS2017 v15.9.5 build 27026', interpolated=True),

        # Visual Studio 2017 version 15.9.4 (values are interpolated)
        0x01046991: VersionInfo(VIT.OBJ, 'VS2017 v15.9.4 build 27025', interpolated=True),
        0x01036991: VersionInfo(VIT.ASM, 'VS2017 v15.9.4 build 27025', interpolated=True),
        0x01056991: VersionInfo(VIT.CPP, 'VS2017 v15.9.4 build 27025', interpolated=True),
        0x00ff6991: VersionInfo(VIT.RES, 'VS2017 v15.9.4 build 27025', interpolated=True),
        0x01026991: VersionInfo(VIT.LNK, 'VS2017 v15.9.4 build 27025', interpolated=True),
        0x01016991: VersionInfo(VIT.IMP, 'VS2017 v15.9.4 build 27025', interpolated=True),
        0x01006991: VersionInfo(VIT.EXP, 'VS2017 v15.9.4 build 27025', interpolated=True),

        # Visual Studio 2017 version 15.9.1 (values are interpolated)
        0x0104698f: VersionInfo(VIT.OBJ, 'VS2017 v15.9.1 build 27023', interpolated=True),
        0x0103698f: VersionInfo(VIT.ASM, 'VS2017 v15.9.1 build 27023', interpolated=True),
        0x0105698f: VersionInfo(VIT.CPP, 'VS2017 v15.9.1 build 27023', interpolated=True),
        0x00ff698f: VersionInfo(VIT.RES, 'VS2017 v15.9.1 build 27023', interpolated=True),
        0x0102698f: VersionInfo(VIT.LNK, 'VS2017 v15.9.1 build 27023', interpolated=True),
        0x0101698f: VersionInfo(VIT.IMP, 'VS2017 v15.9.1 build 27023', interpolated=True),
        0x0100698f: VersionInfo(VIT.EXP, 'VS2017 v15.9.1 build 27023', interpolated=True),

        # Visual Studio 2017 version 15.8.5 (values are interpolated)
        # source: https://walbourn.github.io/vs-2017-15-8-update/
        0x0104686c: VersionInfo(VIT.OBJ, 'VS2017 v15.8.5 build 26732', interpolated=True),
        0x0103686c: VersionInfo(VIT.ASM, 'VS2017 v15.8.5 build 26732', interpolated=True),
        0x0105686c: VersionInfo(VIT.CPP, 'VS2017 v15.8.5 build 26732', interpolated=True),
        0x00ff686c: VersionInfo(VIT.RES, 'VS2017 v15.8.5 build 26732', interpolated=True),
        0x0102686c: VersionInfo(VIT.LNK, 'VS2017 v15.8.5 build 26732', interpolated=True),
        0x0101686c: VersionInfo(VIT.IMP, 'VS2017 v15.8.5 build 26732', interpolated=True),
        0x0100686c: VersionInfo(VIT.EXP, 'VS2017 v15.8.5 build 26732', interpolated=True),

        # Visual Studio 2017 version 15.8.9 (sic!) (values are interpolated)
        # source: https://walbourn.github.io/vs-2017-15-8-update/
        0x0104686a: VersionInfo(VIT.OBJ, 'VS2017 v15.8.9? build 26730', interpolated=True),
        0x0103686a: VersionInfo(VIT.ASM, 'VS2017 v15.8.9? build 26730', interpolated=True),
        0x0105686a: VersionInfo(VIT.CPP, 'VS2017 v15.8.9? build 26730', interpolated=True),
        0x00ff686a: VersionInfo(VIT.RES, 'VS2017 v15.8.9? build 26730', interpolated=True),
        0x0102686a: VersionInfo(VIT.LNK, 'VS2017 v15.8.9? build 26730', interpolated=True),
        0x0101686a: VersionInfo(VIT.IMP, 'VS2017 v15.8.9? build 26730', interpolated=True),
        0x0100686a: VersionInfo(VIT.EXP, 'VS2017 v15.8.9? build 26730', interpolated=True),

        # Visual Studio 2017 version 15.8.4 (values are interpolated)
        # source: https://walbourn.github.io/vs-2017-15-8-update/
        0x01046869: VersionInfo(VIT.OBJ, 'VS2017 v15.8.4 build 26729', interpolated=True),
        0x01036869: VersionInfo(VIT.ASM, 'VS2017 v15.8.4 build 26729', interpolated=True),
        0x01056869: VersionInfo(VIT.CPP, 'VS2017 v15.8.4 build 26729', interpolated=True),
        0x00ff6869: VersionInfo(VIT.RES, 'VS2017 v15.8.4 build 26729', interpolated=True),
        0x01026869: VersionInfo(VIT.LNK, 'VS2017 v15.8.4 build 26729', interpolated=True),
        0x01016869: VersionInfo(VIT.IMP, 'VS2017 v15.8.4 build 26729', interpolated=True),
        0x01006869: VersionInfo(VIT.EXP, 'VS2017 v15.8.4 build 26729', interpolated=True),

        # Visual Studio 2017 version 15.8.0 (values are interpolated)
        # source: https://walbourn.github.io/vs-2017-15-8-update/
        0x01046866: VersionInfo(VIT.OBJ, 'VS2017 v15.8.0 build 26726', interpolated=True),
        0x01036866: VersionInfo(VIT.ASM, 'VS2017 v15.8.0 build 26726', interpolated=True),
        0x01056866: VersionInfo(VIT.CPP, 'VS2017 v15.8.0 build 26726', interpolated=True),
        0x00ff6866: VersionInfo(VIT.RES, 'VS2017 v15.8.0 build 26726', interpolated=True),
        0x01026866: VersionInfo(VIT.LNK, 'VS2017 v15.8.0 build 26726', interpolated=True),
        0x01016866: VersionInfo(VIT.IMP, 'VS2017 v15.8.0 build 26726', interpolated=True),
        0x01006866: VersionInfo(VIT.EXP, 'VS2017 v15.8.0 build 26726', interpolated=True),

        # Visual Studio 2017 version 15.7.5 (values are interpolated)
        0x01046741: VersionInfo(VIT.OBJ, 'VS2017 v15.7.5 build 26433', interpolated=True),
        0x01036741: VersionInfo(VIT.ASM, 'VS2017 v15.7.5 build 26433', interpolated=True),
        0x01056741: VersionInfo(VIT.CPP, 'VS2017 v15.7.5 build 26433', interpolated=True),
        0x00ff6741: VersionInfo(VIT.RES, 'VS2017 v15.7.5 build 26433', interpolated=True),
        0x01026741: VersionInfo(VIT.LNK, 'VS2017 v15.7.5 build 26433', interpolated=True),
        0x01016741: VersionInfo(VIT.IMP, 'VS2017 v15.7.5 build 26433', interpolated=True),
        0x01006741: VersionInfo(VIT.EXP, 'VS2017 v15.7.5 build 26433', interpolated=True),

        # Visual Studio 2017 version 15.7.4 (values are interpolated)
        # source: https://walbourn.github.io/vs-2017-15-7-update/
        0x0104673f: VersionInfo(VIT.OBJ, 'VS2017 v15.7.4 build 26431', interpolated=True),
        0x0103673f: VersionInfo(VIT.ASM, 'VS2017 v15.7.4 build 26431', interpolated=True),
        0x0105673f: VersionInfo(VIT.CPP, 'VS2017 v15.7.4 build 26431', interpolated=True),
        0x00ff673f: VersionInfo(VIT.RES, 'VS2017 v15.7.4 build 26431', interpolated=True),
        0x0102673f: VersionInfo(VIT.LNK, 'VS2017 v15.7.4 build 26431', interpolated=True),
        0x0101673f: VersionInfo(VIT.IMP, 'VS2017 v15.7.4 build 26431', interpolated=True),
        0x0100673f: VersionInfo(VIT.EXP, 'VS2017 v15.7.4 build 26431', interpolated=True),

        # Visual Studio 2017 version 15.7.3 (values are interpolated)
        0x0104673e: VersionInfo(VIT.OBJ, 'VS2017 v15.7.3 build 26430', interpolated=True),
        0x0103673e: VersionInfo(VIT.ASM, 'VS2017 v15.7.3 build 26430', interpolated=True),
        0x0105673e: VersionInfo(VIT.CPP, 'VS2017 v15.7.3 build 26430', interpolated=True),
        0x00ff673e: VersionInfo(VIT.RES, 'VS2017 v15.7.3 build 26430', interpolated=True),
        0x0102673e: VersionInfo(VIT.LNK, 'VS2017 v15.7.3 build 26430', interpolated=True),
        0x0101673e: VersionInfo(VIT.IMP, 'VS2017 v15.7.3 build 26430', interpolated=True),
        0x0100673e: VersionInfo(VIT.EXP, 'VS2017 v15.7.3 build 26430', interpolated=True),

        # Visual Studio 2017 version 15.7.2 (values are interpolated)
        0x0104673d: VersionInfo(VIT.OBJ, 'VS2017 v15.7.2 build 26429', interpolated=True),
        0x0103673d: VersionInfo(VIT.ASM, 'VS2017 v15.7.2 build 26429', interpolated=True),
        0x0105673d: VersionInfo(VIT.CPP, 'VS2017 v15.7.2 build 26429', interpolated=True),
        0x00ff673d: VersionInfo(VIT.RES, 'VS2017 v15.7.2 build 26429', interpolated=True),
        0x0102673d: VersionInfo(VIT.LNK, 'VS2017 v15.7.2 build 26429', interpolated=True),
        0x0101673d: VersionInfo(VIT.IMP, 'VS2017 v15.7.2 build 26429', interpolated=True),
        0x0100673d: VersionInfo(VIT.EXP, 'VS2017 v15.7.2 build 26429', interpolated=True),

        # Visual Studio 2017 version 15.7.1 (values are interpolated)
        0x0104673c: VersionInfo(VIT.OBJ, 'VS2017 v15.7.1 build 26428', interpolated=True),
        0x0103673c: VersionInfo(VIT.ASM, 'VS2017 v15.7.1 build 26428', interpolated=True),
        0x0105673c: VersionInfo(VIT.CPP, 'VS2017 v15.7.1 build 26428', interpolated=True),
        0x00ff673c: VersionInfo(VIT.RES, 'VS2017 v15.7.1 build 26428', interpolated=True),
        0x0102673c: VersionInfo(VIT.LNK, 'VS2017 v15.7.1 build 26428', interpolated=True),
        0x0101673c: VersionInfo(VIT.IMP, 'VS2017 v15.7.1 build 26428', interpolated=True),
        0x0100673c: VersionInfo(VIT.EXP, 'VS2017 v15.7.1 build 26428', interpolated=True),

        # Visual Studio 2017 version 15.6.7 (values are interpolated)
        0x01046614: VersionInfo(VIT.OBJ, 'VS2017 v15.6.7 build 26132', interpolated=True),
        0x01036614: VersionInfo(VIT.ASM, 'VS2017 v15.6.7 build 26132', interpolated=True),
        0x01056614: VersionInfo(VIT.CPP, 'VS2017 v15.6.7 build 26132', interpolated=True),
        0x00ff6614: VersionInfo(VIT.RES, 'VS2017 v15.6.7 build 26132', interpolated=True),
        0x01026614: VersionInfo(VIT.LNK, 'VS2017 v15.6.7 build 26132', interpolated=True),
        0x01016614: VersionInfo(VIT.IMP, 'VS2017 v15.6.7 build 26132', interpolated=True),
        0x01006614: VersionInfo(VIT.EXP, 'VS2017 v15.6.7 build 26132', interpolated=True),

        # Visual Studio 2017 version 15.6.6 (values are interpolated)
        0x01046613: VersionInfo(VIT.OBJ, 'VS2017 v15.6.6 build 26131', interpolated=True),
        0x01036613: VersionInfo(VIT.ASM, 'VS2017 v15.6.6 build 26131', interpolated=True),
        0x01056613: VersionInfo(VIT.CPP, 'VS2017 v15.6.6 build 26131', interpolated=True),
        0x00ff6613: VersionInfo(VIT.RES, 'VS2017 v15.6.6 build 26131', interpolated=True),
        0x01026613: VersionInfo(VIT.LNK, 'VS2017 v15.6.6 build 26131', interpolated=True),
        0x01016613: VersionInfo(VIT.IMP, 'VS2017 v15.6.6 build 26131', interpolated=True),
        0x01006613: VersionInfo(VIT.EXP, 'VS2017 v15.6.6 build 26131', interpolated=True),

        # Visual Studio 2017 version 15.6.4 has the same build number
        # Visual Studio 2017 version 15.6.3 (values are interpolated)
        0x01046611: VersionInfo(VIT.OBJ, 'VS2017 v15.6.3 build 26129', interpolated=True),
        0x01036611: VersionInfo(VIT.ASM, 'VS2017 v15.6.3 build 26129', interpolated=True),
        0x01056611: VersionInfo(VIT.CPP, 'VS2017 v15.6.3 build 26129', interpolated=True),
        0x00ff6611: VersionInfo(VIT.RES, 'VS2017 v15.6.3 build 26129', interpolated=True),
        0x01026611: VersionInfo(VIT.LNK, 'VS2017 v15.6.3 build 26129', interpolated=True),
        0x01016611: VersionInfo(VIT.IMP, 'VS2017 v15.6.3 build 26129', interpolated=True),
        0x01006611: VersionInfo(VIT.EXP, 'VS2017 v15.6.3 build 26129', interpolated=True),

        # Visual Studio 2017 version 15.6.2 has the same build number
        # Visual Studio 2017 version 15.6.1 has the same build number
        # Visual Studio 2017 version 15.6.0 (values are interpolated)
        0x01046610: VersionInfo(VIT.OBJ, 'VS2017 v15.6.0 build 26128', interpolated=True),
        0x01036610: VersionInfo(VIT.ASM, 'VS2017 v15.6.0 build 26128', interpolated=True),
        0x01056610: VersionInfo(VIT.CPP, 'VS2017 v15.6.0 build 26128', interpolated=True),
        0x00ff6610: VersionInfo(VIT.RES, 'VS2017 v15.6.0 build 26128', interpolated=True),
        0x01026610: VersionInfo(VIT.LNK, 'VS2017 v15.6.0 build 26128', interpolated=True),
        0x01016610: VersionInfo(VIT.IMP, 'VS2017 v15.6.0 build 26128', interpolated=True),
        0x01006610: VersionInfo(VIT.EXP, 'VS2017 v15.6.0 build 26128', interpolated=True),

        # Visual Studio 2017 version 15.5.7 has the same build number
        # Visual Studio 2017 version 15.5.6 (values are interpolated)
        0x010464eb: VersionInfo(VIT.OBJ, 'VS2017 v15.5.6 build 25835', interpolated=True),
        0x010364eb: VersionInfo(VIT.ASM, 'VS2017 v15.5.6 build 25835', interpolated=True),
        0x010564eb: VersionInfo(VIT.CPP, 'VS2017 v15.5.6 build 25835', interpolated=True),
        0x00ff64eb: VersionInfo(VIT.RES, 'VS2017 v15.5.6 build 25835', interpolated=True),
        0x010264eb: VersionInfo(VIT.LNK, 'VS2017 v15.5.6 build 25835', interpolated=True),
        0x010164eb: VersionInfo(VIT.IMP, 'VS2017 v15.5.6 build 25835', interpolated=True),
        0x010064eb: VersionInfo(VIT.EXP, 'VS2017 v15.5.6 build 25835', interpolated=True),

        # MSVS2017 v15.5.4 (15.5.3 has the same build number)
        0x010464ea: VersionInfo(VIT.OBJ, 'VS2017 v15.5.4 build 25834'),
        0x010364ea: VersionInfo(VIT.ASM, 'VS2017 v15.5.4 build 25834'),
        0x010564ea: VersionInfo(VIT.CPP, 'VS2017 v15.5.4 build 25834'),
        0x00ff64ea: VersionInfo(VIT.RES, 'VS2017 v15.5.4 build 25834'),
        0x010264ea: VersionInfo(VIT.LNK, 'VS2017 v15.5.4 build 25834'),
        0x010064ea: VersionInfo(VIT.EXP, 'VS2017 v15.5.4 build 25834'),
        0x010164ea: VersionInfo(VIT.IMP, 'VS2017 v15.5.4 build 25834'),

        # Visual Studio 2017 version 15.5.2 (values are interpolated)
        0x010464e7: VersionInfo(VIT.OBJ, 'VS2017 v15.5.2 build 25831', interpolated=True),
        0x010364e7: VersionInfo(VIT.ASM, 'VS2017 v15.5.2 build 25831', interpolated=True),
        0x010564e7: VersionInfo(VIT.CPP, 'VS2017 v15.5.2 build 25831', interpolated=True),
        0x00ff64e7: VersionInfo(VIT.RES, 'VS2017 v15.5.2 build 25831', interpolated=True),
        0x010264e7: VersionInfo(VIT.LNK, 'VS2017 v15.5.2 build 25831', interpolated=True),
        0x010164e7: VersionInfo(VIT.IMP, 'VS2017 v15.5.2 build 25831', interpolated=True),
        0x010064e7: VersionInfo(VIT.EXP, 'VS2017 v15.5.2 build 25831', interpolated=True),

        # Visual Studio 2017 version 15.4.5 (values are interpolated)
        0x010463cb: VersionInfo(VIT.OBJ, 'VS2017 v15.4.5 build 25547', interpolated=True),
        0x010363cb: VersionInfo(VIT.ASM, 'VS2017 v15.4.5 build 25547', interpolated=True),
        0x010563cb: VersionInfo(VIT.CPP, 'VS2017 v15.4.5 build 25547', interpolated=True),
        0x00ff63cb: VersionInfo(VIT.RES, 'VS2017 v15.4.5 build 25547', interpolated=True),
        0x010263cb: VersionInfo(VIT.LNK, 'VS2017 v15.4.5 build 25547', interpolated=True),
        0x010163cb: VersionInfo(VIT.IMP, 'VS2017 v15.4.5 build 25547', interpolated=True),
        0x010063cb: VersionInfo(VIT.EXP, 'VS2017 v15.4.5 build 25547', interpolated=True),

        # Visual Studio 2017 version 15.4.4 (values are interpolated)
        0x010463c6: VersionInfo(VIT.OBJ, 'VS2017 v15.4.4 build 25542', interpolated=True),
        0x010363c6: VersionInfo(VIT.ASM, 'VS2017 v15.4.4 build 25542', interpolated=True),
        0x010563c6: VersionInfo(VIT.CPP, 'VS2017 v15.4.4 build 25542', interpolated=True),
        0x00ff63c6: VersionInfo(VIT.RES, 'VS2017 v15.4.4 build 25542', interpolated=True),
        0x010263c6: VersionInfo(VIT.LNK, 'VS2017 v15.4.4 build 25542', interpolated=True),
        0x010163c6: VersionInfo(VIT.IMP, 'VS2017 v15.4.4 build 25542', interpolated=True),
        0x010063c6: VersionInfo(VIT.EXP, 'VS2017 v15.4.4 build 25542', interpolated=True),

        # Visual Studio 2017 version 15.3.3 (values are interpolated)
        0x010463a3: VersionInfo(VIT.OBJ, 'VS2017 v15.3.3 build 25507', interpolated=True),
        0x010363a3: VersionInfo(VIT.ASM, 'VS2017 v15.3.3 build 25507', interpolated=True),
        0x010563a3: VersionInfo(VIT.CPP, 'VS2017 v15.3.3 build 25507', interpolated=True),
        0x00ff63a3: VersionInfo(VIT.RES, 'VS2017 v15.3.3 build 25507', interpolated=True),
        0x010263a3: VersionInfo(VIT.LNK, 'VS2017 v15.3.3 build 25507', interpolated=True),
        0x010163a3: VersionInfo(VIT.IMP, 'VS2017 v15.3.3 build 25507', interpolated=True),
        0x010063a3: VersionInfo(VIT.EXP, 'VS2017 v15.3.3 build 25507', interpolated=True),

        # Visual Studio 2017 version 15.3 (values are interpolated)
        # source: https://twitter.com/visualc/status/897853176002433024
        0x010463a2: VersionInfo(VIT.OBJ, 'VS2017 v15.3 build 25506', interpolated=True),
        0x010363a2: VersionInfo(VIT.ASM, 'VS2017 v15.3 build 25506', interpolated=True),
        0x010563a2: VersionInfo(VIT.CPP, 'VS2017 v15.3 build 25506', interpolated=True),
        0x00ff63a2: VersionInfo(VIT.RES, 'VS2017 v15.3 build 25506', interpolated=True),
        0x010263a2: VersionInfo(VIT.LNK, 'VS2017 v15.3 build 25506', interpolated=True),
        0x010163a2: VersionInfo(VIT.IMP, 'VS2017 v15.3 build 25506', interpolated=True),
        0x010063a2: VersionInfo(VIT.EXP, 'VS2017 v15.3 build 25506', interpolated=True),

        # Visual Studio 2017 version 15.2 has the same build number
        # Visual Studio 2017 version 15.1 has the same build number
        # Visual Studio 2017 version 15.0 (values are interpolated)
        0x010461b9: VersionInfo(VIT.OBJ, 'VS2017 v15.0 build 25017', interpolated=True),
        0x010361b9: VersionInfo(VIT.ASM, 'VS2017 v15.0 build 25017', interpolated=True),
        0x010561b9: VersionInfo(VIT.CPP, 'VS2017 v15.0 build 25017', interpolated=True),
        0x00ff61b9: VersionInfo(VIT.RES, 'VS2017 v15.0 build 25017', interpolated=True),
        0x010261b9: VersionInfo(VIT.LNK, 'VS2017 v15.0 build 25017', interpolated=True),
        0x010161b9: VersionInfo(VIT.IMP, 'VS2017 v15.0 build 25017', interpolated=True),
        0x010061b9: VersionInfo(VIT.EXP, 'VS2017 v15.0 build 25017', interpolated=True),

        # MSVS Community 2015 UPD3.1 (cl version 19.00.24215.1) - some IDs are interpolated
        # [ASM] is the same as in UPD3 build 24213
        0x01045e97: VersionInfo(VIT.OBJ, 'VS2015 UPD3.1 build 24215'),
        0x01055e97: VersionInfo(VIT.CPP, 'VS2015 UPD3.1 build 24215'),
        0x01025e97: VersionInfo(VIT.LNK, 'VS2015 UPD3.1 build 24215'),
        0x01005e97: VersionInfo(VIT.EXP, 'VS2015 UPD3.1 build 24215'),
        0x01015e97: VersionInfo(VIT.IMP, 'VS2015 UPD3.1 build 24215'),

        # MSVS Community 2015 UPD3 (cl version 19.00.24213.1)
        0x01045e95: VersionInfo(VIT.OBJ, 'VS2015 UPD3 build 24213'),
        0x01035e92: VersionInfo(VIT.ASM, 'VS2015 UPD3 build 24210'),
        0x01055e95: VersionInfo(VIT.CPP, 'VS2015 UPD3 build 24213'),
        0x00ff5e92: VersionInfo(VIT.RES, 'VS2015 UPD3 build 24210'),
        0x01025e95: VersionInfo(VIT.LNK, 'VS2015 UPD3 build 24213'),
        0x01005e95: VersionInfo(VIT.EXP, 'VS2015 UPD3 build 24213'),
        0x01015e95: VersionInfo(VIT.IMP, 'VS2015 UPD3 build 24213'),

        # Visual Studio 2015 Update 3 [14.0] (values are interpolated)
        0x01045e92: VersionInfo(VIT.OBJ, 'VS2015 Update 3 [14.0] build 24210', interpolated=True),
        # 01035e92 [ASM] VS2015 Update 3 [14.0] build 24210 (*)
        0x01055e92: VersionInfo(VIT.CPP, 'VS2015 Update 3 [14.0] build 24210', interpolated=True),
        # 00ff5e92 [RES] VS2015 Update 3 [14.0] build 24210 (*)
        0x01025e92: VersionInfo(VIT.LNK, 'VS2015 Update 3 [14.0] build 24210', interpolated=True),
        0x01015e92: VersionInfo(VIT.IMP, 'VS2015 Update 3 [14.0] build 24210', interpolated=True),
        0x01005e92: VersionInfo(VIT.EXP, 'VS2015 Update 3 [14.0] build 24210', interpolated=True),

        # MSVS Community 2015 UPD2 (14.0.25123.0?)
        0x01045d6e: VersionInfo(VIT.OBJ, 'VS2015 UPD2 build 23918'),
        0x01035d6e: VersionInfo(VIT.ASM, 'VS2015 UPD2 build 23918'),
        0x01055d6e: VersionInfo(VIT.CPP, 'VS2015 UPD2 build 23918'),
        0x00ff5d6e: VersionInfo(VIT.RES, 'VS2015 UPD2 build 23918'),
        0x01025d6e: VersionInfo(VIT.LNK, 'VS2015 UPD2 build 23918'),
        0x01005d6e: VersionInfo(VIT.EXP, 'VS2015 UPD2 build 23918'),
        0x01015d6e: VersionInfo(VIT.IMP, 'VS2015 UPD2 build 23918'),

        # MSVS Community 2015 14.0.24728.2 (UPD 1) 14.0.24720.0 D14REL
        0x01045bd2: VersionInfo(VIT.OBJ, 'VS2015 UPD1 build 23506'),
        0x01035bd2: VersionInfo(VIT.ASM, 'VS2015 UPD1 build 23506'),
        0x01055bd2: VersionInfo(VIT.CPP, 'VS2015 UPD1 build 23506'),
        0x00ff5bd2: VersionInfo(VIT.RES, 'VS2015 UPD1 build 23506'),
        0x01025bd2: VersionInfo(VIT.LNK, 'VS2015 UPD1 build 23506'),
        0x01005bd2: VersionInfo(VIT.EXP, 'VS2015 UPD1 build 23506'),
        0x01015bd2: VersionInfo(VIT.IMP, 'VS2015 UPD1 build 23506'),

        # MSVS Community 2015 [14.0]
        0x010459f2: VersionInfo(VIT.OBJ, 'VS2015 [14.0] build 23026'),
        0x010359f2: VersionInfo(VIT.ASM, 'VS2015 [14.0] build 23026'),
        0x010559f2: VersionInfo(VIT.CPP, 'VS2015 [14.0] build 23026'),
        0x00ff59f2: VersionInfo(VIT.RES, 'VS2015 [14.0] build 23026'),
        0x010259f2: VersionInfo(VIT.LNK, 'VS2015 [14.0] build 23026'),
        0x010059f2: VersionInfo(VIT.EXP, 'VS2015 [14.0] build 23026'),
        0x010159f2: VersionInfo(VIT.IMP, 'VS2015 [14.0] build 23026'),

        # Visual Studio 2013 Nobemver CTP [12.0] (values are interpolated)
        0x00e0527a: VersionInfo(VIT.OBJ, 'VS2013 Nobemver CTP [12.0] build 21114', interpolated=True),
        0x00df527a: VersionInfo(VIT.ASM, 'VS2013 Nobemver CTP [12.0] build 21114', interpolated=True),
        0x00e1527a: VersionInfo(VIT.CPP, 'VS2013 Nobemver CTP [12.0] build 21114', interpolated=True),
        0x00db527a: VersionInfo(VIT.RES, 'VS2013 Nobemver CTP [12.0] build 21114', interpolated=True),
        0x00de527a: VersionInfo(VIT.LNK, 'VS2013 Nobemver CTP [12.0] build 21114', interpolated=True),
        0x00dd527a: VersionInfo(VIT.IMP, 'VS2013 Nobemver CTP [12.0] build 21114', interpolated=True),
        0x00dc527a: VersionInfo(VIT.EXP, 'VS2013 Nobemver CTP [12.0] build 21114', interpolated=True),

        # MSVS2013 12.0.40629.00 Update 5
        0x00e09eb5: VersionInfo(VIT.OBJ, 'VS2013 UPD5 build 40629'),
        0x00e19eb5: VersionInfo(VIT.CPP, 'VS2013 UPD5 build 40629'),
        # cvtres not updated since RTM version, so add interpolated one
        0x00db9eb5: VersionInfo(VIT.RES, 'VS2013 Update 5 [12.0] build 40629', interpolated=True),
        0x00de9eb5: VersionInfo(VIT.LNK, 'VS2013 UPD5 build 40629'),
        0x00dc9eb5: VersionInfo(VIT.EXP, 'VS2013 UPD5 build 40629'),
        0x00dd9eb5: VersionInfo(VIT.IMP, 'VS2013 UPD5 build 40629'),
        0x00df9eb5: VersionInfo(VIT.ASM, 'VS2013 UPD5 build 40629'),

        # MSVS2013 12.0.31101.00 Update 4 - not attested in real world, @comp.id is
        # calculated.
        0x00e0797d: VersionInfo(VIT.OBJ, 'VS2013 UPD4 build 31101', interpolated=True),
        0x00e1797d: VersionInfo(VIT.CPP, 'VS2013 UPD4 build 31101', interpolated=True),
        0x00db797d: VersionInfo(VIT.RES, 'VS2013 UPD4 build 31101', interpolated=True),
        0x00de797d: VersionInfo(VIT.LNK, 'VS2013 UPD4 build 31101', interpolated=True),
        0x00dc797d: VersionInfo(VIT.EXP, 'VS2013 UPD4 build 31101', interpolated=True),
        0x00dd797d: VersionInfo(VIT.IMP, 'VS2013 UPD4 build 31101', interpolated=True),
        0x00df797d: VersionInfo(VIT.ASM, 'VS2013 UPD4 build 31101', interpolated=True),

        # MSVS2013 12.0.30723.00 Update 3 - not attested in real world, @comp.id is
        # calculated.
        0x00e07803: VersionInfo(VIT.OBJ, 'VS2013 UPD3 build 30723', interpolated=True),
        0x00e17803: VersionInfo(VIT.CPP, 'VS2013 UPD3 build 30723', interpolated=True),
        0x00db7803: VersionInfo(VIT.RES, 'VS2013 UPD3 build 30723', interpolated=True),
        0x00de7803: VersionInfo(VIT.LNK, 'VS2013 UPD3 build 30723', interpolated=True),
        0x00dc7803: VersionInfo(VIT.EXP, 'VS2013 UPD3 build 30723', interpolated=True),
        0x00dd7803: VersionInfo(VIT.IMP, 'VS2013 UPD3 build 30723', interpolated=True),
        0x00df7803: VersionInfo(VIT.ASM, 'VS2013 UPD3 build 30723', interpolated=True),

        # MSVS2013 12.0.30501.00 Update 2 - not attested in real world, @comp.id is
        # calculated.
        0x00e07725: VersionInfo(VIT.OBJ, 'VS2013 UPD2 build 30501'),
        0x00e17725: VersionInfo(VIT.CPP, 'VS2013 UPD2 build 30501'),
        # cvtres not updated since RTM version, so add interpolated one
        0x00db7725: VersionInfo(VIT.RES, 'VS2013 Update 2 [12.0] build 30501', interpolated=True),
        0x00de7725: VersionInfo(VIT.LNK, 'VS2013 UPD2 build 30501'),
        0x00dc7725: VersionInfo(VIT.EXP, 'VS2013 UPD2 build 30501'),
        0x00dd7725: VersionInfo(VIT.IMP, 'VS2013 UPD2 build 30501'),
        0x00df7725: VersionInfo(VIT.ASM, 'VS2013 UPD2 build 30501'),

        # Visual Studio 2013 Update2 RC [12.0] (values are interpolated)
        0x00e07674: VersionInfo(VIT.OBJ, 'VS2013 Update2 RC [12.0] build 30324', interpolated=True),
        0x00df7674: VersionInfo(VIT.ASM, 'VS2013 Update2 RC [12.0] build 30324', interpolated=True),
        0x00e17674: VersionInfo(VIT.CPP, 'VS2013 Update2 RC [12.0] build 30324', interpolated=True),
        0x00db7674: VersionInfo(VIT.RES, 'VS2013 Update2 RC [12.0] build 30324', interpolated=True),
        0x00de7674: VersionInfo(VIT.LNK, 'VS2013 Update2 RC [12.0] build 30324', interpolated=True),
        0x00dd7674: VersionInfo(VIT.IMP, 'VS2013 Update2 RC [12.0] build 30324', interpolated=True),
        0x00dc7674: VersionInfo(VIT.EXP, 'VS2013 Update2 RC [12.0] build 30324', interpolated=True),

        # MSVS2013 RTM
        # Looks like it doesn't always dump linker's comp.id
        # Visual Studio 2013 Update 1 [12.0] also has this build number
        0x00e0520d: VersionInfo(VIT.OBJ, 'VS2013 build 21005'),
        0x00e1520d: VersionInfo(VIT.CPP, 'VS2013 build 21005'),
        0x00db520d: VersionInfo(VIT.RES, 'VS2013 build 21005'),
        0x00de520d: VersionInfo(VIT.LNK, 'VS2013 build 21005'),
        0x00dc520d: VersionInfo(VIT.EXP, 'VS2013 build 21005'),
        0x00dd520d: VersionInfo(VIT.IMP, 'VS2013 build 21005'),
        0x00df520d: VersionInfo(VIT.ASM, 'VS2013 build 21005'),

        # Visual Studio 2013 RC [12.0] (values are interpolated)
        0x00e0515b: VersionInfo(VIT.OBJ, 'VS2013 RC [12.0] build 20827', interpolated=True),
        0x00df515b: VersionInfo(VIT.ASM, 'VS2013 RC [12.0] build 20827', interpolated=True),
        0x00e1515b: VersionInfo(VIT.CPP, 'VS2013 RC [12.0] build 20827', interpolated=True),
        0x00db515b: VersionInfo(VIT.RES, 'VS2013 RC [12.0] build 20827', interpolated=True),
        0x00de515b: VersionInfo(VIT.LNK, 'VS2013 RC [12.0] build 20827', interpolated=True),
        0x00dd515b: VersionInfo(VIT.IMP, 'VS2013 RC [12.0] build 20827', interpolated=True),
        0x00dc515b: VersionInfo(VIT.EXP, 'VS2013 RC [12.0] build 20827', interpolated=True),

        # Visual Studio 2013 Preview [12.0] (values are interpolated)
        0x00e05089: VersionInfo(VIT.OBJ, 'VS2013 Preview [12.0] build 20617', interpolated=True),
        0x00df5089: VersionInfo(VIT.ASM, 'VS2013 Preview [12.0] build 20617', interpolated=True),
        0x00e15089: VersionInfo(VIT.CPP, 'VS2013 Preview [12.0] build 20617', interpolated=True),
        0x00db5089: VersionInfo(VIT.RES, 'VS2013 Preview [12.0] build 20617', interpolated=True),
        0x00de5089: VersionInfo(VIT.LNK, 'VS2013 Preview [12.0] build 20617', interpolated=True),
        0x00dd5089: VersionInfo(VIT.IMP, 'VS2013 Preview [12.0] build 20617', interpolated=True),
        0x00dc5089: VersionInfo(VIT.EXP, 'VS2013 Preview [12.0] build 20617', interpolated=True),

        # MSVS2012 Premium Update 4 (11.0.61030.00 Update 4)
        0x00ceee66: VersionInfo(VIT.OBJ, 'VS2012 UPD4 build 61030'),
        0x00cfee66: VersionInfo(VIT.CPP, 'VS2012 UPD4 build 61030'),
        0x00cdee66: VersionInfo(VIT.ASM, 'VS2012 UPD4 build 61030'),
        0x00c9ee66: VersionInfo(VIT.RES, 'VS2012 UPD4 build 61030'),
        0x00ccee66: VersionInfo(VIT.LNK, 'VS2012 UPD4 build 61030'),
        0x00caee66: VersionInfo(VIT.EXP, 'VS2012 UPD4 build 61030'),
        0x00cbee66: VersionInfo(VIT.IMP, 'VS2012 UPD4 build 61030'),

        # MSVS2012 Update 3 (17.00.60610.1 Update 3) - not attested in real world,
        # @comp.id is calculated.
        0x00ceecc2: VersionInfo(VIT.OBJ, 'VS2012 UPD3 build 60610', interpolated=True),
        0x00cfecc2: VersionInfo(VIT.CPP, 'VS2012 UPD3 build 60610', interpolated=True),
        0x00cdecc2: VersionInfo(VIT.ASM, 'VS2012 UPD3 build 60610', interpolated=True),
        0x00c9ecc2: VersionInfo(VIT.RES, 'VS2012 UPD3 build 60610', interpolated=True),
        0x00ccecc2: VersionInfo(VIT.LNK, 'VS2012 UPD3 build 60610', interpolated=True),
        0x00caecc2: VersionInfo(VIT.EXP, 'VS2012 UPD3 build 60610', interpolated=True),
        0x00cbecc2: VersionInfo(VIT.IMP, 'VS2012 UPD3 build 60610', interpolated=True),

        # MSVS2012 Update 2 (17.00.60315.1 Update 2) - not attested in real world,
        # @comp.id is calculated.
        0x00ceeb9b: VersionInfo(VIT.OBJ, 'VS2012 UPD2 build 60315', interpolated=True),
        0x00cfeb9b: VersionInfo(VIT.CPP, 'VS2012 UPD2 build 60315', interpolated=True),
        0x00cdeb9b: VersionInfo(VIT.ASM, 'VS2012 UPD2 build 60315', interpolated=True),
        0x00c9eb9b: VersionInfo(VIT.RES, 'VS2012 UPD2 build 60315', interpolated=True),
        0x00cceb9b: VersionInfo(VIT.LNK, 'VS2012 UPD2 build 60315', interpolated=True),
        0x00caeb9b: VersionInfo(VIT.EXP, 'VS2012 UPD2 build 60315', interpolated=True),
        0x00cbeb9b: VersionInfo(VIT.IMP, 'VS2012 UPD2 build 60315', interpolated=True),

        # MSVS2012 Update 1 (17.00.51106.1 Update 1) - not attested in real world,
        # @comp.id is calculated.
        0x00cec7a2: VersionInfo(VIT.OBJ, 'VS2012 UPD1 build 51106', interpolated=True),
        0x00cfc7a2: VersionInfo(VIT.CPP, 'VS2012 UPD1 build 51106', interpolated=True),
        0x00cdc7a2: VersionInfo(VIT.ASM, 'VS2012 UPD1 build 51106', interpolated=True),
        0x00c9c7a2: VersionInfo(VIT.RES, 'VS2012 UPD1 build 51106', interpolated=True),
        0x00ccc7a2: VersionInfo(VIT.LNK, 'VS2012 UPD1 build 51106', interpolated=True),
        0x00cac7a2: VersionInfo(VIT.EXP, 'VS2012 UPD1 build 51106', interpolated=True),
        0x00cbc7a2: VersionInfo(VIT.IMP, 'VS2012 UPD1 build 51106', interpolated=True),

        # Visual Studio 2012 November CTP [11.0] (values are interpolated)
        0x00cec751: VersionInfo(VIT.OBJ, 'VS2012 November CTP [11.0] build 51025', interpolated=True),
        0x00cdc751: VersionInfo(VIT.ASM, 'VS2012 November CTP [11.0] build 51025', interpolated=True),
        0x00cfc751: VersionInfo(VIT.CPP, 'VS2012 November CTP [11.0] build 51025', interpolated=True),
        0x00c9c751: VersionInfo(VIT.RES, 'VS2012 November CTP [11.0] build 51025', interpolated=True),
        0x00ccc751: VersionInfo(VIT.LNK, 'VS2012 November CTP [11.0] build 51025', interpolated=True),
        0x00cbc751: VersionInfo(VIT.IMP, 'VS2012 November CTP [11.0] build 51025', interpolated=True),
        0x00cac751: VersionInfo(VIT.EXP, 'VS2012 November CTP [11.0] build 51025', interpolated=True),

        # MSVS2012 Premium (11.0.50727.1 RTMREL)
        0x00cec627: VersionInfo(VIT.OBJ, 'VS2012 build 50727'),
        0x00cfc627: VersionInfo(VIT.CPP, 'VS2012 build 50727'),
        0x00c9c627: VersionInfo(VIT.RES, 'VS2012 build 50727'),
        0x00cdc627: VersionInfo(VIT.ASM, 'VS2012 build 50727'),
        0x00cac627: VersionInfo(VIT.EXP, 'VS2012 build 50727'),
        0x00cbc627: VersionInfo(VIT.IMP, 'VS2012 build 50727'),
        0x00ccc627: VersionInfo(VIT.LNK, 'VS2012 build 50727'),

        # MSVS2010 SP1 kb 983509 (10.0.40219.1 SP1Rel)
        0x00aa9d1b: VersionInfo(VIT.OBJ, 'VS2010 SP1 build 40219'),
        0x00ab9d1b: VersionInfo(VIT.CPP, 'VS2010 SP1 build 40219'),
        0x009d9d1b: VersionInfo(VIT.LNK, 'VS2010 SP1 build 40219'),
        0x009a9d1b: VersionInfo(VIT.RES, 'VS2010 SP1 build 40219'),
        0x009b9d1b: VersionInfo(VIT.EXP, 'VS2010 SP1 build 40219'),
        0x009c9d1b: VersionInfo(VIT.IMP, 'VS2010 SP1 build 40219'),
        0x009e9d1b: VersionInfo(VIT.ASM, 'VS2010 SP1 build 40219'),

        # MSVS2010 (10.0.30319.1 RTMRel)
        0x00aa766f: VersionInfo(VIT.OBJ, 'VS2010 build 30319'),
        0x00ab766f: VersionInfo(VIT.CPP, 'VS2010 build 30319'),
        0x009d766f: VersionInfo(VIT.LNK, 'VS2010 build 30319'),
        0x009a766f: VersionInfo(VIT.RES, 'VS2010 build 30319'),
        0x009b766f: VersionInfo(VIT.EXP, 'VS2010 build 30319'),
        0x009c766f: VersionInfo(VIT.IMP, 'VS2010 build 30319'),
        0x009e766f: VersionInfo(VIT.ASM, 'VS2010 build 30319'),

        # Visual Studio 2010 Beta 2 [10.0] (values are interpolated)
        0x00aa520b: VersionInfo(VIT.OBJ, 'VS2010 Beta 2 [10.0] build 21003', interpolated=True),
        0x009e520b: VersionInfo(VIT.ASM, 'VS2010 Beta 2 [10.0] build 21003', interpolated=True),
        0x00ab520b: VersionInfo(VIT.CPP, 'VS2010 Beta 2 [10.0] build 21003', interpolated=True),
        0x009a520b: VersionInfo(VIT.RES, 'VS2010 Beta 2 [10.0] build 21003', interpolated=True),
        0x009d520b: VersionInfo(VIT.LNK, 'VS2010 Beta 2 [10.0] build 21003', interpolated=True),
        0x009c520b: VersionInfo(VIT.IMP, 'VS2010 Beta 2 [10.0] build 21003', interpolated=True),
        0x009b520b: VersionInfo(VIT.EXP, 'VS2010 Beta 2 [10.0] build 21003', interpolated=True),

        # Visual Studio 2010 Beta 1 [10.0] (values are interpolated)
        0x00aa501a: VersionInfo(VIT.OBJ, 'VS2010 Beta 1 [10.0] build 20506', interpolated=True),
        0x009e501a: VersionInfo(VIT.ASM, 'VS2010 Beta 1 [10.0] build 20506', interpolated=True),
        0x00ab501a: VersionInfo(VIT.CPP, 'VS2010 Beta 1 [10.0] build 20506', interpolated=True),
        0x009a501a: VersionInfo(VIT.RES, 'VS2010 Beta 1 [10.0] build 20506', interpolated=True),
        0x009d501a: VersionInfo(VIT.LNK, 'VS2010 Beta 1 [10.0] build 20506', interpolated=True),
        0x009c501a: VersionInfo(VIT.IMP, 'VS2010 Beta 1 [10.0] build 20506', interpolated=True),
        0x009b501a: VersionInfo(VIT.EXP, 'VS2010 Beta 1 [10.0] build 20506', interpolated=True),

        # MSVS2008 SP1 (9.0.30729.1 SP)
        0x00837809: VersionInfo(VIT.OBJ, 'VS2008 SP1 build 30729'),
        0x00847809: VersionInfo(VIT.CPP, 'VS2008 SP1 build 30729'),
        # cvtres is the same as in VS2008, so add interpolated
        0x00947809: VersionInfo(VIT.RES, 'VS2008 SP1 [9.0] build 30729', interpolated=True),
        0x00957809: VersionInfo(VIT.ASM, 'VS2008 SP1 build 30729'),
        0x00927809: VersionInfo(VIT.EXP, 'VS2008 SP1 build 30729'),
        0x00937809: VersionInfo(VIT.IMP, 'VS2008 SP1 build 30729'),
        0x00917809: VersionInfo(VIT.LNK, 'VS2008 SP1 build 30729'),

        # MSVS2008 (9.0.21022.8 RTM)
        0x0083521e: VersionInfo(VIT.OBJ, 'VS2008 build 21022'),
        0x0084521e: VersionInfo(VIT.CPP, 'VS2008 build 21022'),
        0x0091521e: VersionInfo(VIT.LNK, 'VS2008 build 21022'),
        0x0094521e: VersionInfo(VIT.RES, 'VS2008 build 21022'),
        0x0092521e: VersionInfo(VIT.EXP, 'VS2008 build 21022'),
        0x0093521e: VersionInfo(VIT.IMP, 'VS2008 build 21022'),
        0x0095521e: VersionInfo(VIT.ASM, 'VS2008 build 21022'),

        # Visual Studio 2008 Beta 2 [9.0] (values are interpolated)
        0x008350e2: VersionInfo(VIT.OBJ, 'VS2008 Beta 2 [9.0] build 20706', interpolated=True),
        0x009550e2: VersionInfo(VIT.ASM, 'VS2008 Beta 2 [9.0] build 20706', interpolated=True),
        0x008450e2: VersionInfo(VIT.CPP, 'VS2008 Beta 2 [9.0] build 20706', interpolated=True),
        0x009450e2: VersionInfo(VIT.RES, 'VS2008 Beta 2 [9.0] build 20706', interpolated=True),
        0x009150e2: VersionInfo(VIT.LNK, 'VS2008 Beta 2 [9.0] build 20706', interpolated=True),
        0x009350e2: VersionInfo(VIT.IMP, 'VS2008 Beta 2 [9.0] build 20706', interpolated=True),
        0x009250e2: VersionInfo(VIT.EXP, 'VS2008 Beta 2 [9.0] build 20706', interpolated=True),

        # MSVS2005 (RTM.50727-4200) cl version: 14.00.50727.42
        # MSVS2005-SP1 dumps the same comp.id's.
        # It is strange, but there exists VS2012 with the same build number:
        # 11 Build 50727.1
        0x006dc627: VersionInfo(VIT.OBJ, 'VS2005 build 50727'),
        0x006ec627: VersionInfo(VIT.CPP, 'VS2005 build 50727'),
        0x0078c627: VersionInfo(VIT.LNK, 'VS2005 build 50727'),
        0x007cc627: VersionInfo(VIT.RES, 'VS2005 build 50727'),
        0x007ac627: VersionInfo(VIT.EXP, 'VS2005 build 50727'),
        0x007bc627: VersionInfo(VIT.IMP, 'VS2005 build 50727'),
        0x007dc627: VersionInfo(VIT.ASM, 'VS2005 build 50727'),

        # Visual Studio 2005 [8.0] (values are interpolated)
        0x006dc490: VersionInfo(VIT.OBJ, 'VS2005 [8.0] build 50320', interpolated=True),
        0x007dc490: VersionInfo(VIT.ASM, 'VS2005 [8.0] build 50320', interpolated=True),
        0x006ec490: VersionInfo(VIT.CPP, 'VS2005 [8.0] build 50320', interpolated=True),
        0x007cc490: VersionInfo(VIT.RES, 'VS2005 [8.0] build 50320', interpolated=True),
        0x0078c490: VersionInfo(VIT.LNK, 'VS2005 [8.0] build 50320', interpolated=True),
        0x007bc490: VersionInfo(VIT.IMP, 'VS2005 [8.0] build 50320', interpolated=True),
        0x007ac490: VersionInfo(VIT.EXP, 'VS2005 [8.0] build 50320', interpolated=True),

        # Visual Studio 2005 Beta 2 [8.0] (values are interpolated)
        0x006dc427: VersionInfo(VIT.OBJ, 'VS2005 Beta 2 [8.0] build 50215', interpolated=True),
        0x007dc427: VersionInfo(VIT.ASM, 'VS2005 Beta 2 [8.0] build 50215', interpolated=True),
        0x006ec427: VersionInfo(VIT.CPP, 'VS2005 Beta 2 [8.0] build 50215', interpolated=True),
        0x007cc427: VersionInfo(VIT.RES, 'VS2005 Beta 2 [8.0] build 50215', interpolated=True),
        0x0078c427: VersionInfo(VIT.LNK, 'VS2005 Beta 2 [8.0] build 50215', interpolated=True),
        0x007bc427: VersionInfo(VIT.IMP, 'VS2005 Beta 2 [8.0] build 50215', interpolated=True),
        0x007ac427: VersionInfo(VIT.EXP, 'VS2005 Beta 2 [8.0] build 50215', interpolated=True),

        # Visual Studio 2005 Beta 1 [8.0] (values are interpolated)
        0x006d9e9f: VersionInfo(VIT.OBJ, 'VS2005 Beta 1 [8.0] build 40607', interpolated=True),
        0x007d9e9f: VersionInfo(VIT.ASM, 'VS2005 Beta 1 [8.0] build 40607', interpolated=True),
        0x006e9e9f: VersionInfo(VIT.CPP, 'VS2005 Beta 1 [8.0] build 40607', interpolated=True),
        0x007c9e9f: VersionInfo(VIT.RES, 'VS2005 Beta 1 [8.0] build 40607', interpolated=True),
        0x00789e9f: VersionInfo(VIT.LNK, 'VS2005 Beta 1 [8.0] build 40607', interpolated=True),
        0x007b9e9f: VersionInfo(VIT.IMP, 'VS2005 Beta 1 [8.0] build 40607', interpolated=True),
        0x007a9e9f: VersionInfo(VIT.EXP, 'VS2005 Beta 1 [8.0] build 40607', interpolated=True),

        # Windows Server 2003 SP1 DDK (for AMD64) (values are interpolated)
        0x006d9d76: VersionInfo(VIT.OBJ, 'Windows Server 2003 SP1 DDK (for AMD64) build 40310', interpolated=True),
        0x007d9d76: VersionInfo(VIT.ASM, 'Windows Server 2003 SP1 DDK (for AMD64) build 40310', interpolated=True),
        0x006e9d76: VersionInfo(VIT.CPP, 'Windows Server 2003 SP1 DDK (for AMD64) build 40310', interpolated=True),
        0x007c9d76: VersionInfo(VIT.RES, 'Windows Server 2003 SP1 DDK (for AMD64) build 40310', interpolated=True),
        0x00789d76: VersionInfo(VIT.LNK, 'Windows Server 2003 SP1 DDK (for AMD64) build 40310', interpolated=True),
        0x007b9d76: VersionInfo(VIT.IMP, 'Windows Server 2003 SP1 DDK (for AMD64) build 40310', interpolated=True),
        0x007a9d76: VersionInfo(VIT.EXP, 'Windows Server 2003 SP1 DDK (for AMD64) build 40310', interpolated=True),

        # MSVS2003 (.NET) SP1 (kb918007)
        0x005f178e: VersionInfo(VIT.OBJ, 'VS2003 (.NET) SP1 build 6030'),
        0x0060178e: VersionInfo(VIT.CPP, 'VS2003 (.NET) SP1 build 6030'),
        0x005a178e: VersionInfo(VIT.LNK, 'VS2003 (.NET) SP1 build 6030'),
        0x000f178e: VersionInfo(VIT.ASM, 'VS2003 (.NET) SP1 build 6030'),
        # cvtres is the same version as without SP1
        0x005e178e: VersionInfo(VIT.RES, 'VS.NET 2003 SP1 [7.1] build 6030', interpolated=True),
        0x005c178e: VersionInfo(VIT.EXP, 'VS2003 (.NET) SP1 build 6030'),
        0x005d178e: VersionInfo(VIT.IMP, 'VS2003 (.NET) SP1 build 6030'),

        # Windows Server 2003 SP1 DDK (values are interpolated)
        0x005f0fc3: VersionInfo(VIT.OBJ, 'Windows Server 2003 SP1 DDK build 4035', interpolated=True),
        0x000f0fc3: VersionInfo(VIT.ASM, 'Windows Server 2003 SP1 DDK build 4035', interpolated=True),
        0x00600fc3: VersionInfo(VIT.CPP, 'Windows Server 2003 SP1 DDK build 4035', interpolated=True),
        0x005e0fc3: VersionInfo(VIT.RES, 'Windows Server 2003 SP1 DDK build 4035', interpolated=True),
        0x005a0fc3: VersionInfo(VIT.LNK, 'Windows Server 2003 SP1 DDK build 4035', interpolated=True),
        0x005d0fc3: VersionInfo(VIT.IMP, 'Windows Server 2003 SP1 DDK build 4035', interpolated=True),
        0x005c0fc3: VersionInfo(VIT.EXP, 'Windows Server 2003 SP1 DDK build 4035', interpolated=True),

        # MSVS2003 (.NET) 7.0.1.3088
        0x005f0c05: VersionInfo(VIT.OBJ, 'VS2003 (.NET) build 3077'),
        0x00600c05: VersionInfo(VIT.CPP, 'VS2003 (.NET) build 3077'),
        0x000f0c05: VersionInfo(VIT.ASM, 'VS2003 (.NET) build 3077'),
        0x005e0bec: VersionInfo(VIT.RES, 'VS2003 (.NET) build 3052'),
        0x005c0c05: VersionInfo(VIT.EXP, 'VS2003 (.NET) build 3077'),
        0x005d0c05: VersionInfo(VIT.IMP, 'VS2003 (.NET) build 3077'),
        0x005a0c05: VersionInfo(VIT.LNK, 'VS2003 (.NET) build 3077'),
        # Visual Studio .NET 2003 [7.1] (values are interpolated)
        0x005e0c05: VersionInfo(VIT.RES, 'VS.NET 2003 [7.1] build 3077', interpolated=True),

        # MSVS2002 (.NET) 7.0.9466
        0x001c24fa: VersionInfo(VIT.OBJ, 'VS2002 (.NET) build 9466'),
        0x001d24fa: VersionInfo(VIT.CPP, 'VS2002 (.NET) build 9466'),
        0x004024fa: VersionInfo(VIT.ASM, 'VS2002 (.NET) build 9466'),
        0x003d24fa: VersionInfo(VIT.LNK, 'VS2002 (.NET) build 9466'),
        0x004524fa: VersionInfo(VIT.RES, 'VS2002 (.NET) build 9466'),
        0x003f24fa: VersionInfo(VIT.EXP, 'VS2002 (.NET) build 9466'),
        0x001924fa: VersionInfo(VIT.IMP, 'VS2002 (.NET) build 9466'),

        # Windows XP SP1 DDK (values are interpolated)
        0x001c23d8: VersionInfo(VIT.OBJ, 'Windows XP SP1 DDK build 9176', interpolated=True),
        0x004023d8: VersionInfo(VIT.ASM, 'Windows XP SP1 DDK build 9176', interpolated=True),
        0x001d23d8: VersionInfo(VIT.CPP, 'Windows XP SP1 DDK build 9176', interpolated=True),
        0x004523d8: VersionInfo(VIT.RES, 'Windows XP SP1 DDK build 9176', interpolated=True),
        0x003d23d8: VersionInfo(VIT.LNK, 'Windows XP SP1 DDK build 9176', interpolated=True),
        0x001923d8: VersionInfo(VIT.IMP, 'Windows XP SP1 DDK build 9176', interpolated=True),
        0x003f23d8: VersionInfo(VIT.EXP, 'Windows XP SP1 DDK build 9176', interpolated=True),

        # MSVS98 6.0 SP6 (Enterprise edition)
        # Looks like linker may mix compids for C and C++ objects (why?)
        0x000a2636: VersionInfo(VIT.OBJ, 'VS98 (6.0) SP6 build 8804'),
        0x000b2636: VersionInfo(VIT.CPP, 'VS98 (6.0) SP6 build 8804'),

        # MSVC++ 6.0 SP5 (Enterprise edition)
        0x00152306: VersionInfo(VIT.OBJ, 'VC++ 6.0 SP5 build 8804'),
        0x00162306: VersionInfo(VIT.CPP, 'VC++ 6.0 SP5 build 8804'),
        0x000420ff: VersionInfo(VIT.LNK, 'VC++ 6.0 SP5 imp/exp build 8447'),
        0x000606c7: VersionInfo(VIT.RES, 'VS98 (6.0) SP6 cvtres build 1736'),

        # MSVS6.0 (no serVITepacks)
        0x000a1fe8: VersionInfo(VIT.OBJ, 'VS98 (6.0) build 8168'),
        0x000b1fe8: VersionInfo(VIT.CPP, 'VS98 (6.0) build 8168'),
        0x000606b8: VersionInfo(VIT.RES, 'VS98 (6.0) cvtres build 1720'),
        0x00041fe8: VersionInfo(VIT.LNK, 'VS98 (6.0) imp/exp build 8168'),

        # MSVS97 5.0 Enterprise Edition (cl 11.00.7022, link 5.00.7022)
        # Does NOT generate any @comp.id records, nor Rich headers.
        # SP3 added Rich-generating linker (albeit it doesn't identify itself),
        # and CVTRES and LIB(?) utilities that generate @comp.id records. There is no
        # distinction between import and export records yet. I marked the records as
        # [IMP] because VS98 linker seems to omit export records from the header; VS97
        # linker might do the same.
        0x00060684: VersionInfo(VIT.RES, 'VS97 (5.0) SP3 cvtres 5.00.1668'),
        0x00021c87: VersionInfo(VIT.IMP, 'VS97 (5.0) SP3 link 5.10.7303'),
    }
