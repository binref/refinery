from __future__ import annotations

import itertools
import plistlib

from enum import IntEnum
from hashlib import md5
from typing import Iterable

from refinery.lib import lief
from refinery.lib.structures import StreamDetour, Struct, StructReader
from refinery.lib.types import Param
from refinery.units import Arg, Unit
from refinery.units.formats.pe.pemeta import pemeta
from refinery.units.sinks.ppjson import ppjson

CS_ADHOC = 0x0000_0002


class BlobType(IntEnum):
    CODEDIRECTORY                 = 0x00000 # noqa
    INFOSLOT                      = 0x00001 # noqa
    REQUIREMENTS                  = 0x00002 # noqa
    RESOURCEDIR                   = 0x00003 # noqa
    APPLICATION                   = 0x00004 # noqa
    XML_ENTITLEMENTS              = 0x00005 # noqa
    DER_ENTITLEMENTS              = 0x00007 # noqa
    LAUNCH_CONSTRAINT_SELF        = 0x00008 # noqa
    LAUNCH_CONSTRAINT_PARENT      = 0x00009 # noqa
    LAUNCH_CONSTRAINT_RESPONSIBLE = 0x0000A # noqa
    LIBRARY_CONSTRAINT            = 0x0000B # noqa
    ALTERNATE_CODEDIRECTORIES     = 0x01000 # noqa
    CMS_SIGNATURE                 = 0x10000 # noqa


class BlobMagic(IntEnum):
    OneRequirement      = 0xFADE0C00 # noqa
    Requirements        = 0xFADE0C01 # noqa
    CodeDirectory       = 0xFADE0C02 # noqa
    Signature           = 0xFADE0CC0 # noqa
    DetachedSignature   = 0xFADE0CC1 # noqa
    BlobWrapper         = 0xFADE0B01 # noqa
    SignatureOld        = 0xFADE0B02 # noqa
    EntitlementsXML     = 0xFADE7171 # noqa
    EntitlementsDER     = 0xFADE7172 # noqa
    LaunchConstraint    = 0xFADE8181 # noqa


class BlobIndex(Struct):
    def __init__(self, reader: StructReader[memoryview]):
        self.type = reader.u32()
        self.offset = reader.u32()
        with StreamDetour(reader, self.offset):
            pos = reader.tell()
            self.magic = reader.u32()
            length = reader.u32()
            self.data = reader.read(length - reader.tell() + pos)


class SuperBlob(Struct):
    def __init__(self, reader: StructReader[memoryview]):
        magic = reader.read(4)
        if magic == B'\xfa\xde\x0c\xc0':
            reader.bigendian = True
        elif magic != B'\xc0\x0c\xde\xfa':
            raise ValueError
        self.size = reader.u32()
        count = reader.u32()
        self.blobs = [BlobIndex(reader) for _ in range(count)]


class CodeDirectoryBlob(Struct):
    def __init__(self, reader: StructReader[memoryview]):
        reader.bigendian = True
        self.version = reader.u32()
        self.flags = reader.u32()
        self.hashOffset = reader.u32()
        self.identOffset = reader.u32()
        self.nSpecialSlots = reader.u32()
        self.nCodeSlots = reader.u32()
        self.codeLimit = reader.u32()
        self.hashSize = reader.u8()
        self.hashType = reader.u8()
        self.platform = reader.u8()
        self.pageSize = reader.u8()
        self.spare2 = reader.u32()


_CPU_SUBTYPES = {
    lief.MachO.Header.CPU_TYPE.X86: {
        0x03: 'ALL',
        0x04: 'ARCH1',
    },
    lief.MachO.Header.CPU_TYPE.X86_64: {
        0x03: 'ALL',
        0x08: 'H',
    },
    lief.MachO.Header.CPU_TYPE.POWERPC: {
        0x00: 'ALL',
        0x01: '601',
        0x02: '602',
        0x03: '603',
        0x04: '603e',
        0x05: '603ev',
        0x06: '604',
        0x07: '604e',
        0x08: '620',
        0x09: '750',
        0x0A: '7400',
        0x0B: '7450',
        0x64: '970',
    },
    lief.MachO.Header.CPU_TYPE.ARM: {
        0x00: 'ALL',
        0x05: 'V4T',
        0x06: 'V6',
        0x07: 'V5',
        0x08: 'XSCALE',
        0x09: 'V7',
        0x0A: 'ARM_V7F',
        0x0B: 'V7S',
        0x0C: 'V7K',
        0x0E: 'V6M',
        0x0F: 'V7M',
        0x10: 'V7EM',
    },
    lief.MachO.Header.CPU_TYPE.ARM64: {
        0x00: 'ALL',
        0x02: 'ARM64E',
    },
    lief.MachO.Header.CPU_TYPE.SPARC: {
        0x00: 'ALL',
    },
}


class machometa(Unit):
    """
    Extract metadata from Mach-O files.
    """
    def __init__(
        self, all: Param[bool, Arg('-c', '--custom',
            help='Unless enabled, all default categories will be extracted.')] = True,
        header: Param[bool, Arg('-H', help='Parse basic data from the Mach-O header.')] = False,
        linked_images: Param[bool, Arg('-K', help='Parse all library images linked by the Mach-O.')] = False,
        signatures: Param[bool, Arg('-S', help='Parse signature and entitlement information.')] = False,
        version: Param[bool, Arg('-V', help='Parse version information from the Mach-O load commands.')] = False,
        load_commands: Param[bool, Arg('-D', help='Parse load commands from the Mach-O header.')] = False,
        exports: Param[bool, Arg('-E', help='List all exported functions.')] = False,
        imports: Param[bool, Arg('-I', help='List all imported functions.')] = False,
        tabular: Param[bool, Arg('-t', help='Print information in a table rather than as JSON')] = False,
    ):
        super().__init__(
            header=all or header,
            linked_images=all or linked_images,
            version=all or version,
            signatures=all or signatures,
            load_commands=load_commands,
            imports=imports,
            exports=exports,
            tabular=tabular,
        )

    def compute_symhash(self, macho: lief.MachO.Binary) -> dict:
        def _symbols(symbols: Iterable[lief.MachO.Symbol]):
            for sym in symbols:
                if sym.category != lief.MachO.Symbol.CATEGORY.UNDEFINED:
                    continue
                yield lief.string(sym.name)
        symbols = sorted(set(_symbols(macho.symbols)))
        symbols: str = ','.join(symbols)
        return md5(symbols.encode('utf8')).hexdigest()

    def parse_macho_header(self, macho: lief.MachO.Binary, data=None) -> dict:
        info = {}
        if header := macho.header:
            st = header.cpu_subtype & 0x7FFFFFFF
            ht = 'mach_header_64' if header.magic in {
                lief.MachO.MACHO_TYPES.CIGAM_64,
                lief.MachO.MACHO_TYPES.MAGIC_64,
            } else 'mach_header'
            info['Type'] = ht
            info['Magic'] = header.magic.value
            info['CPUType'] = header.cpu_type.__name__.upper()
            info['CPUSubType'] = _CPU_SUBTYPES.get(header.cpu_type, {}).get(st, st)
            info['FileType'] = header.file_type.__name__
            info['LoadCount'] = header.nb_cmds
            info['LoadSize'] = header.sizeof_cmds
            info['Flags'] = sorted(flag.__name__ for flag in header.flags_list)
            info['Reserved'] = header.reserved
        return info

    def parse_linked_images(self, macho: lief.MachO.Binary, data=None) -> dict:
        load_command_images = {}
        load_commands: Iterable[lief.MachO.LoadCommand] = macho.commands
        for load_command in load_commands:
            if not isinstance(load_command, lief.MachO.DylibCommand):
                continue
            images: list[str] = load_command_images.setdefault(load_command.command.__name__, [])
            images.append(load_command.name)
        return load_command_images

    def parse_signature(self, macho_image: lief.MachO.Binary, data=None) -> dict:

        if not macho_image.has_code_signature:
            return {}

        info = {}
        reader = StructReader(macho_image.code_signature.content)
        super_blob = SuperBlob(reader)

        for blob in super_blob.blobs:

            if blob.type == BlobType.CODEDIRECTORY:
                codedirectory_blob = CodeDirectoryBlob.Parse(blob.data)
                if codedirectory_blob.flags & CS_ADHOC != 0:
                    info['AdHocSigned'] = True
                else:
                    info['AdHocSigned'] = False
                reader.seekset(codedirectory_blob.identOffset + blob.offset)
                info['SignatureIdentifier'] = reader.read_c_string('utf8')
                continue

            if blob.type == BlobType.CMS_SIGNATURE:
                reader.seekset(blob.offset)
                cms_signature = blob.data
                if not cms_signature:
                    continue
                try:
                    parsed_cms_signature = pemeta.parse_signature(bytearray(cms_signature))
                    info['Signature'] = parsed_cms_signature
                except ValueError as pkcs7_parse_error:
                    self.log_warn(F'Could not parse the data in CSSLOT_CMS_SIGNATURE as valid PKCS7 data: {pkcs7_parse_error!s}')
                continue

            if blob.type == BlobType.REQUIREMENTS:
                # TODO: Parse the requirements blob,
                # which is encoded according to the code signing requirements language:
                # https://developer.apple.com/library/archive/documentation/Security
                #        /Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html
                info['Requirements'] = blob.data.hex()
                continue

            if blob.type == BlobType.XML_ENTITLEMENTS:
                entitlements = bytes(blob.data)
                if not entitlements:
                    continue
                try:
                    entitlements = plistlib.loads(entitlements)
                except Exception as error:
                    self.log_warn(F'failed to parse entitlements: {error!s}')
                else:
                    info['Entitlements'] = entitlements

        return info

    def parse_version(self, macho: lief.MachO.Binary, data=None) -> dict:
        info = {}
        load_commands: Iterable[lief.MachO.LoadCommand] = macho.commands
        for load_command in load_commands:
            if load_command.command == lief.MachO.LoadCommand.TYPE.SOURCE_VERSION:
                if 'SourceVersion' not in info:
                    cmd: lief.MachO.SourceVersion = load_command
                    info['SourceVersion'] = cmd.version[0]
                else:
                    self.log_warn('More than one load command of type SOURCE_VERSION found; the MachO file is possibly malformed')
                continue
            if load_command.command == lief.MachO.LoadCommand.TYPE.BUILD_VERSION:
                if 'BuildVersion' not in info:
                    cmd: lief.MachO.BuildVersion = load_command
                    info['BuildVersion'] = {}
                    info['BuildVersion']['Platform'] = cmd.platform.__name__
                    info['BuildVersion']['MinOS'] = '.'.join(str(v) for v in cmd.minos)
                    info['BuildVersion']['SDK'] = '.'.join(str(v) for v in cmd.sdk)
                    info['BuildVersion']['Ntools'] = len(cmd.tools)
                else:
                    self.log_warn('More than one load command of type BUILD_VERSION found; the MachO file is possibly malformed')
                continue
        return info

    def parse_load_commands(self, macho: lief.MachO.Binary, data=None) -> list:
        info = []
        load_commands: Iterable[lief.MachO.LoadCommand] = macho.commands
        for load_command in load_commands:
            info.append(dict(
                Type=load_command.command.__name__,
                Size=load_command.size,
                Data=load_command.data.hex(),
            ))
        return info

    def parse_imports(self, macho: lief.MachO.Binary, data=None) -> list:
        info = []
        imports: Iterable[lief.MachO.Symbol] = macho.imported_symbols
        for imp in imports:
            info.append(lief.string(imp.name))
        return info

    def parse_exports(self, macho: lief.MachO.Binary, data=None) -> list:
        info = []
        exports: Iterable[lief.MachO.Symbol] = macho.exported_symbols
        for exp in exports:
            info.append(lief.string(exp.name))
        return info

    def process(self, data: bytearray):
        result = {}
        slices = []
        macho = lief.load_macho(data)
        macho_slices: list[lief.MachO.Binary] = []

        for k in itertools.count():
            if not (ms := macho.at(k)):
                break
            macho_slices.append(ms)

        result['FileType'] = 'FAT' if len(macho_slices) > 1 else 'THIN'

        for image in macho_slices:
            slice_result = {}

            for switch, resolver, name in [
                (self.args.header,          self.parse_macho_header,  'Header'),       # noqa
                (self.args.linked_images,   self.parse_linked_images, 'LinkedImages'), # noqa
                (self.args.signatures,      self.parse_signature,     'Signatures'),   # noqa
                (self.args.version,         self.parse_version,       'Version'),      # noqa
                (self.args.load_commands,   self.parse_load_commands, 'LoadCommands'), # noqa
                (self.args.imports,         self.parse_imports,       'Imports'),      # noqa
                (self.args.exports,         self.parse_exports,       'Exports'),      # noqa
            ]:
                if not switch:
                    continue
                self.log_debug(F'parsing: {name}')
                try:
                    info = resolver(image, data)
                except Exception as E:
                    self.log_info(F'failed to obtain {name}: {E!s}')
                    continue
                if info:
                    slice_result[name] = info

            if image.uuid is not None:
                uuid = bytes(image.uuid.uuid)
                slice_result['UUID'] = uuid.hex()
            slice_result['SymHash'] = self.compute_symhash(image)
            if fileset_name := image.fileset_name:
                slice_result['FilesetName'] = fileset_name
            slices.append(slice_result)

        if slices:
            result['Slices'] = slices
            yield from ppjson(
                tabular=self.args.tabular
            )._pretty_output(result)
