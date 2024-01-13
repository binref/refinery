#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from io import BytesIO
from typing import Dict, List, TYPE_CHECKING

from refinery.units import Arg, Unit
from refinery.units.formats.pe.pemeta import pemeta
from refinery.units.sinks.ppjson import ppjson

if TYPE_CHECKING:
    from ktool import Image
    from ktool.codesign import BlobIndex, SuperBlob


CS_ADHOC = 0x0000_0002


class machometa(Unit):
    """
    Extract metadata from Mach-O files.
    """
    def __init__(
        self, all: Arg('-c', '--custom',
            help='Unless enabled, all default categories will be extracted.') = True,
        header: Arg('-H', help='Parse basic data from the Mach-O header.') = False,
        linked_images: Arg('-K', help='Parse all library images linked by the Mach-O.') = False,
        signatures: Arg('-S', help='Parse signature and entitlement information.') = False,
        version: Arg('-V', help='Parse version information from the Mach-O load commands.') = False,
        load_commands: Arg('-D', help='Parse load commands from the Mach-O header.') = False,
        exports: Arg('-E', help='List all exported functions.') = False,
        imports: Arg('-I', help='List all imported functions.') = False,
        tabular: Arg('-t', help='Print information in a table rather than as JSON') = False,
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

    @Unit.Requires('k2l>=2.0', 'all')
    def _ktool():
        import ktool
        import ktool.macho
        import ktool.codesign
        return ktool

    def parse_macho_header(self, macho_image: Image, data=None) -> Dict:
        info = {}
        macho_header = macho_image.macho_header
        dyld_header = macho_image.macho_header.dyld_header
        if dyld_header is not None:
            info['Type'] = dyld_header.type_name
            info['Magic'] = dyld_header.magic
            info['CPUType'] = macho_image.slice.type.name
            info['CPUSubType'] = macho_image.slice.subtype.name
            info['FileType'] = macho_image.macho_header.filetype.name
            info['LoadCount'] = dyld_header.loadcnt
            info['LoadSize'] = dyld_header.loadsize
            info['Flags'] = [flag.name for flag in macho_header.flags]
            info['Reserved'] = dyld_header.reserved
        return info

    def parse_linked_images(self, macho_image: Image, data=None) -> Dict:
        load_command_images = {}
        linked_images = macho_image.linked_images
        LOAD_COMMAND = self._ktool.macho.LOAD_COMMAND
        for linked_image in linked_images:
            load_command_name = LOAD_COMMAND(linked_image.cmd.cmd).name
            load_command_images.setdefault(load_command_name, []).append(linked_image.install_name)
        return load_command_images

    def parse_signature(self, macho_image: Image, data=None) -> Dict:

        _km = self._ktool.macho
        _kc = self._ktool.codesign

        class CodeDirectoryBlob(_km.Struct):
            FIELDS = {
                'magic': _km.uint32_t,
                'length': _km.uint32_t,
                'version': _km.uint32_t,
                'flags': _km.uint32_t,
                'hashOffset': _km.uint32_t,
                'identOffset': _km.uint32_t,
                'nSpecialSlots': _km.uint32_t,
                'nCodeSlots': _km.uint32_t,
                'codeLimit': _km.uint32_t,
                'hashSize': _km.uint8_t,
                'hashType': _km.uint8_t,
                'platform': _km.uint8_t,
                'pageSize': _km.uint8_t,
                'spare2': _km.uint32_t
            }

            def __init__(self, byte_order='little'):
                super().__init__(byte_order=byte_order)
                self.magic = 0
                self.length = 0
                self.version = 0
                self.flags = 0
                self.hashOffset = 0
                self.identOffset = 0
                self.nSpecialSlots = 0
                self.nCodeSlots = 0
                self.codeLimit = 0
                self.hashSize = 0
                self.hashType = 0
                self.platform = 0
                self.pageSize = 0
                self.spare2 = 0

        info = {}
        if macho_image.codesign_info is not None:
            superblob: SuperBlob = macho_image.codesign_info.superblob

            for blob in macho_image.codesign_info.slots:
                blob: BlobIndex
                # ktool does not include code for extracting Blobs of types
                # CSSLOT_CODEDIRECTORY, CSSLOT_CMS_SIGNATURE
                # so we must do it ourselves here.
                if blob.type == _kc.CSSLOT_CODEDIRECTORY:
                    start = superblob.off + blob.offset
                    codedirectory_blob = macho_image.read_struct(start, CodeDirectoryBlob)

                    # Ad-hoc signing
                    flags = _kc.swap_32(codedirectory_blob.flags)
                    if flags & CS_ADHOC != 0:
                        info['AdHocSigned'] = True
                    else:
                        info['AdHocSigned'] = False

                    # Signature identifier
                    identifier_offset = _kc.swap_32(codedirectory_blob.identOffset)
                    identifier_data = macho_image.read_cstr(start + identifier_offset)
                    info['SignatureIdentifier'] = identifier_data

                if blob.type == 0x10000:  # CSSLOT_CMS_SIGNATURE
                    start = superblob.off + blob.offset
                    blob_data = macho_image.read_struct(start, _kc.Blob)
                    blob_data.magic = _kc.swap_32(blob_data.magic)
                    blob_data.length = _kc.swap_32(blob_data.length)
                    cms_signature = macho_image.read_bytearray(start + _kc.Blob.SIZE, blob_data.length - _kc.Blob.SIZE)

                    if len(cms_signature) != 0:
                        try:
                            parsed_cms_signature = pemeta.parse_signature(bytearray(cms_signature))
                            info['Signature'] = parsed_cms_signature
                        except ValueError as pkcs7_parse_error:
                            self.log_warn(F'Could not parse the data in CSSLOT_CMS_SIGNATURE as valid PKCS7 data: {pkcs7_parse_error!s}')

            if macho_image.codesign_info.req_dat is not None:
                # TODO: Parse the requirements blob,
                # which is encoded according to the code signing requirements language:
                # https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html
                info['Requirements'] = macho_image.codesign_info.req_dat.hex()
            if macho_image.codesign_info.entitlements is not None:
                info['Entitlements'] = macho_image.codesign_info.entitlements
        return info

    def parse_version(self, macho_image: Image, data=None) -> Dict:
        info = {}
        load_commands = macho_image.macho_header.load_commands

        SVC = self._ktool.macho.source_version_command
        BVC = self._ktool.macho.build_version_command

        for load_command in load_commands:
            if isinstance(load_command, SVC):
                if 'SourceVersion' not in info:
                    info['SourceVersion'] = load_command.version
                else:
                    self.log_warn('More than one load command of type source_version_command found; the MachO file is possibly malformed')
            elif isinstance(load_command, BVC):
                if 'BuildVersion' not in info:
                    info['BuildVersion'] = {}
                    info['BuildVersion']['Platform'] = macho_image.platform.name
                    info['BuildVersion']['MinOS'] = F'{macho_image.minos.x}.{macho_image.minos.y}.{macho_image.minos.z}'
                    info['BuildVersion']['SDK'] = F'{macho_image.sdk_version.x}.{macho_image.sdk_version.y}.{macho_image.sdk_version.z}'
                    info['BuildVersion']['Ntools'] = load_command.ntools
                else:
                    self.log_warn('More than one load command of type build_version_command found; the MachO file is possibly malformed')
        return info

    def parse_load_commands(self, macho_image: Image, data=None) -> List:
        info = []
        load_commands = macho_image.macho_header.load_commands
        for load_command in load_commands:
            info.append(load_command.serialize())
        return info

    def parse_imports(self, macho_image: Image, data=None) -> List:
        info = []
        for imp in macho_image.imports:
            info.append(imp.name)
        return info

    def parse_exports(self, macho_image: Image, data=None) -> List:
        info = []
        for exp in macho_image.exports:
            info.append(exp.name)
        return info

    def process(self, data: bytearray):
        result = {}
        ktool = self._ktool
        macho = ktool.load_macho_file(fp=BytesIO(data), use_mmaped_io=False)
        if macho.type is ktool.MachOFileType.FAT:
            result['FileType'] = 'FAT'
        elif macho.type is ktool.MachOFileType.THIN:
            result['FileType'] = 'THIN'

        slices = []

        for macho_slice in macho.slices:
            slice_result = {}
            macho_image = ktool.load_image(fp=macho_slice)

            for switch, resolver, name in [
                (self.args.header, self.parse_macho_header, 'Header'),
                (self.args.linked_images, self.parse_linked_images, 'LinkedImages'),
                (self.args.signatures, self.parse_signature, 'Signatures'),
                (self.args.version, self.parse_version, 'Version'),
                (self.args.load_commands, self.parse_load_commands, 'LoadCommands'),
                (self.args.imports, self.parse_imports, 'Imports'),
                (self.args.exports, self.parse_exports, 'Exports'),
            ]:
                if not switch:
                    continue
                self.log_debug(F'parsing: {name}')
                try:
                    info = resolver(macho_image, data)
                except Exception as E:
                    self.log_info(F'failed to obtain {name}: {E!s}')
                    continue
                if info:
                    slice_result[name] = info

            if macho_image.uuid is not None:
                uuid: bytes = macho_image.uuid
                slice_result['UUID'] = uuid.hex()
            slice_result['BaseName'] = macho_image.base_name
            slice_result['InstallName'] = macho_image.install_name
            slices.append(slice_result)

        if slices:
            result['Slices'] = slices
            yield from ppjson(tabular=self.args.tabular)._pretty_output(result, indent=4, ensure_ascii=False)
