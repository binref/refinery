#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from contextlib import suppress
from io import BytesIO
from typing import Dict, List

from ktool import load_image, load_macho_file, Image, MachOFileType
from ktool.macho import build_version_command, LOAD_COMMAND, source_version_command, Struct, uint8_t, uint32_t
from ktool.codesign import Blob, BlobIndex, CSSLOT_CODEDIRECTORY, SuperBlob, swap_32

from refinery.units import Arg, Unit
from refinery.units.sinks.ppjson import ppjson


class CodeDirectoryBlob(Struct):
    _FIELDNAMES = [
        "magic",
        "length",
        "version",
        "flags",
        "hashOffset",
        "identOffset",
        "nSpecialSlots",
        "nCodeSlots",
        "codeLimit",
        "hashSize",
        "hashType",
        "platform",
        "pageSize",
        "spare2"
    ]
    _SIZES = [
        uint32_t,
        uint32_t,
        uint32_t,
        uint32_t,
        uint32_t,
        uint32_t,
        uint32_t,
        uint32_t,
        uint32_t,
        uint8_t,
        uint8_t,
        uint8_t,
        uint8_t,
        uint32_t
    ]
    SIZE = 44

    def __init__(self, byte_order="little"):
        super().__init__(fields=self._FIELDNAMES, sizes=self._SIZES, byte_order=byte_order)
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
        version: Arg('-V', help="Parse version information from the Mach-O load commands.") = False,
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

    @classmethod
    def parse_pkcs7_signature(cls, data: bytearray) -> dict:
        """
        Extracts a JSON-serializable and human readable dictionary with information about
        time stamp and code signing certificates.
        Shamelessly copied directly from the pemeta unit.
        """
        from refinery.units.formats.pkcs7 import pkcs7

        try:
            signature = data | pkcs7 | json.loads
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
                            info.update(ProgramName=attr['value']['programName'])
                            info.update(MoreInfo=attr['value']['moreInfo'])
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

    def parse_macho_header(self, macho_image: Image, data=None) -> Dict:
        info = {}
        macho_header = macho_image.macho_header
        dyld_header = macho_image.macho_header.dyld_header
        if dyld_header is not None:
            info['type'] = dyld_header.typename()
            info['magic'] = dyld_header.magic
            info['cputype'] = macho_image.slice.type.name
            info['cpusubtype'] = macho_image.slice.subtype.name
            info['filetype'] = macho_image.macho_header.filetype.name
            info['loadcount'] = dyld_header.loadcnt
            info['loadsize'] = dyld_header.loadsize
            info['flags'] = [flag.name for flag in macho_header.flags]
            info['reserved'] = dyld_header.reserved
        return info

    def parse_linked_images(self, macho_image: Image, data=None) -> Dict:
        load_command_images = {}
        linked_images = macho_image.linked_images
        for linked_image in linked_images:
            load_command_name = LOAD_COMMAND(linked_image.cmd.cmd).name
            load_command_images.setdefault(load_command_name, []).append(linked_image.install_name)
        return load_command_images

    def parse_signature(self, macho_image: Image, data=None) -> Dict:
        info = {}
        if macho_image.codesign_info is not None:
            superblob: SuperBlob = macho_image.codesign_info.superblob

            for blob in macho_image.codesign_info.slots:
                blob: BlobIndex
                # ktool does not include code for extracting Blobs of types
                # CSSLOT_CODEDIRECTORY, CSSLOT_CMS_SIGNATURE
                # so we must do it ourselves here.
                if blob.type == CSSLOT_CODEDIRECTORY:
                    start = superblob.off + blob.offset
                    codedirectory_blob = macho_image.load_struct(start, CodeDirectoryBlob)

                    # Ad-hoc signing
                    flags = swap_32(codedirectory_blob.flags)
                    if flags & CS_ADHOC != 0:
                        info['Ad-Hoc Signed'] = True
                    else:
                        info['Ad-Hoc Signed'] = False

                    # Signature identifier
                    identifier_offset = swap_32(codedirectory_blob.identOffset)
                    identifier_data = macho_image.get_cstr_at(start + identifier_offset)
                    info['Signature Identifier'] = identifier_data

                if blob.type == 0x10000:  # CSSLOT_CMS_SIGNATURE
                    start = superblob.off + blob.offset
                    blob_data = macho_image.load_struct(start, Blob)
                    blob_data.magic = swap_32(blob_data.magic)
                    blob_data.length = swap_32(blob_data.length)
                    cms_signature = macho_image.get_bytes_at(start + Blob.SIZE, blob_data.length - Blob.SIZE)

                    # TODO: We may want to handle malformed signatures a bit better here.
                    # In particular, we want to make sure we can still get the signature identifier field
                    # (from CSSLOT_CODEDIRECTORY above) even if the data here in CSSLOT_CMS_SIGNATURE
                    # cannot be parsed as a valid PKCS7 blob.
                    if len(cms_signature) != 0:
                        parsed_cms_signature = self.parse_pkcs7_signature(bytearray(cms_signature))
                        info['Signature'] = parsed_cms_signature

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
        for load_command in load_commands:
            if isinstance(load_command, source_version_command):
                info["SourceVersion"] = load_command.version
            elif isinstance(load_command, build_version_command):
                info["BuildVersion"] = {}
                info["BuildVersion"]["Platform"] = load_command.platform
                info["BuildVersion"]["MinOS"] = load_command.minos
                info["BuildVersion"]["SDK"] = load_command.sdk
                info["BuildVersion"]["Ntools"] = load_command.ntools
        self.log_debug(info)
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
        macho = load_macho_file(fp=BytesIO(data), use_mmaped_io=False)
        if macho.type is MachOFileType.FAT:
            result['FileType'] = 'FAT'
        elif macho.type is MachOFileType.THIN:
            result['FileType'] = 'THIN'

        result['Slices'] = []

        for macho_slice in macho.slices:
            slice_result = {}
            macho_image = load_image(fp=macho_slice)

            for switch, resolver, name in [
                (self.args.header, self.parse_macho_header, 'Header'),
                (self.args.linked_images, self.parse_linked_images, 'Linked Images'),
                (self.args.signatures, self.parse_signature, 'Signatures'),
                (self.args.version, self.parse_version, 'Version'),
                (self.args.load_commands, self.parse_load_commands, 'Load Commands'),
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
            slice_result['Base Name'] = macho_image.base_name
            slice_result['Install Name'] = macho_image.install_name

            result['Slices'].append(slice_result)

        if result:
            yield from ppjson(tabular=self.args.tabular)._pretty_output(result, indent=4, ensure_ascii=False)
