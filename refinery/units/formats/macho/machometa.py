#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from io import BytesIO
from typing import Dict, List

from ktool import load_image, load_macho_file, Image, MachOFileType
from ktool.macho import build_version_command, source_version_command

from refinery.units import Arg, Unit
from refinery.units.sinks.ppjson import ppjson


class machometa(Unit):
    """
    Extract metadata from Mach-O files.
    """
    def __init__(
        self, all: Arg('-c', '--custom',
            help='Unless enabled, all default categories will be extracted.') = True,
        header: Arg('-H', help='Parse basic data from the Mach-O header.') = False,
        linked_images: Arg('-K', help='Parse all library images linked by the Mach-O.') = False,
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
            load_commands=load_commands,
            imports=imports,
            exports=exports,
            tabular=tabular,
        )

    def parse_macho_header(self, macho_image: Image, data=None) -> Dict:
        info = {}
        dyld_header = macho_image.macho_header.dyld_header
        if dyld_header is not None:
            info = dyld_header.serialize()
        return info

    def parse_linked_images(self, macho_image: Image, data=None) -> List:
        info = []
        linked_images = macho_image.linked_images
        for linked_image in linked_images:
            info.append(linked_image.serialize())
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
