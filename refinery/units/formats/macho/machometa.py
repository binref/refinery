#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from io import BytesIO
from typing import List

from ktool import load_image, Image

from refinery.units import Arg, Unit
from refinery.units.sinks.ppjson import ppjson


class machometa(Unit):
    """
    Extract metadata from Mach-O files.
    """
    def __init__(
        self, all: Arg('-c', '--custom',
            help='Unless enabled, all default categories will be extracted.') = True,
        exports: Arg('-E', help='List all exported functions.') = False,
        imports: Arg('-I', help='List all imported functions.') = False,
        tabular: Arg('-t', help='Print information in a table rather than as JSON') = False,
    ):
        super().__init__(
            imports=imports,
            exports=exports,
            tabular=tabular,
        )
        
    def parse_imports(self, macho: Image, data=None) -> List:
        info = []
        for imp in macho.imports:
            info.append(imp.name)
        return info

    def parse_exports(self, macho: Image, data=None) -> List:
        info = []
        for exp in macho.exports:
            info.append(exp.name)
        return info

    def process(self, data: bytearray):
        result = {}
        macho = load_image(fp=BytesIO(data))

        for switch, resolver, name in [
            (self.args.imports, self.parse_imports, 'Imports'),
            (self.args.exports, self.parse_exports, 'Exports'),
        ]:
            if not switch:
                continue
            self.log_debug(F'parsing: {name}')
            try:
                info = resolver(macho, data)
            except Exception as E:
                self.log_info(F'failed to obtain {name}: {E!s}')
                continue
            if info:
                result[name] = info

        result['Base Name'] = macho.base_name
        result['Install Name'] = macho.install_name

        if result:
            yield from ppjson(tabular=self.args.tabular)._pretty_output(result, indent=4, ensure_ascii=False)
