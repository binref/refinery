#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import io
import re

from refinery import Unit
from refinery.lib.vfs import VirtualFileSystem
from refinery.lib.tools import NoLogging


class vbapc(Unit):
    """
    Extract VBA macro p-code from Office documents. By default, the unit also uses pcode2code to
    decompile the disassembled p-code. This unit is specifically useful for macro documents that
    use VBA code stomping, i.e. the embedded macro source code is stomped and does not represent
    the p-code functionality that the document will actually execute.
    """
    def __init__(self, raw: Unit.Arg.Switch('-r', help='Return disassembled p-code, do not try to decompile.') = False):
        super().__init__(raw=raw)

    @Unit.Requires('oletools', 'formats', 'office', 'extended')
    def _pcodedmp():
        with NoLogging():
            import pcodedmp.pcodedmp
            return pcodedmp.pcodedmp

    def process(self, data):
        class args:
            disasmOnly = True
            verbose = False
        with io.StringIO() as output:
            with VirtualFileSystem() as vfs:
                vf = vfs.new(data)
                self._pcodedmp.processFile(vf, args, output)
            code = output.getvalue()
            if not self.args.raw:
                from refinery.lib.thirdparty.pcode2code import Parser
                parser = Parser(code)
                parser.parseInput()
                parser.processInput(False)
                code = parser.getOutput()
                code = re.sub(R'(?m)^((?:Sub|Function).*?)$(?!\n[^\s])', r'\n\1', code)
            return code.encode(self.codec)
