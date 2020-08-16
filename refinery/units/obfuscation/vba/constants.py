#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import Deobfuscator
from ....lib.patterns import formats


class deob_vba_constants(Deobfuscator):
    def deobfuscate(self, data):
        codelines = data.splitlines(keepends=True)
        constants = {}
        constline = {}
        variables = set()
        for k, line in enumerate(codelines):
            match = re.match(R'(?im)^\s*(?:sub|function)\s*(\w+)', line)
            if match:
                variables.add(match[1])
                continue
            match = re.match(
                R'(?im)^(?:\s*const)?\s*(\w+)\s*=\s*({i}|{s})\s*(?:\'|rem|$)'.format(
                    s=formats.ps1str,
                    i=formats.integer
                ), line)
            if match is None or match[1] in variables:
                pass
            elif match[2] != constants.get(match[1], match[2]):
                self.log_debug(F'del {match[1]}')
                del constants[match[1]]
                del constline[match[1]]
                variables.add(match[1])
            else:
                self.log_debug(F'add {match[1]} = {match[2]}')
                constants[match[1]] = match[2]
                constline[match[1]] = k
        codelines = [line for k, line in enumerate(codelines) if k not in constline.values()]
        data = ''.join(codelines)
        for name, value in constants.items():
            data = re.sub(RF'\b{re.escape(name)!s}\b', value, data)

        return data
