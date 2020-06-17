#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import Deobfuscator


class deob_vba_constants(Deobfuscator):
    def deobfuscate(self, data):
        def extract_constants(lines):
            for line in lines:
                match = re.match(R'(?i)^\s*const\s*(\w+)\s*=\s*(.*?)(?:\'|rem|$)', line)
                if match is None:
                    yield line
                    continue
                constants[match[1]] = match[2]
                self.log_debug(F'const {match[1]} = {match[2]}')

        constants = {}
        data = '\n'.join(extract_constants(data.splitlines(keepends=False)))
        for name, value in constants.items():
            data = re.sub(RF'\b{re.escape(name)!s}\b', value, data)

        return data
