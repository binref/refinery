#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import Deobfuscator
from ....lib.patterns import formats


class deob_vba_dummy_variables(Deobfuscator):
    def deobfuscate(self, data):
        lines = data.splitlines(keepends=False)
        keeps = {}

        def might_be_used_in(name, line):
            # avoid finding the name within a string literal
            line = '""'.join(re.split(str(formats.ps1str), line))
            line = re.split(RF'\b{name}\b', line)
            try:
                L, R = line
            except ValueError:
                return False
            L = L.strip().lower()
            if L.startswith("'") or L.startswith('rem'):
                return False
            R = R.strip().lower()
            if R.startswith('=') and 'if' not in L:
                return False
            if L.startswith('dim'):
                return False
            return True

        pattern = re.compile(
            R'^\s{0,8}(?:const\s{1,8})?(\w+)\s{1,8}=\s{1,8}.*$',
            flags=re.IGNORECASE
        )

        for k, current_line in enumerate(lines):
            try:
                name = pattern.match(current_line).group(1)
            except AttributeError:
                continue
            used_somewhere = False
            for j, line in enumerate(lines):
                if might_be_used_in(name, line):
                    used_somewhere = keeps[j] = True
            if not used_somewhere and not keeps.get(k, False):
                keeps[k] = False

        return '\n'.join(line for k, line in enumerate(lines) if keeps.get(k, True))
