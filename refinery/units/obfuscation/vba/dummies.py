#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import collections
import re

from .. import Deobfuscator
from ....lib.patterns import formats


class deob_vba_dummy_variables(Deobfuscator):
    def deobfuscate(self, data):
        lines = data.splitlines(keepends=False)
        names = collections.defaultdict(list)

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

        for k, line in enumerate(lines):
            try:
                name = pattern.match(line)[1]
            except (AttributeError, TypeError):
                continue
            names[name].append(k)

        for line in lines:
            while True:
                for name in names:
                    if might_be_used_in(name, line):
                        del names[name]
                        break
                else:
                    break

        return '\n'.join(line for k, line in enumerate(lines) if not any(
            k in rows for rows in names.values()))
