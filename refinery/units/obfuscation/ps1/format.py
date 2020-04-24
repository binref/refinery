#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from ....lib.patterns import formats
from . import string_unquote, string_quote, Ps1StringLiterals
from .. import Deobfuscator


class deob_ps1_format(Deobfuscator):
    """
    PowerShell deobfuscation for the following "format string"-based technique:

    - `"{0}{2}{1}"-f 'signa','ures','t'`
    - `"{0}na{2}{1}"-f 'sig','ures','t'`
    """

    def deobfuscate(self, data):

        repeat = True

        while repeat:

            repeat = False

            for string in re.finditer(str(formats.ps1str), data):
                argmatch = re.search(R'^\s*-[fF]\s*((?:{s},\s*)*{s})'.format(s=formats.ps1str), data[string.end():])
                if not argmatch:
                    continue

                def dbgmsg():
                    sample = string.group(0)
                    if len(sample) > 33:
                        sample = F"{sample[1:30]}...{sample[0]}"
                    return F'found match at {string.start()}: {sample}'

                self.log_debug(dbgmsg)

                args = re.split(F'({formats.ps1str})', argmatch.group(1))
                args = [
                    string_unquote(a.strip())
                    for a in args[1::2]
                ]

                def argreplace(m):
                    try:
                        index = int(m.group(1))
                        return args[index]
                    except IndexError:
                        self.log_debug(F'only found {len(args)} arguments and format sequence {index}, aborting.')
                        raise
                try:
                    substitution = string_quote(re.sub(R'\{(\d+)\}', argreplace, string_unquote(string.group(0))))
                except IndexError:
                    continue

                data = data[:string.start()] + substitution + data[argmatch.end() + string.end():]
                repeat = True
                break

        return data
