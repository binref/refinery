#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from ....lib.patterns import formats
from ....lib.tools import lookahead
from . import string_apply, string_unquote
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
                    sample = string[0]
                    if len(sample) > 33:
                        sample = F"{sample[1:30]}...{sample[0]}"
                    return F'found match at {string.start()}: {sample}'

                self.log_debug(dbgmsg)

                args = re.split(F'({formats.ps1str})', argmatch[1])
                args = [list(string_unquote(a.strip())) for a in args[1::2]]

                def formatter(string):
                    buffer = []
                    for k, part in enumerate(re.split(R'(\{\d+\})', string)):
                        if k % 2 == 0:
                            if part:
                                buffer.append(part)
                            continue
                        try:
                            index = int(part[1:-1])
                            arg = args[index]
                        except IndexError as IE:
                            raise IndexError(F'only found {len(args)} arguments and format sequence {index}, aborting.') from IE

                        it = iter(arg)
                        buffer.append(next(it))

                        if len(arg) > 1:
                            yield ''.join(buffer)
                            buffer = []
                            for last, part in lookahead(it):
                                if last:
                                    buffer.append(part)
                                    break
                                yield part

                    yield ''.join(buffer)

                try:
                    result = string_apply(string[0], formatter)
                except IndexError:
                    continue

                data = data[:string.start()] + result + data[argmatch.end() + string.end():]
                repeat = True
                break

        return data
