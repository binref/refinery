#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import Deobfuscator
from ....lib.deobfuscation import cautious_eval_or_default, cautious_eval
from ....lib.patterns import formats


class deob_vba_arithmetic(Deobfuscator):
    def deobfuscate(self, data):

        def evaluate(match):
            match = match[0]
            expr = match.strip()
            brackets = 0
            for end, character in enumerate(expr):
                if character == '(':
                    brackets += 1
                    continue
                if character == ')':
                    brackets -= 1
                    if brackets < 0:
                        expr, tail = expr[:end], expr[end:]
                        break
            else:
                tail = ''
            if expr.isdigit() or brackets > 0:
                return match
            if self.log_debug('evaluating', expr):
                evaluator = cautious_eval
            else:
                def evaluator(e): return cautious_eval_or_default(e, e)
            result = str(evaluator(expr)) + self.deobfuscate(tail)
            if expr.startswith('(') and expr.endswith(')'):
                result = F'({result})'
            return result

        pattern = re.compile(R'(?:{i}|{f}|[-+(])(?:[^\S\r\n]{{0,20}}(?:{i}|{f}|[-%|&~<>()+/*^]))+'.format(
            i=str(formats.integer), f=str(formats.float)))

        return pattern.sub(evaluate, data)
