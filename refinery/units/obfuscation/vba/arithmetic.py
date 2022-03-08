#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
import re

from refinery.units.obfuscation import Deobfuscator, StringLiterals
from refinery.lib.deobfuscation import ExpressionParsingFailure, cautious_eval
from refinery.lib.patterns import formats


class deob_vba_arithmetic(Deobfuscator):
    def deobfuscate(self, data):
        strings = StringLiterals(formats.vbastr, data)

        def vba_int_eval(match: re.Match[str]) -> str:
            s = match[0].lower()
            if not s.startswith('&'):
                return s
            t, s = s[1], s[2:].rstrip('&')
            if t == 'h':
                return str(int(s, 16))
            if t == 'b':
                return str(int(s, 2))
            if t == 'o':
                return str(int(s, 8))

        @strings.outside
        def evaluate(match: re.Match[str]):
            expression = match[0]
            expression = expression.strip()
            if not any(c.isdigit() for c in expression):
                return expression
            expression = re.sub(str(formats.vbaint), vba_int_eval, expression)
            brackets = 0
            for end, character in enumerate(expression):
                if character == '(':
                    brackets += 1
                    continue
                if character == ')':
                    brackets -= 1
                    if brackets < 0:
                        expression, tail = expression[:end], expression[end:]
                        break
            else:
                tail = ''
            if expression.isdigit() or brackets > 0:
                return expression
            try:
                result = str(cautious_eval(expression)) + self.deobfuscate(tail)
            except ExpressionParsingFailure:
                result = expression
                self.log_warn(F'error trying to parse arithmetic expression at offset {match.start()}: ({expression})')
            else:
                if expression.startswith('(') and expression.endswith(')'):
                    result = F'({result})'
            return result

        pattern = re.compile(R'(?:{i}|{f}|[-+(])(?:[^\S\r\n]{{0,20}}(?:{i}|{f}|[-%|&~<>()+/*^]))+'.format(
            i=str(formats.vbaint), f=str(formats.float)))

        return pattern.sub(evaluate, data)
