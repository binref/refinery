from __future__ import annotations

import re

from refinery.lib.deobfuscation import cautious_eval
from refinery.lib.patterns import formats
from refinery.units.obfuscation import Deobfuscator, StringLiterals


class deob_js_arithmetic(Deobfuscator):
    def deobfuscate(self, data):
        strings = StringLiterals(formats.string, data)

        @strings.outside
        def evaluate(match: re.Match[str]):
            expression = match[0]
            expression = expression.strip()
            if not any(c.isdigit() for c in expression):
                return expression
            brackets = 0
            positions = []
            ok = True
            head = tail = rest = ''
            for end, character in enumerate(expression):
                if character == '(':
                    brackets += 1
                    positions.append(end)
                    continue
                if character == ')':
                    brackets -= 1
                    if brackets < 0:
                        expression, tail = expression[:end], expression[end:]
                        break
                    else:
                        positions.pop()
                    if brackets == 0 and expression[0] == '(':
                        expression, rest = expression[:end + 1], expression[end + 1:]
                        break
            if expression.isdigit():
                return match[0]
            if brackets > 0:
                pos = positions[~0] + 1
                head = expression[:pos]
                expression = expression[pos:]
            try:
                result = str(cautious_eval(expression + rest))
            except Exception:
                ok = False
            else:
                rest = ''
            if not ok and rest:
                try:
                    result = str(cautious_eval(expression))
                except Exception:
                    expression += rest
                else:
                    ok = True
            if not ok:
                result = expression
                self.log_info(F'error trying to parse arithmetic expression at offset {match.start()}: ({expression})')
            else:
                if expression.startswith('(') and expression.endswith(')'):
                    result = F'({result})'
            if tail:
                tail = self.deobfuscate(tail)
            return F'{head}{result}{rest}{tail}'

        pattern = re.compile(R'(?:{i}|{f}|[-+(])(?:[^\S\r\n]{{0,20}}(?:{i}|{f}|[-%|&~<>()+/*^]))+'.format(
            i=str(formats.integer), f=str(formats.float)))

        return pattern.sub(evaluate, data)
