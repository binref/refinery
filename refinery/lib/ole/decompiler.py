"""
VBA p-code decompiler that converts pcodedmp disassembly text back to VBA source code. This module
is based on pcode2code by Nicolas Zilio (@Big5_sec), originally available at:
https://github.com/Big5-sec/pcode2code

Copyright (C) 2019 Nicolas Zilio
Licensed under the GNU General Public License v3.0 or later.

The code was substantially rewritten for use within Binary Refinery, but remains subject to the
original GPL license.
"""
from __future__ import annotations

import re
import struct

from typing import Callable


class PCodeDecompilerError(Exception):
    """
    Custom exception for p-code decompilation failures.
    """


class VBAStack:
    """
    Typed wrapper around a list used as a stack for VBA p-code decompilation. Popping from an
    empty stack returns an empty string rather than raising an exception.
    """

    def __init__(self):
        self._items: list[str] = []

    def pop(self) -> str:
        if not self._items:
            return ''
        return self._items.pop()

    def push(self, item: str) -> None:
        self._items.append(item)

    def size(self) -> int:
        return len(self._items)

    def top(self) -> str:
        return self._items[-1]

    def bottom(self) -> str:
        return self._items[0]

    def clear(self) -> None:
        self._items.clear()

    def drain(self) -> list[str]:
        """
        Pop all items and return them in bottom-to-top order.
        """
        items = list(reversed(self._items))
        self._items.clear()
        items.reverse()
        return items


class VBADecompiler:
    """
    Executes VBA p-code opcodes against a stack to reconstruct VBA source text. Each opcode name
    maps to a handler via the internal dispatch dictionary.
    """

    def __init__(self, stack: VBAStack):
        self._stack = stack
        self.indent_level: int = 0
        self.indent_increase_pending: bool = False
        self.has_bos: bool = False
        self.one_line_if: bool = False
        self.unindented: int = 0

        self._dispatch: dict[str, Callable] = self._build_dispatch()

    def _binary_op(self, operator: str) -> None:
        rhs = self._stack.pop()
        lhs = self._stack.pop()
        self._stack.push(f'{lhs} {operator} {rhs}')

    def _unary_prefix(self, prefix: str) -> None:
        self._stack.push(F'{prefix}{self._stack.pop()}')

    def _unary_fn(self, name: str) -> None:
        self._stack.push(f'{name}({self._stack.pop()})')

    def _pop_params(self, num_hex: str) -> list[str]:
        n = int(num_hex, 16)
        params: list[str] = []
        for _ in range(n):
            params.append(self._stack.pop())
        params.reverse()
        return params

    def _join_params(self, params: list[str]) -> str:
        return ', '.join(params)

    def _args_ld_pattern(
        self, prefix: str, suffix: str, num_hex: str
    ) -> None:
        params = self._pop_params(num_hex)
        self._stack.push(prefix + self._join_params(params) + suffix)

    def _mem_access(self, separator: str, var: str) -> None:
        self._stack.push(self._stack.pop() + separator + var)

    def _with_access(self, separator: str, var: str) -> None:
        self._stack.push(separator + var)

    def _redim_body(
        self, args: list[str], obj_prefix: str = ''
    ) -> str:
        preserve = False
        if args and args[0] == '(Preserve)':
            args.pop(0)
            preserve = True

        var_name = args[0]
        # args[1] is num_params hex, not used beyond triggering the pop

        values = self._stack.drain()

        if values and values[0].startswith('ReDim'):
            val = F'{values.pop(0)}, {obj_prefix}{var_name}('
        else:
            val = 'ReDim '
            if preserve:
                val += 'Preserve '
            val += F'{obj_prefix}{var_name}('

        first1 = values.pop(0)
        first2 = values.pop(0)
        if first1 == 'OptionBase':
            val += first2
        else:
            val += F'{first1} To {first2}'

        while values:
            val += ', '
            v1 = values.pop(0)
            v2 = values.pop(0)
            if v1 == 'OptionBase':
                val += v2
            else:
                val += F'{v1} To {v2}'

        val += ')'
        return val

    def _redim_as_suffix(self, args: list[str]) -> str:
        remaining = args[2:]
        if remaining and remaining[-1] != 'Variant)':
            return F' {remaining[0][1:]} {remaining[1][:-1]}'
        return ''

    def _collect_print_elements(self) -> str:
        elmts = self._stack.drain()
        val = elmts[0]
        for elmt in elmts[1:]:
            if elmt in (';', ',') and elmts.index(elmt) != 1:
                val += elmt
            else:
                val += F' {elmt}'
        return val

    def _collect_print_simple(self) -> str:
        elmts = self._stack.drain()
        val = elmts[0]
        for elmt in elmts[1:]:
            val += F' {elmt}'
        return val

    def _op_imp(self) -> None:
        self._binary_op('Imp')

    def _op_eqv(self) -> None:
        self._binary_op('Eqv')

    def _op_xor(self) -> None:
        self._binary_op('Xor')

    def _op_or(self) -> None:
        self._binary_op('Or')

    def _op_and(self) -> None:
        self._binary_op('And')

    def _op_eq(self) -> None:
        self._binary_op('=')

    def _op_ne(self) -> None:
        self._binary_op('<>')

    def _op_le(self) -> None:
        self._binary_op('<=')

    def _op_ge(self) -> None:
        self._binary_op('>=')

    def _op_lt(self) -> None:
        self._binary_op('<')

    def _op_gt(self) -> None:
        self._binary_op('>')

    def _op_add(self) -> None:
        self._binary_op('+')

    def _op_sub(self) -> None:
        self._binary_op('-')

    def _op_mod(self) -> None:
        self._binary_op('Mod')

    def _op_idiv(self) -> None:
        self._binary_op('\\')

    def _op_mul(self) -> None:
        self._binary_op('*')

    def _op_div(self) -> None:
        self._binary_op('/')

    def _op_concat(self) -> None:
        self._binary_op('&')

    def _op_like(self) -> None:
        self._binary_op('Like')

    def _op_pwr(self) -> None:
        self._binary_op('^')

    def _op_is(self) -> None:
        self._binary_op('Is')

    def _op_not(self) -> None:
        self._unary_prefix('Not ')

    def _op_umi(self) -> None:
        self._unary_prefix('-')

    def _op_fnabs(self) -> None:
        self._unary_fn('Abs')

    def _op_fnfix(self) -> None:
        self._unary_fn('Fix')

    def _op_fnint(self) -> None:
        self._unary_fn('int')

    def _op_fnsgn(self) -> None:
        self._unary_fn('Sgn')

    def _op_fnlen(self) -> None:
        self._unary_fn('Len')

    def _op_fnlenb(self) -> None:
        self._unary_fn('LenB')

    def _op_paren(self) -> None:
        self._stack.push(F'({self._stack.pop()})')

    def _op_sharp(self) -> None:
        self._stack.push(F'#{self._stack.pop()}')

    def _op_ldlhs(self) -> None:
        raise PCodeDecompilerError('not implemented: LdLHS')

    def _op_ld(self, var: str) -> None:
        if var == 'id_FFFF':
            var = 'Me'
        self._stack.push(var)

    def _op_memld(self, var: str) -> None:
        self._mem_access('.', var)

    def _op_dictld(self, var: str) -> None:
        self._mem_access('!', var)

    def _op_indexld(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: IndexLd')

    def _op_argsld(self, varname: str, numparams: str) -> None:
        params = self._pop_params(numparams)
        self._stack.push(F'{varname}({self._join_params(params)})')

    def _op_argsmemld(self, var: str, numparams: str) -> None:
        obj = self._stack.pop()
        params = self._pop_params(numparams)
        self._stack.push(F'{obj}.{var}({self._join_params(params)})')

    def _op_argsdictld(self, var: str, numparams: str) -> None:
        obj = self._stack.pop()
        params = self._pop_params(numparams)
        self._stack.push(F'{obj}!{var}({self._join_params(params)})')

    def _op_st(self, arg: str) -> None:
        self._stack.push(F'{arg} = {self._stack.pop()}')

    def _op_memst(self, var: str) -> None:
        obj = F'{self._stack.pop()}.{var}'
        self._stack.push(F'{obj} = {self._stack.pop()}')

    def _op_dictst(self, var: str) -> None:
        obj = self._stack.pop()
        self._stack.push(F'{obj}!{var} = {self._stack.pop()}')

    def _op_indexst(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: IndexSt')

    def _op_argsst(self, var: str, numparams: str) -> None:
        params = self._pop_params(numparams)
        val = F'{var}({self._join_params(params)}) = {self._stack.pop()}'
        self._stack.push(val)

    def _op_argsmemst(self, var: str, numparams: str) -> None:
        obj = F'{self._stack.pop()}.'
        params = self._pop_params(numparams)
        val = F'{obj}{var}({self._join_params(params)}) = {self._stack.pop()}'
        self._stack.push(val)

    def _op_argsdictst(self, var: str, numparams: str) -> None:
        obj = F'{self._stack.pop()}!'
        params = self._pop_params(numparams)
        val = F'{obj}{var}({self._join_params(params)}) = {self._stack.pop()}'
        self._stack.push(val)

    def _op_set(self, var: str) -> None:
        self._stack.push(F'Set {var} = {self._stack.pop()}')

    def _op_memset(self, var: str) -> None:
        obj = self._stack.pop()
        self._stack.push(F'Set {obj}.{var} = {self._stack.pop()}')

    def _op_dictset(self, var: str) -> None:
        obj = self._stack.pop()
        self._stack.push(F'Set {obj}!{var} = {self._stack.pop()}')

    def _op_indexset(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: IndexSet')

    def _op_argsset(self, var: str, nb: str) -> None:
        arg = self._stack.pop()
        self._stack.push(F'Set {var}({arg}) = {self._stack.pop()}')

    def _op_argsmemset(self, var: str, numparams: str) -> None:
        obj = self._stack.pop()
        params = self._pop_params(numparams)
        joined = self._join_params(params)
        val = F'Set {obj}.{var}({joined}) = {self._stack.pop()}'
        self._stack.push(val)

    def _op_argsdictset(self, var: str, numparams: str) -> None:
        obj = self._stack.pop()
        params = self._pop_params(numparams)
        joined = self._join_params(params)
        val = F'Set {obj}!{var}({joined}) = {self._stack.pop()}'
        self._stack.push(val)

    def _op_memldwith(self, var: str) -> None:
        self._with_access('.', var)

    def _op_dictldwith(self, var: str) -> None:
        self._with_access('!', var)

    def _op_argsmemldwith(self, var: str, numparams: str) -> None:
        params = self._pop_params(numparams)
        self._stack.push(F'.{var}({self._join_params(params)})')

    def _op_argsdictldwith(self, var: str, numparams: str) -> None:
        params = self._pop_params(numparams)
        self._stack.push(F'!{var}({self._join_params(params)})')

    def _op_memstwith(self, var: str) -> None:
        self._stack.push(F'.{var} = {self._stack.pop()}')

    def _op_dictstwith(self, var: str) -> None:
        self._stack.push(F'!{var} = {self._stack.pop()}')

    def _op_argsmemstwith(self, var: str, numparams: str) -> None:
        params = self._pop_params(numparams)
        val = F'.{var}({self._join_params(params)}) = {self._stack.pop()}'
        self._stack.push(val)

    def _op_argsdictstwith(self, var: str, *args: str) -> None:
        self._stack.push(F'!{var} = {self._stack.pop()}')

    def _op_memsetwith(self, var: str) -> None:
        self._stack.push(F'Set .{var} = {self._stack.pop()}')

    def _op_dictsetwith(self, var: str) -> None:
        self._stack.push(F'Set !{var} = {self._stack.pop()}')

    def _op_argsmemsetwith(self, var: str, numparams: str) -> None:
        params = self._pop_params(numparams)
        val = F'Set !{var}({self._join_params(params)}) = {self._stack.pop()}'
        self._stack.push(val)

    def _op_argsdictsetwith(self, var: str, numparams: str) -> None:
        params = self._pop_params(numparams)
        val = F'Set !{var}({self._join_params(params)}) = {self._stack.pop()}'
        self._stack.push(val)

    def _op_argscall(self, *args: str) -> None:
        args_list = list(args)
        if args_list[0] == '(Call)':
            nb = int(args_list[2], 16)
            val = F'Call {args_list[1]}('
            end_val = ')'
        else:
            val = args_list[0]
            nb = int(args_list[1], 16)
            end_val = ''

        params: list[str] = []
        for _ in range(nb):
            params.append(self._stack.pop())
        params.reverse()

        if params:
            if params[0].startswith('(') or args_list[0] == '(Call)':
                val += params[0]
            else:
                val += F' {params[0]}'
            for p in params[1:]:
                val += F', {p}'
            val += end_val
        self._stack.push(val)

    def _op_argsmemcall(self, *args: str) -> None:
        args_list = list(args)
        parenthesis = False
        if args_list[0] == '(Call)':
            args_list.pop(0)
            val = F'Call {self._stack.pop()}.{args_list[0]}('
            parenthesis = True
        else:
            val = F'{self._stack.pop()}.{args_list[0]}'

        nb = int(args_list[1], 16)
        end_val = ''

        params: list[str] = []
        for _ in range(nb):
            params.append(self._stack.pop())
        params.reverse()

        if params:
            if params[0].startswith('('):
                val += params[0]
                end_val = ')'
            elif not parenthesis:
                val += F' {params[0]}'
            else:
                val += params[0]
            for p in params[1:]:
                val += F', {p}'

        if parenthesis:
            end_val = ')'
        self._stack.push(val + end_val)

    def _op_argsmemcallwith(self, *args: str) -> None:
        args_list = list(args)
        parenthesis = False
        if args_list[0] == '(Call)':
            args_list.pop(0)
            parenthesis = True
            val = F'Call .{args_list[0]}('
        else:
            val = F'.{args_list[0]}'

        nb = int(args_list[1], 16)
        end_val = ''

        params: list[str] = []
        for _ in range(nb):
            params.append(self._stack.pop())
        params.reverse()

        if params:
            if params[0].startswith('('):
                val += params[0]
                end_val = ')'
            elif not parenthesis:
                val += F' {params[0]}'
            else:
                val += params[0]
            for p in params[1:]:
                val += F', {p}'

        if parenthesis:
            end_val = ')'
        self._stack.push(val + end_val)

    def _op_argsarray(self, var: str, numparams: str) -> None:
        params = self._pop_params(numparams)
        self._stack.push(F'{var}({self._join_params(params)})')

    def _op_assert(self) -> None:
        self._stack.push(F'Debug.Assert {self._stack.pop()}')

    def _op_bos(self, valarg: str) -> None:
        arg = int(valarg, 16)
        if arg == 0:
            self._stack.push(F'{self._stack.pop()}:')
        self.has_bos = True

    def _op_bosimplicit(self, *args: str) -> None:
        self.has_bos = True

    def _op_bol(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: BoL')

    def _op_ldaddressof(self, var: str) -> None:
        self._stack.push(F'AddressOf {var}')

    def _op_memaddressof(self, var: str) -> None:
        self._stack.push(F'AddressOf {self._stack.pop()}.{var}')

    def _op_case(self) -> None:
        self._stack.push(F'Case {self._stack.pop()}')

    def _op_caseto(self) -> None:
        upper = self._stack.pop()
        self._stack.push(F'Case {self._stack.pop()} To {upper}')

    def _op_casegt(self) -> None:
        self._stack.push(F'Case Is > {self._stack.pop()}')

    def _op_caselt(self) -> None:
        self._stack.push(F'Case Is < {self._stack.pop()}')

    def _op_casege(self) -> None:
        self._stack.push(F'Case Is >= {self._stack.pop()}')

    def _op_casele(self) -> None:
        self._stack.push(F'Case Is <= {self._stack.pop()}')

    def _op_casene(self) -> None:
        self._stack.push(F'Case Is <> {self._stack.pop()}')

    def _op_caseeq(self) -> None:
        self._stack.push(F'Case Is = {self._stack.pop()}')

    def _op_caseelse(self) -> None:
        self._stack.push('Case Else')

    def _op_casedone(self) -> None:
        pass

    def _op_circle(self, _unused: str) -> None:
        obj = self._stack.pop()
        params: list[str] = []
        for _ in range(7):
            params.append(self._stack.pop())
        params.reverse()

        val = F'{obj}.Circle ({params[0]}, {params[1]}), {params[2]}'

        trailing = params[3:]
        if all(p == '0' for p in trailing):
            self._stack.push(val)
        else:
            for p in trailing:
                if p == '0':
                    val += ', <tbr>'
                else:
                    val += F', {p}'
            val = val.replace(', <tbr>', '')
            self._stack.push(val)

    def _op_close(self, numparams: str) -> None:
        params = self._pop_params(numparams)
        self._stack.push(F'Close {self._join_params(params)}')

    def _op_closeall(self) -> None:
        self._stack.push('Close')

    _COERCE_MAP: dict[str, str] = {
        '(Str)': 'CStr', '(Var)': 'CVar', '(Sng)': 'CSng',
        '(Lng)': 'CLng', '(Int)': 'CInt', '(Dbl)': 'CDbl',
        '(Date)': 'CDate', '(Cur)': 'CCur', '(Byte)': 'CByte',
        '(Bool)': 'CBool',
    }

    def _op_coerce(self, arg: str) -> None:
        fn = self._COERCE_MAP.get(arg)
        if fn is None:
            raise PCodeDecompilerError(f'not implemented coerce type: {arg}')
        self._stack.push(F'{fn}({self._stack.pop()})')

    def _op_coercevar(self, arg: str) -> None:
        if arg == '(Err)':
            self._stack.push(F'CVErr({self._stack.pop()})')
        else:
            raise PCodeDecompilerError(f'not implemented coercevar type: {arg}')

    def _op_context(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: Context')

    def _op_debug(self) -> None:
        self._stack.push('Debug')

    def _op_deftype(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: DefType')

    def _op_dim(self, *args: str) -> None:
        if args:
            val = ' '.join(args)
            val = val[1:-1]
        else:
            val = 'Dim'
        self._stack.push(val)

    def _op_dimimplicit(self) -> None:
        self._stack.push('DimImplicit')

    def _op_do(self) -> None:
        self._stack.push('Do')
        self.indent_increase_pending = True

    def _op_doevents(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: DoEvents')

    def _op_dounitil(self) -> None:
        self._stack.push(F'Do Until {self._stack.pop()}')
        self.indent_increase_pending = True

    def _op_dowhile(self) -> None:
        self._stack.push(F'Do While {self._stack.pop()}')
        self.indent_increase_pending = True

    def _op_else(self) -> None:
        self._stack.push('Else')

    def _op_elseblock(self) -> None:
        self._stack.push('Else')
        self.indent_level -= 1
        self.indent_increase_pending = True

    def _op_elseifblock(self) -> None:
        self._stack.push(F'ElseIf {self._stack.pop()} Then')
        self.indent_level -= 1
        self.indent_increase_pending = True

    def _op_elseiftypeblock(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: ElseIfTypeBlock')

    def _op_end(self) -> None:
        self._stack.push('End')

    def _op_endcontext(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: EndContext')

    def _op_endfunc(self) -> None:
        self._stack.push('End Function')
        self.indent_level -= 1

    def _op_endif(self) -> None:
        if self.one_line_if:
            self.one_line_if = False
        else:
            self._stack.push('End If')
            self.indent_level -= 1

    def _op_endifblock(self) -> None:
        self._stack.push('End If')
        self.indent_level -= 1

    def _op_endimmediate(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: EndImmediate')

    def _op_endprop(self) -> None:
        self._stack.push('End Property')
        self.indent_level -= 1

    def _op_endselect(self) -> None:
        self._stack.push('End Select')
        self.indent_level -= 1

    def _op_endsub(self) -> None:
        self._stack.push('End Sub')
        self.indent_level -= 1

    def _op_endtype(self) -> None:
        self._stack.push('End Type')
        self.indent_level -= 1

    def _op_endwith(self) -> None:
        self._stack.push('End With')
        self.indent_level -= 1

    def _op_erase(self, nb_params: str) -> None:
        nb = int(nb_params, 16)
        params: list[str] = []
        for _ in range(nb):
            params.append(self._stack.pop())
            params.reverse()
        val = ', '.join(params)
        self._stack.push(F'Erase {val}')

    def _op_error(self) -> None:
        self._stack.push(F'Error {self._stack.pop()}')

    def _op_eventdecl(self, *args: str) -> None:
        val = args[1]
        for a in args[2:-1]:
            val += F' {a}'
        self._stack.push(F'Event {val} {args[-1][:-1]}')

    def _op_raiseevent(
        self, evt_name: str, nb_params: str
    ) -> None:
        nb = int(nb_params, 16)
        params: list[str] = []
        suffix = ''
        if nb > 0:
            for _ in range(nb):
                params.append(self._stack.pop())
            params.reverse()
            suffix = F'({self._join_params(params)})'
        self._stack.push(F'RaiseEvent {evt_name}{suffix}')

    def _op_argsmemraiseevent(
        self, var: str, numparams: str
    ) -> None:
        nb = int(numparams, 16)
        obj = self._stack.pop()
        val = F'RaiseEvent {obj}.{var}('
        params: list[str] = []
        if nb > 0:
            for _ in range(nb):
                params.append(self._stack.pop())
            params.reverse()
            val += self._join_params(params) + ')'
        self._stack.push(val)

    def _op_argsmemraiseeventwith(
        self, var: str, numparams: str
    ) -> None:
        nb = int(numparams, 16)
        val = F'RaiseEvent .{var}('
        params: list[str] = []
        if nb > 0:
            for _ in range(nb):
                params.append(self._stack.pop())
            params.reverse()
            val += self._join_params(params) + ')'
        self._stack.push(val)

    def _op_exitdo(self) -> None:
        self._stack.push('Exit Do')

    def _op_exitfor(self) -> None:
        self._stack.push('Exit For')

    def _op_exitfunc(self) -> None:
        self._stack.push('Exit Function')

    def _op_exitprop(self) -> None:
        self._stack.push('Exit Property')

    def _op_exitsub(self) -> None:
        self._stack.push('Exit Sub')

    def _op_fncurdir(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: FnCurDir')

    def _op_fndir(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: FnDir')

    def _op_empty0(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: Empty0')

    def _op_empty1(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: Empty1')

    def _op_fnerror(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: FnError')

    def _op_fnformat(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: FnFormat')

    def _op_fnfreefile(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: FnFreeFile')

    def _op_fninstr(self) -> None:
        arg2 = self._stack.pop()
        arg1 = self._stack.pop()
        self._stack.push(f'Instr({arg1}, {arg2})')

    def _op_fninstr3(self) -> None:
        a3 = self._stack.pop()
        a2 = self._stack.pop()
        a1 = self._stack.pop()
        self._stack.push(f'Instr({a1}, {a2}, {a3})')

    def _op_fninstr4(self) -> None:
        a4 = self._stack.pop()
        a3 = self._stack.pop()
        a2 = self._stack.pop()
        a1 = self._stack.pop()
        self._stack.push(f'Instr({a1}, {a2}, {a3}, {a4})')

    def _op_fninstrb(self) -> None:
        arg2 = self._stack.pop()
        arg1 = self._stack.pop()
        self._stack.push(f'InstrB({arg1}, {arg2})')

    def _op_fninstrb3(self) -> None:
        a3 = self._stack.pop()
        a2 = self._stack.pop()
        a1 = self._stack.pop()
        self._stack.push(f'InstrB({a1}, {a2}, {a3})')

    def _op_fninstrb4(self) -> None:
        a4 = self._stack.pop()
        a3 = self._stack.pop()
        a2 = self._stack.pop()
        a1 = self._stack.pop()
        self._stack.push(f'Instr({a1}, {a2}, {a3}, {a4})')

    def _op_fnlbound(self, arg: str) -> None:
        n = int(arg, 16) + 1
        params: list[str] = []
        for _ in range(n):
            params.append(self._stack.pop())
        params.reverse()
        self._stack.push(F'LBound({self._join_params(params)})')

    def _op_fnmid(self) -> None:
        self._unary_fn('Mid')

    def _op_fnmidb(self) -> None:
        self._unary_fn('MidB')

    def _op_fnstrcomp(self) -> None:
        s2 = self._stack.pop()
        s1 = self._stack.pop()
        self._stack.push(f'StrComp({s1}, {s2})')

    def _op_fnstrcomp3(self) -> None:
        a3 = self._stack.pop()
        s2 = self._stack.pop()
        s1 = self._stack.pop()
        self._stack.push(f'StrComp({s1}, {s2}, {a3})')

    def _op_fnstringvar(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: FnStringVar')

    def _op_fnstringstr(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: FnStringStr')

    def _op_fnubound(self, arg: str) -> None:
        n = int(arg, 16) + 1
        params: list[str] = []
        for _ in range(n):
            params.append(self._stack.pop())
        params.reverse()
        self._stack.push(F'UBound({self._join_params(params)})')

    def _op_for(self) -> None:
        maxvar = self._stack.pop()
        minvar = self._stack.pop()
        loopvar = self._stack.pop()
        self._stack.push(f'For {loopvar} = {minvar} To {maxvar}')
        self.indent_increase_pending = True

    def _op_foreach(self) -> None:
        collect = self._stack.pop()
        loopvar = self._stack.pop()
        self._stack.push(f'For Each {loopvar} In {collect}')
        self.indent_increase_pending = True

    def _op_foreachas(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: ForEachAs')

    def _op_forstep(self) -> None:
        step = self._stack.pop()
        maxvar = self._stack.pop()
        minvar = self._stack.pop()
        loopvar = self._stack.pop()
        self._stack.push(
            f'For {loopvar} = {minvar} To {maxvar}'
            f' Step {step}')
        self.indent_increase_pending = True

    def _op_funcdefn(self, *args: str) -> None:
        val = ' '.join(args)
        val = val[1:-1]
        self._stack.push(val)
        if not val.startswith('Declare'):
            self.indent_increase_pending = True

    def _op_funcdefnsave(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: FuncDefnSave')

    def _op_getrec(self) -> None:
        record = self._stack.pop()
        record_num = self._stack.pop()
        chan = self._stack.pop()
        if chan:
            self._stack.push(f'Get {chan}, {record_num}, {record}')
        else:
            self._stack.push(f'Get {record_num}, , {record}')

    def _op_gosub(self, var: str) -> None:
        self._stack.push(F'GoSub {var}')

    def _op_goto(self, var: str) -> None:
        self._stack.push(F'GoTo {var}')

    def _op_if(self, *args: str) -> None:
        self._stack.push(F'If {self._stack.pop()} Then')
        self.one_line_if = True

    def _op_ifblock(self) -> None:
        self._stack.push(F'If {self._stack.pop()} Then')
        self.indent_increase_pending = True

    def _op_typeof(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: TypeOf')

    def _op_iftypeblock(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: IfTypeBlock')

    def _op_implements(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: Implements')

    def _op_input(self) -> None:
        self._stack.push(F'Input {self._stack.pop()}')

    def _op_inputdone(self) -> None:
        elmts = self._stack.drain()
        val = elmts[0]
        for e in elmts[1:]:
            val += e
        self._stack.push(val)

    def _op_inputitem(self) -> None:
        self._stack.push(F', {self._stack.pop()}')

    def _op_label(self, arg: str) -> None:
        self._stack.push(F'{arg}:')

    def _op_let(self, *args: str) -> None:
        self._stack.push('Let')
        self.has_bos = True

    def _op_line(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: Line')

    def _op_linecont(self, *args: str) -> None:
        pass

    def _op_lineinput(self) -> None:
        var = self._stack.pop()
        num_file = self._stack.pop()
        self._stack.push(f'Line Input #{num_file}, {var}')

    def _op_linenum(self, *args: str) -> None:
        return

    def _op_litcy(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: LitCy')

    def _op_litdate(self, *args: str) -> None:
        raise PCodeDecompilerError(
            'a date literal is defined here but cannot be'
            ' reconstructed from the p-code')

    def _op_litdefault(self) -> None:
        pass

    def _op_litdi2(self, value: str) -> None:
        self._stack.push(str(int(value, 16)))

    def _op_litdi4(self, byte1: str, byte2: str) -> None:
        val = int(byte2 + byte1[2:], 16)
        self._stack.push(str(val))

    def _op_litdi8(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: LitDI8')

    def _op_lithi2(self, byte: str) -> None:
        val = byte[2:]
        while val.startswith('0') and len(val) > 1:
            val = val[1:]
        self._stack.push(F'&H{val}')

    def _op_lithi4(self, byte1: str, byte2: str) -> None:
        val = byte2[2:] + byte1[2:]
        while val.startswith('0') and len(val) > 1:
            val = val[1:]
        self._stack.push(F'&H{val}')

    def _op_lithi8(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: LitHI8')

    def _op_litnothing(self) -> None:
        self._stack.push('Nothing')

    def _op_litoi2(self, value: str) -> None:
        v = int(value, 16)
        self._stack.push(F'&O{oct(v)[2:]}')

    def _op_litoi4(self, byte1: str, byte2: str) -> None:
        val = byte2[2:] + byte1[2:]
        v = int(val, 16)
        self._stack.push(F'&O{oct(v)[2:]}')

    def _op_litoi8(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: LitOI8')

    def _op_litr4(self, byte1: str, byte2: str) -> None:
        hexstr = byte2[2:] + byte1[2:]
        value = struct.unpack('!f', bytes.fromhex(hexstr))[0]
        self._stack.push(str(value))

    def _op_litr8(
        self, b1: str, b2: str, b3: str, b4: str
    ) -> None:
        hexstr = b4[2:] + b3[2:] + b2[2:] + b1[2:]
        value = struct.unpack('!d', bytes.fromhex(hexstr))[0]
        self._stack.push(str(value))

    def _op_litsmalli2(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: LitSmallI2')

    def _op_litstr(self, mylen: str, *args: str) -> None:
        val = ' '.join(args)
        if len(val) >= 2:
            val = val[1:-1]
            val = val.replace('"', '""')
            val = F'"{val}"'
        self._stack.push(val)

    def _op_litvarspecial(self, var: str) -> None:
        self._stack.push(var[1:-1])

    def _op_lock(self) -> None:
        sz = self._stack.size()
        if sz == 3:
            last = self._stack.pop()
            first = self._stack.pop()
            chan = self._stack.pop()
            self._stack.push(f'Lock {chan}, {first} To {last}')
        elif sz == 2:
            rec = self._stack.pop()
            chan = self._stack.pop()
            self._stack.push(f'Lock {chan}, {rec}')
        elif sz == 1:
            self._stack.push(F'Lock {self._stack.pop()}')

    def _op_loop(self) -> None:
        self._stack.push('Loop')
        self.indent_level -= 1

    def _op_loopuntil(self) -> None:
        self._stack.push(F'Loop Until {self._stack.pop()}')
        self.indent_level -= 1

    def _op_loopwhile(self) -> None:
        self._stack.push(F'Loop While {self._stack.pop()}')
        self.indent_level -= 1

    def _op_lset(self) -> None:
        var = self._stack.pop()
        val = self._stack.pop()
        self._stack.push(f'LSet {var} = {val}')

    def _op_me(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: Me')

    def _op_meimplicit(self, *args: str) -> None:
        self._stack.push('MeImplicit')

    def _op_memredim(self, *args: str) -> None:
        obj = self._stack.pop()
        args_list = list(args)
        preserve = False
        if args_list[0] == '(Preserve)':
            args_list.pop(0)
            preserve = True

        values = self._stack.drain()

        if values and values[0].startswith('ReDim'):
            val = F'{values.pop(0)}, {obj}.{args_list[0]}('
        else:
            val = 'ReDim '
            if preserve:
                val += 'Preserve '
            val += F'{obj}.{args_list[0]}('

        v1 = values.pop(0)
        v2 = values.pop(0)
        if v1 == 'OptionBase':
            val += v2
        else:
            val += F'{v1} To {v2}'

        while values:
            val += ', '
            v1 = values.pop(0)
            v2 = values.pop(0)
            if v1 == 'OptionBase':
                val += v2
            else:
                val += F'{v1} To {v2}'

        val += ')'
        self._stack.push(val)

    def _op_memredimwith(self, *args: str) -> None:
        args_list = list(args)
        preserve = False
        if args_list[0] == '(Preserve)':
            args_list.pop(0)
            preserve = True

        values = self._stack.drain()

        if values and values[0].startswith('ReDim'):
            val = F'{values.pop(0)}, .{args_list[0]}('
        else:
            val = 'ReDim '
            if preserve:
                val += 'Preserve '
            val += F'.{args_list[0]}('

        v1 = values.pop(0)
        v2 = values.pop(0)
        if v1 == 'OptionBase':
            val += v2
        else:
            val += F'{v1} To {v2}'

        while values:
            val += ', '
            v1 = values.pop(0)
            v2 = values.pop(0)
            if v1 == 'OptionBase':
                val += v2
            else:
                val += F'{v1} To {v2}'

        val += ')'
        self._stack.push(val)

    def _op_memredimas(self, *args: str) -> None:
        obj = self._stack.pop()
        args_list = list(args)
        preserve = False
        if args_list[0] == '(Preserve)':
            args_list.pop(0)
            preserve = True

        values = self._stack.drain()

        if values and values[0].startswith('ReDim'):
            val = F'{values.pop(0)}, {obj}.{args_list[0]}('
        else:
            val = 'ReDim '
            if preserve:
                val += 'Preserve '
            val += F'{obj}.{args_list[0]}('

        v1 = values.pop(0)
        v2 = values.pop(0)
        if v1 == 'OptionBase':
            val += v2
        else:
            val += F'{v1} To {v2}'

        while values:
            val += ', '
            v1 = values.pop(0)
            v2 = values.pop(0)
            if v1 == 'OptionBase':
                val += v2
            else:
                val += F'{v1} To {v2}'

        val += ')'

        remaining = args_list[2:]
        if remaining and remaining[-1] != 'Variant)':
            val += F' {remaining[0][1:]} {remaining[1][:-1]}'
        self._stack.push(val)

    def _op_memredimaswith(self, *args: str) -> None:
        args_list = list(args)
        preserve = False
        if args_list[0] == '(Preserve)':
            args_list.pop(0)
            preserve = True

        values = self._stack.drain()

        if values and values[0].startswith('ReDim'):
            val = F'{values.pop(0)}, .{args_list[0]}('
        else:
            val = 'ReDim '
            if preserve:
                val += 'Preserve '
            val += F'.{args_list[0]}('

        v1 = values.pop(0)
        v2 = values.pop(0)
        if v1 == 'OptionBase':
            val += v2
        else:
            val += F'{v1} To {v2}'

        while values:
            val += ', '
            v1 = values.pop(0)
            v2 = values.pop(0)
            if v1 == 'OptionBase':
                val += v2
            else:
                val += F'{v1} To {v2}'

        val += ')'

        remaining = args_list[2:]
        if remaining and remaining[-1] != 'Variant)':
            val += F' {remaining[0][1:]} {remaining[1][:-1]}'
        self._stack.push(val)

    def _op_mid(self) -> None:
        if self._stack.size() > 3:
            length = self._stack.pop()
            start = self._stack.pop()
            obj = self._stack.pop()
            rhs = self._stack.pop()
            self._stack.push(f'Mid({obj}, {start}, {length}) = {rhs}')
        else:
            start = self._stack.pop()
            obj = self._stack.pop()
            rhs = self._stack.pop()
            self._stack.push(f'Mid({obj}, {start}) = {rhs}')

    def _op_midb(self) -> None:
        if self._stack.size() > 3:
            length = self._stack.pop()
            start = self._stack.pop()
            obj = self._stack.pop()
            rhs = self._stack.pop()
            self._stack.push(f'MidB({obj}, {start}, {length}) = {rhs}')
        else:
            start = self._stack.pop()
            obj = self._stack.pop()
            rhs = self._stack.pop()
            self._stack.push(f'MidB({obj}, {start}) = {rhs}')

    def _op_name(self) -> None:
        newname = self._stack.pop()
        oldname = self._stack.pop()
        self._stack.push(f'Name {oldname} As {newname}')

    def _op_new(self, var: str) -> None:
        self._stack.push(F'New {var}')

    def _op_next(self) -> None:
        self._stack.push('Next')
        self.indent_level -= 1
        self.indent_increase_pending = False

    def _op_nextvar(self) -> None:
        self._stack.push(F'Next {self._stack.pop()}')
        self.indent_level -= 1

    def _op_onerror(self, *args: str) -> None:
        if args[0] == '(Resume':
            self._stack.push('On Error Resume Next')
        elif args[0] == '(GoTo':
            self._stack.push('On Error GoTo 0')
        else:
            self._stack.push(F'On Error GoTo {args[0]}')

    def _op_ongosub(self, nb: str, *args: str) -> None:
        val = F'On {self._stack.pop()} GoSub '
        self._stack.push(val + ' '.join(args))

    def _op_ongoto(self, nb: str, *args: str) -> None:
        val = F'On {self._stack.pop()} GoTo '
        self._stack.push(val + ' '.join(args))

    def _op_open(self, *args: str) -> None:
        chan = self._stack.pop()
        mode = args[0][1:]
        for a in args[1:]:
            mode += F' {a}'
        mode = mode[:-1]
        filename = self._stack.pop()
        self._stack.push(f'Open {filename} {mode} As {chan}')

    def _op_option(self, *args: str) -> None:
        val = args[0][1:]
        if len(args) > 1:
            for a in args[1:]:
                val += F' {a}'
        self._stack.push(F'Option {val[:-1]}')

    def _op_optionbase(self) -> None:
        self._stack.push('OptionBase')

    def _op_parambyval(self) -> None:
        self._stack.push(F'ByVal {self._stack.pop()}')

    def _op_paramomitted(self) -> None:
        self._stack.push('')

    def _op_paramnamed(self, var: str) -> None:
        self._stack.push(F'{var}:={self._stack.pop()}')

    def _op_printchan(self) -> None:
        self._stack.push(F'Print {self._stack.pop()},')

    def _op_printcomma(self, *args: str) -> None:
        self._stack.push(',')

    def _op_printeos(self) -> None:
        self._stack.push(self._collect_print_elements())

    def _op_printitemcomma(self) -> None:
        self._stack.push(self._collect_print_simple() + ',')

    def _op_printitemnl(self) -> None:
        self._stack.push(self._collect_print_elements())

    def _op_printitemsemi(self) -> None:
        self._stack.push(self._collect_print_simple() + ';')

    def _op_printnl(self) -> None:
        self._stack.push(self._collect_print_simple())

    def _op_printobj(self) -> None:
        if self._stack.top() == 'MeImplicit':
            self._stack.pop()
            self._stack.push('Print')
        else:
            self._stack.push(F'{self._stack.pop()}.Print')

    def _op_printsemi(self, *args: str) -> None:
        self._stack.push(';')

    def _op_printspc(self) -> None:
        self._stack.push(F'Spc({self._stack.pop()})')

    def _op_printtab(self, *args: str) -> None:
        self._stack.push(F'Tab({self._stack.pop()})')

    def _op_printtabcomma(self) -> None:
        self._stack.push('Tab')

    def _op_pset(self, numparams: str) -> None:
        obj = self._stack.pop()
        first_arg = self._stack.pop()
        nb = int(numparams, 16)

        val = F'{obj}.PSet('
        if first_arg != '0':
            val += F'{first_arg}, '

        params: list[str] = []
        for _ in range(nb):
            params.append(self._stack.pop())
        params.reverse()

        if params:
            val += params[0]
            for p in params[1:]:
                val += F', {p}'
        val += ')'
        self._stack.push(val)

    def _op_putrec(self) -> None:
        record = self._stack.pop()
        record_num = self._stack.pop()
        chan = self._stack.pop()
        self._stack.push(f'Put {chan}, {record_num}, {record}')

    def _op_quoterem(
        self, val1: str, lenvar: str, *args: str
    ) -> None:
        val = F"'{args[0][1:]}"
        for a in args[1:]:
            val += F' {a}'
        val = val[:-1]
        if self._stack.size() != 0:
            val = F'{self._stack.pop()} {val}'
        self._stack.push(val)

    def _op_redim(self, *args: str) -> None:
        args_list = list(args)
        preserve = False
        if args_list[0] == '(Preserve)':
            args_list.pop(0)
            preserve = True

        values = self._stack.drain()

        if values and values[0].startswith('ReDim'):
            val = F'{values.pop(0)}, {args_list[0]}('
        else:
            val = 'ReDim '
            if preserve:
                val += 'Preserve '
            val += F'{args_list[0]}('

        v1 = values.pop(0)
        v2 = values.pop(0)
        if v1 == 'OptionBase':
            val += v2
        else:
            val += F'{v1} To {v2}'

        while values:
            val += ', '
            v1 = values.pop(0)
            v2 = values.pop(0)
            if v1 == 'OptionBase':
                val += v2
            else:
                val += F'{v1} To {v2}'

        val += ')'
        self._stack.push(val)

    def _op_redimas(self, *args: str) -> None:
        args_list = list(args)
        preserve = False
        if args_list[0] == '(Preserve)':
            args_list.pop(0)
            preserve = True

        values = self._stack.drain()

        if values and values[0].startswith('ReDim'):
            val = F'{values.pop(0)}, {args_list[0]}('
        else:
            val = 'ReDim '
            if preserve:
                val += 'Preserve '
            val += F'{args_list[0]}('

        v1 = values.pop(0)
        v2 = values.pop(0)
        if v1 == 'OptionBase':
            val += v2
        else:
            val += F'{v1} To {v2}'

        while values:
            val += ', '
            v1 = values.pop(0)
            v2 = values.pop(0)
            if v1 == 'OptionBase':
                val += v2
            else:
                val += F'{v1} To {v2}'

        val += ')'

        remaining = args_list[2:]
        if remaining and remaining[-1] != 'Variant)':
            val += F' {remaining[0][1:]} {remaining[1][:-1]}'
        self._stack.push(val)

    def _op_reparse(self, *args: str) -> None:
        val = args[1][1:]
        for a in args[2:]:
            val += F' {a}'
        val = val[:-1]
        self._stack.push(val)

    def _op_rem(self, *args: str) -> None:
        val = args[2]
        for a in args[3:]:
            val += F' {a}'
        val = val[:-1]
        self._stack.push(F'Rem {val}')

    def _op_resume(self, *args: str) -> None:
        if not args:
            self._stack.push('Resume')
        elif args[0] == '(Next)':
            self._stack.push('Resume Next')
        else:
            self._stack.push(F'Resume {args[0]}')

    def _op_return(self) -> None:
        self._stack.push('Return')

    def _op_rset(self) -> None:
        var = self._stack.pop()
        val = self._stack.pop()
        self._stack.push(f'RSet {var} = {val}')

    def _op_scale(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: Scale')

    def _op_seek(self) -> None:
        data = self._stack.pop()
        self._stack.push(F'Seek {self._stack.pop()}, {data}')

    def _op_selectcase(self) -> None:
        self._stack.push(F'Select Case {self._stack.pop()}')
        self.indent_increase_pending = True

    def _op_selectis(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: SelectIs')

    def _op_selecttype(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: SelectType')

    def _op_setstmt(self) -> None:
        pass

    def _op_stack(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: Stack')

    def _op_stop(self) -> None:
        self._stack.push('Stop')

    def _op_type(self, *args: str) -> None:
        if args[0] == '(Private)':
            self._stack.push(F'Private Type {args[1]}')
        elif args[0] == '(Public)':
            self._stack.push(F'Public Type {args[1]}')
        else:
            self._stack.push(F'Type {args[0]}')
        self.indent_increase_pending = True

    def _op_unlock(self) -> None:
        sz = self._stack.size()
        if sz == 3:
            last = self._stack.pop()
            first = self._stack.pop()
            chan = self._stack.pop()
            self._stack.push(f'Unlock {chan}, {first} To {last}')
        elif sz == 2:
            rec = self._stack.pop()
            chan = self._stack.pop()
            self._stack.push(f'Unlock {chan}, {rec}')
        elif sz == 1:
            self._stack.push(F'Unlock {self._stack.pop()}')

    def _op_vardefn(self, *args: str) -> None:
        args_list = list(args)
        ending = ''

        if args_list[0] == '(WithEvents)':
            var = F'{args_list.pop(0)[1:-1]} {args_list.pop(0)}'
        else:
            var = args_list.pop(0)

        if args_list:
            if args_list[-1].startswith('0x'):
                args_list.pop(-1)
            if args_list:
                ending = F' {args_list[0]}'
                for a in args_list[1:]:
                    ending += F' {a}'
                ending = F' {" ".join(args_list)[1:-1]}'

        stacktop = self._stack.pop()

        if stacktop == 'DimImplicit':
            self._stack.push(F'{var}{ending}')
            return

        decls = [
            'Dim', 'Private', 'Public', 'Protected', 'Friend',
            'Protected Friend', 'Shared', 'Shadows', 'Static',
            'ReadOnly',
        ]
        if stacktop in decls:
            self._stack.push(F'{stacktop} {var}{ending}')
            return

        self._stack.push(stacktop)
        values = self._stack.drain()

        if len(values) == 1:
            for decl in decls:
                if values[0].startswith(decl):
                    self._stack.push(F'{values[0]}, {var}{ending}')
                    return

        if 'Const' in values[0]:
            decl_part = values.pop(0)
            end_val = F' = {values.pop(0)}'
            if values:
                raise PCodeDecompilerError('undefined variable declaration')
            self._stack.push(F'{decl_part} {var}{ending}{end_val}')
            return

        val = ''
        if values[0] in decls:
            val += F'{values.pop(0)} {var}('
        elif values[0] == 'DimImplicit':
            values.pop(0)
            val += var + '('
        else:
            prev_decl = False
            for decl in decls:
                if values[0].startswith(decl):
                    val += F'{values.pop(0)}, {var}('
                    prev_decl = True
                    break
            if not prev_decl:
                val += var + '('

        v1 = values.pop(0)
        v2 = values.pop(0)
        if v1 == 'OptionBase':
            val += v2
        else:
            val += F'{v1} To {v2}'

        while values:
            val += ', '
            v1 = values.pop(0)
            v2 = values.pop(0)
            if v1 == 'OptionBase':
                val += v2
            else:
                val += F'{v1} To {v2}'

        val += F'){ending}'
        self._stack.push(val)

    def _op_wend(self) -> None:
        self._stack.push('Wend')
        self.indent_level -= 1

    def _op_while(self) -> None:
        self._stack.push(F'While {self._stack.pop()}')
        self.indent_increase_pending = True

    def _op_with(self) -> None:
        self._stack.push(F'With {self._stack.pop()}')
        self.indent_increase_pending = True

    def _op_writechan(self) -> None:
        self._stack.push(F'Write {self._stack.pop()},')

    def _op_constfuncexpr(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: ConstFuncExpr')

    def _op_lbconst(self, var: str) -> None:
        self._stack.push(F'#Const {var} = {self._stack.pop()}')

    def _op_lbif(self) -> None:
        self._stack.push(F'#If {self._stack.pop()} Then')
        self.indent_increase_pending = True

    def _op_lbelse(self) -> None:
        self._stack.push('#Else')
        self.indent_level -= 1
        self.indent_increase_pending = True

    def _op_lbelseif(self) -> None:
        self._stack.push(F'#ElseIf {self._stack.pop()} Then')
        self.indent_level -= 1
        self.indent_increase_pending = True

    def _op_lbendif(self) -> None:
        self._stack.push('#End If')
        self.indent_level -= 1

    def _op_lbmark(self) -> None:
        pass

    def _op_endforvariable(self) -> None:
        pass

    def _op_startforvariable(self) -> None:
        pass

    def _op_newredim(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: NewRedim')

    def _op_startwithexpr(self) -> None:
        pass

    def _op_setorst(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: SetOrSt')

    def _op_endenum(self) -> None:
        self._stack.push('End Enum')
        self.indent_level -= 1

    def _op_illegal(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: Illegal')

    def _op_newline(self) -> None:
        self._stack.push('')

    def _build_dispatch(self) -> dict[str, Callable]:
        return {
            'Imp'                   : self._op_imp,
            'Eqv'                   : self._op_eqv,
            'Xor'                   : self._op_xor,
            'Or'                    : self._op_or,
            'And'                   : self._op_and,
            'Eq'                    : self._op_eq,
            'Ne'                    : self._op_ne,
            'Le'                    : self._op_le,
            'Ge'                    : self._op_ge,
            'Lt'                    : self._op_lt,
            'Gt'                    : self._op_gt,
            'Add'                   : self._op_add,
            'Sub'                   : self._op_sub,
            'Mod'                   : self._op_mod,
            'IDiv'                  : self._op_idiv,
            'Mul'                   : self._op_mul,
            'Div'                   : self._op_div,
            'Concat'                : self._op_concat,
            'Like'                  : self._op_like,
            'Pwr'                   : self._op_pwr,
            'Is'                    : self._op_is,
            'Not'                   : self._op_not,
            'UMi'                   : self._op_umi,
            'FnAbs'                 : self._op_fnabs,
            'FnFix'                 : self._op_fnfix,
            'FnInt'                 : self._op_fnint,
            'FnSgn'                 : self._op_fnsgn,
            'FnLen'                 : self._op_fnlen,
            'FnLenB'                : self._op_fnlenb,
            'Paren'                 : self._op_paren,
            'Sharp'                 : self._op_sharp,
            'LdLHS'                 : self._op_ldlhs,
            'Ld'                    : self._op_ld,
            'MemLd'                 : self._op_memld,
            'DictLd'                : self._op_dictld,
            'IndexLd'               : self._op_indexld,
            'ArgsLd'                : self._op_argsld,
            'ArgsMemLd'             : self._op_argsmemld,
            'ArgsDictLd'            : self._op_argsdictld,
            'St'                    : self._op_st,
            'MemSt'                 : self._op_memst,
            'DictSt'                : self._op_dictst,
            'IndexSt'               : self._op_indexst,
            'ArgsSt'                : self._op_argsst,
            'ArgsMemSt'             : self._op_argsmemst,
            'ArgsDictSt'            : self._op_argsdictst,
            'Set'                   : self._op_set,
            'Memset'                : self._op_memset,
            'Dictset'               : self._op_dictset,
            'Indexset'              : self._op_indexset,
            'ArgsSet'               : self._op_argsset,
            'ArgsMemSet'            : self._op_argsmemset,
            'ArgsDictSet'           : self._op_argsdictset,
            'MemLdWith'             : self._op_memldwith,
            'DictLdWith'            : self._op_dictldwith,
            'ArgsMemLdWith'         : self._op_argsmemldwith,
            'ArgsDictLdWith'        : self._op_argsdictldwith,
            'MemStWith'             : self._op_memstwith,
            'DictStWith'            : self._op_dictstwith,
            'ArgsMemStWith'         : self._op_argsmemstwith,
            'ArgsDictStWith'        : self._op_argsdictstwith,
            'MemSetWith'            : self._op_memsetwith,
            'DictSetWith'           : self._op_dictsetwith,
            'ArgsMemSetWith'        : self._op_argsmemsetwith,
            'ArgsDictSetWith'       : self._op_argsdictsetwith,
            'ArgsCall'              : self._op_argscall,
            'ArgsMemCall'           : self._op_argsmemcall,
            'ArgsMemCallWith'       : self._op_argsmemcallwith,
            'ArgsArray'             : self._op_argsarray,
            'Assert'                : self._op_assert,
            'BoS'                   : self._op_bos,
            'BoSImplicit'           : self._op_bosimplicit,
            'BoL'                   : self._op_bol,
            'LdAddressOf'           : self._op_ldaddressof,
            'MemAddressOf'          : self._op_memaddressof,
            'Case'                  : self._op_case,
            'CaseTo'                : self._op_caseto,
            'CaseGt'                : self._op_casegt,
            'CaseLt'                : self._op_caselt,
            'CaseGe'                : self._op_casege,
            'CaseLe'                : self._op_casele,
            'CaseNe'                : self._op_casene,
            'CaseEq'                : self._op_caseeq,
            'CaseElse'              : self._op_caseelse,
            'CaseDone'              : self._op_casedone,
            'Circle'                : self._op_circle,
            'Close'                 : self._op_close,
            'CloseAll'              : self._op_closeall,
            'Coerce'                : self._op_coerce,
            'CoerceVar'             : self._op_coercevar,
            'Context'               : self._op_context,
            'Debug'                 : self._op_debug,
            'DefType'               : self._op_deftype,
            'Dim'                   : self._op_dim,
            'DimImplicit'           : self._op_dimimplicit,
            'Do'                    : self._op_do,
            'DoEvents'              : self._op_doevents,
            'DoUnitil'              : self._op_dounitil,
            'DoWhile'               : self._op_dowhile,
            'Else'                  : self._op_else,
            'ElseBlock'             : self._op_elseblock,
            'ElseIfBlock'           : self._op_elseifblock,
            'ElseIfTypeBlock'       : self._op_elseiftypeblock,
            'End'                   : self._op_end,
            'EndContext'            : self._op_endcontext,
            'EndFunc'               : self._op_endfunc,
            'EndIf'                 : self._op_endif,
            'EndIfBlock'            : self._op_endifblock,
            'EndImmediate'          : self._op_endimmediate,
            'EndProp'               : self._op_endprop,
            'EndSelect'             : self._op_endselect,
            'EndSub'                : self._op_endsub,
            'EndType'               : self._op_endtype,
            'EndWith'               : self._op_endwith,
            'Erase'                 : self._op_erase,
            'Error'                 : self._op_error,
            'EventDecl'             : self._op_eventdecl,
            'RaiseEvent'            : self._op_raiseevent,
            'ArgsMemRaiseEvent'     : self._op_argsmemraiseevent,
            'ArgsMemRaiseEventWith' : self._op_argsmemraiseeventwith,
            'ExitDo'                : self._op_exitdo,
            'ExitFor'               : self._op_exitfor,
            'ExitFunc'              : self._op_exitfunc,
            'ExitProp'              : self._op_exitprop,
            'ExitSub'               : self._op_exitsub,
            'FnCurDir'              : self._op_fncurdir,
            'FnDir'                 : self._op_fndir,
            'Empty0'                : self._op_empty0,
            'Empty1'                : self._op_empty1,
            'FnError'               : self._op_fnerror,
            'FnFormat'              : self._op_fnformat,
            'FnFreeFile'            : self._op_fnfreefile,
            'FnInStr'               : self._op_fninstr,
            'FnInStr3'              : self._op_fninstr3,
            'FnInStr4'              : self._op_fninstr4,
            'FnInStrB'              : self._op_fninstrb,
            'FnInStrB3'             : self._op_fninstrb3,
            'FnInStrB4'             : self._op_fninstrb4,
            'FnLBound'              : self._op_fnlbound,
            'FnMid'                 : self._op_fnmid,
            'FnMidB'                : self._op_fnmidb,
            'FnStrComp'             : self._op_fnstrcomp,
            'FnStrComp3'            : self._op_fnstrcomp3,
            'FnStringVar'           : self._op_fnstringvar,
            'FnStringStr'           : self._op_fnstringstr,
            'FnUBound'              : self._op_fnubound,
            'For'                   : self._op_for,
            'ForEach'               : self._op_foreach,
            'ForEachAs'             : self._op_foreachas,
            'ForStep'               : self._op_forstep,
            'FuncDefn'              : self._op_funcdefn,
            'FuncDefnSave'          : self._op_funcdefnsave,
            'GetRec'                : self._op_getrec,
            'GoSub'                 : self._op_gosub,
            'GoTo'                  : self._op_goto,
            'If'                    : self._op_if,
            'IfBlock'               : self._op_ifblock,
            'TypeOf'                : self._op_typeof,
            'IfTypeBlock'           : self._op_iftypeblock,
            'Implements'            : self._op_implements,
            'Input'                 : self._op_input,
            'InputDone'             : self._op_inputdone,
            'InputItem'             : self._op_inputitem,
            'Label'                 : self._op_label,
            'Let'                   : self._op_let,
            'Line'                  : self._op_line,
            'LineCont'              : self._op_linecont,
            'LineInput'             : self._op_lineinput,
            'LineNum'               : self._op_linenum,
            'LitCy'                 : self._op_litcy,
            'LitDate'               : self._op_litdate,
            'LitDefault'            : self._op_litdefault,
            'LitDI2'                : self._op_litdi2,
            'LitDI4'                : self._op_litdi4,
            'LitDI8'                : self._op_litdi8,
            'LitHI2'                : self._op_lithi2,
            'LitHI4'                : self._op_lithi4,
            'LitHI8'                : self._op_lithi8,
            'LitNothing'            : self._op_litnothing,
            'LitOI2'                : self._op_litoi2,
            'LitOI4'                : self._op_litoi4,
            'LitOI8'                : self._op_litoi8,
            'LitR4'                 : self._op_litr4,
            'LitR8'                 : self._op_litr8,
            'LitSmallI2'            : self._op_litsmalli2,
            'LitStr'                : self._op_litstr,
            'LitVarSpecial'         : self._op_litvarspecial,
            'Lock'                  : self._op_lock,
            'Loop'                  : self._op_loop,
            'LoopUntil'             : self._op_loopuntil,
            'LoopWhile'             : self._op_loopwhile,
            'LSet'                  : self._op_lset,
            'Me'                    : self._op_me,
            'MeImplicit'            : self._op_meimplicit,
            'MemRedim'              : self._op_memredim,
            'MemRedimWith'          : self._op_memredimwith,
            'MemRedimAs'            : self._op_memredimas,
            'MemRedimAsWith'        : self._op_memredimaswith,
            'Mid'                   : self._op_mid,
            'MidB'                  : self._op_midb,
            'Name'                  : self._op_name,
            'New'                   : self._op_new,
            'Next'                  : self._op_next,
            'NextVar'               : self._op_nextvar,
            'OnError'               : self._op_onerror,
            'OnGosub'               : self._op_ongosub,
            'OnGoto'                : self._op_ongoto,
            'Open'                  : self._op_open,
            'Option'                : self._op_option,
            'OptionBase'            : self._op_optionbase,
            'ParamByVal'            : self._op_parambyval,
            'ParamOmitted'          : self._op_paramomitted,
            'ParamNamed'            : self._op_paramnamed,
            'PrintChan'             : self._op_printchan,
            'PrintComma'            : self._op_printcomma,
            'PrintEoS'              : self._op_printeos,
            'PrintItemComma'        : self._op_printitemcomma,
            'PrintItemNL'           : self._op_printitemnl,
            'PrintItemSemi'         : self._op_printitemsemi,
            'PrintNL'               : self._op_printnl,
            'PrintObj'              : self._op_printobj,
            'PrintSemi'             : self._op_printsemi,
            'PrintSpc'              : self._op_printspc,
            'PrintTab'              : self._op_printtab,
            'PrintTabComma'         : self._op_printtabcomma,
            'PSet'                  : self._op_pset,
            'PutRec'                : self._op_putrec,
            'QuoteRem'              : self._op_quoterem,
            'Redim'                 : self._op_redim,
            'RedimAs'               : self._op_redimas,
            'Reparse'               : self._op_reparse,
            'Rem'                   : self._op_rem,
            'Resume'                : self._op_resume,
            'Return'                : self._op_return,
            'RSet'                  : self._op_rset,
            'Scale'                 : self._op_scale,
            'Seek'                  : self._op_seek,
            'SelectCase'            : self._op_selectcase,
            'SelectIs'              : self._op_selectis,
            'SelectType'            : self._op_selecttype,
            'SetStmt'               : self._op_setstmt,
            'Stack'                 : self._op_stack,
            'Stop'                  : self._op_stop,
            'Type'                  : self._op_type,
            'Unlock'                : self._op_unlock,
            'VarDefn'               : self._op_vardefn,
            'Wend'                  : self._op_wend,
            'While'                 : self._op_while,
            'With'                  : self._op_with,
            'WriteChan'             : self._op_writechan,
            'ConstFuncExpr'         : self._op_constfuncexpr,
            'LbConst'               : self._op_lbconst,
            'LbIf'                  : self._op_lbif,
            'LbElse'                : self._op_lbelse,
            'LbElseIf'              : self._op_lbelseif,
            'LbEndIf'               : self._op_lbendif,
            'LbMark'                : self._op_lbmark,
            'EndForVariable'        : self._op_endforvariable,
            'StartForVariable'      : self._op_startforvariable,
            'NewRedim'              : self._op_newredim,
            'StartWithExpr'         : self._op_startwithexpr,
            'SetOrSt'               : self._op_setorst,
            'EndEnum'               : self._op_endenum,
            'Illegal'               : self._op_illegal,
            'NewLine'               : self._op_newline,
        }

    def execute(self, opcode: str, *args: str) -> None:
        """
        Dispatch a single opcode with its arguments.
        """
        handler = self._dispatch.get(opcode)
        if handler is None:
            raise PCodeDecompilerError(f'unknown opcode: {opcode}')
        handler(*args)

    def apply_pending_indent(self) -> None:
        """
        Called after a line is fully processed to apply any pending indent level change.
        """
        if self.unindented > 0:
            self.unindented -= 1
        elif self.indent_increase_pending:
            self.indent_level += 1
        self.indent_increase_pending = False


class PCodeParser:
    """
    Parses pcodedmp output text and uses VBADecompiler to reconstruct readable VBA source code.
    """

    def __init__(self, text: str):
        self._text = text
        self._stack = VBAStack()
        self._decompiler = VBADecompiler(self._stack)
        self._output: str = ''
        self._output_queue: list[tuple[str, int, bool, bool]] = []

    def parse(self) -> str:
        """
        Parse the pcodedmp output and return decompiled VBA source.
        """
        streams = self._parse_input()
        self._process_input(streams)
        self._output = re.sub(
            r'(End\s(?:Function|Sub|Property|Type|Enum))\n(?=\S)',
            r'\1\n\n',
            self._output,
        )
        return self._output

    def _parse_input(
        self,
    ) -> dict[str, dict[int, list[str]]]:
        lines_by_stream: dict[str, dict[int, list[str]]] = {}
        splitted = self._text.splitlines()

        current_stream: str | None = None
        lines: dict[int, list[str]] = {}
        i = 0
        started = False
        opelines: list[str] = []

        for input_line in splitted:
            input_line = input_line.strip()

            if 'VBA/' in input_line and input_line.endswith('bytes'):
                if current_stream is not None:
                    if not opelines:
                        opelines = ['NewLine']
                    lines[i] = opelines
                    lines_by_stream[current_stream] = lines
                    opelines = []
                    i = 0
                    lines = {}
                    started = False
                current_stream = input_line

            if input_line.startswith('Line #'):
                started = True
                if not input_line.startswith('Line #0'):
                    if not opelines:
                        opelines = ['NewLine']
                    lines[i] = opelines
                    i += 1
                opelines = []
            elif started:
                opelines.append(input_line)

        if not opelines:
            opelines = ['NewLine']
        lines[i] = opelines
        if current_stream is not None:
            lines_by_stream[current_stream] = lines

        return lines_by_stream

    def _queue_line(
        self,
        line: str,
        linenum: int,
        print_linenum: bool = False,
        has_end: bool = True,
    ) -> None:
        self._output_queue.append((line, linenum, print_linenum, has_end))

    def _add_line(
        self,
        line: str,
        linenum: int,
        print_linenum: bool = False,
        has_end: bool = True,
        checking_queue: bool = False,
    ) -> None:
        if not line.strip():
            return
        while not checking_queue and self._output_queue:
            entry = self._output_queue.pop()
            self._add_line(*entry, checking_queue=True)
        if print_linenum:
            self._output += F'{linenum}: '
        if not has_end:
            self._output += line
            return
        self._output += line + '\n'

    def _process_input(
        self,
        streams: dict[str, dict[int, list[str]]],
        print_linenum: bool = False,
    ) -> None:
        dc = self._decompiler

        for line_blocks in streams.values():
            unindented = 0
            for oplines in line_blocks.values():
                for line in oplines:
                    if line.startswith('FuncDefn'):
                        unindented += 1
                    if line.startswith(('EndFunc', 'EndSub')):
                        unindented -= 1
            dc.unindented = unindented

            for linenum, oplines in line_blocks.items():
                try:
                    self._stack.clear()
                    for opline in oplines:
                        parts = opline.split()
                        opcode = parts[0]
                        args = parts[1:]
                        dc.execute(opcode, *args)

                    if dc.has_bos:
                        output_parts: list[str] = []
                        while self._stack.size() > 0:
                            output_parts.append(self._stack.pop())
                        output_parts.reverse()
                        indent = dc.indent_level * '  '
                        self._add_line(indent, linenum, print_linenum, False)
                        for part in output_parts[:-1]:
                            self._add_line(
                                part + ' ', linenum,
                                has_end=False)
                        self._add_line(output_parts[-1], linenum)
                        dc.has_bos = False
                    else:
                        indent = dc.indent_level * '  '
                        self._add_line(
                            F'{indent}{self._stack.top()}',
                            linenum, print_linenum)

                except PCodeDecompilerError as e:
                    self._add_line(
                        F"' pcode2code, cannot process line {linenum} : {e}",
                        linenum, print_linenum)
                    for opline in oplines:
                        self._add_line(F"'\t# {opline}", linenum)
                except Exception as e:
                    self._add_line(
                        F"' a generic exception occured at line {linenum}: {e}",
                        linenum, print_linenum)
                    for opline in oplines:
                        self._add_line(F"'\t# {opline}", linenum)

                dc.apply_pending_indent()

            self._output_queue.clear()
