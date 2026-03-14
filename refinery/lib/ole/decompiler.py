"""
VBA p-code decompiler that converts disassembled p-code back to VBA source code. This module
is based on pcode2code by Nicolas Zilio (@Big5_sec), originally available at:
https://github.com/Big5-sec/pcode2code

Copyright (C) 2019 Nicolas Zilio
Licensed under the GNU General Public License v3.0 or later.

The code was substantially rewritten for use within Binary Refinery, but remains subject to the
original GPL license.
"""
from __future__ import annotations

import logging
import math
import re
import struct

from typing import Callable

from refinery.lib.ole.pcode import PCodeLine, PCodeModule

logger = logging.getLogger(__name__)


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
        items = list(self._items)
        self._items.clear()
        return items


_BINARY_OPS: dict[str, str] = {
    'Imp'    : 'Imp',
    'Eqv'    : 'Eqv',
    'Xor'    : 'Xor',
    'Or'     : 'Or',
    'And'    : 'And',
    'Eq'     : '=',
    'Ne'     : '<>',
    'Le'     : '<=',
    'Ge'     : '>=',
    'Lt'     : '<',
    'Gt'     : '>',
    'Add'    : '+',
    'Sub'    : '-',
    'Mod'    : 'Mod',
    'IDiv'   : '\\',
    'Mul'    : '*',
    'Div'    : '/',
    'Concat' : '&',
    'Like'   : 'Like',
    'Pwr'    : '^',
    'Is'     : 'Is',
}

_UNARY_FNS: dict[str, str] = {
    'FnAbs'  : 'Abs',
    'FnFix'  : 'Fix',
    'FnInt'  : 'int',
    'FnSgn'  : 'Sgn',
    'FnLen'  : 'Len',
    'FnLenB' : 'LenB',
    'FnMid'  : 'Mid',
    'FnMidB' : 'MidB',
}


class VBADecompiler:
    """
    Executes VBA p-code opcodes against a stack to reconstruct VBA source text. Each opcode name
    maps to a handler via a naming convention (_op_ + lowercase mnemonic) or the explicit override
    dictionary.
    """

    def __init__(self, stack: VBAStack):
        self._stack = stack
        self.indent_level: int = 0
        self.indent_increase_pending: bool = False
        self.has_bos: bool = False
        self.one_line_if: bool = False
        self.unindented: int = 0
        self._dispatch_overrides: dict[str, Callable] = {}

    def _binary_op(self, operator: str) -> None:
        rhs = self._stack.pop()
        lhs = self._stack.pop()
        self._stack.push(F'{lhs} {operator} {rhs}')

    def _unary_prefix(self, prefix: str) -> None:
        self._stack.push(F'{prefix}{self._stack.pop()}')

    def _unary_fn(self, name: str) -> None:
        self._stack.push(F'{name}({self._stack.pop()})')

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

    def _build_call(
        self,
        args_list: list[str],
        target_prefix: str,
    ) -> None:
        is_call = False
        if args_list[0] == '(Call)':
            args_list.pop(0)
            is_call = True
            name = ' '.join(args_list[:-1])
            val = F'Call {target_prefix}{name}'
        else:
            name = ' '.join(args_list[:-1])
            val = F'{target_prefix}{name}'

        nb = int(args_list[-1], 16)
        end_val = ''

        params: list[str] = []
        for _ in range(nb):
            params.append(self._stack.pop())
        params.reverse()

        if params:
            if params[0].startswith('(') and not is_call:
                val += params[0]
                end_val = ')'
            else:
                val += F' {params[0]}'
            for p in params[1:]:
                val += F', {p}'

        self._stack.push(val + end_val)

    def _lock_unlock(self, keyword: str) -> None:
        sz = self._stack.size()
        if sz == 3:
            last = self._stack.pop()
            first = self._stack.pop()
            chan = self._stack.pop()
            self._stack.push(F'{keyword} {chan}, {first} To {last}')
        elif sz == 2:
            rec = self._stack.pop()
            chan = self._stack.pop()
            self._stack.push(F'{keyword} {chan}, {rec}')
        elif sz == 1:
            self._stack.push(F'{keyword} {self._stack.pop()}')

    def _mid_statement(self, fn_name: str) -> None:
        if self._stack.size() > 3:
            length = self._stack.pop()
            start = self._stack.pop()
            obj = self._stack.pop()
            rhs = self._stack.pop()
            self._stack.push(F'{fn_name}({obj}, {start}, {length}) = {rhs}')
        else:
            start = self._stack.pop()
            obj = self._stack.pop()
            rhs = self._stack.pop()
            self._stack.push(F'{fn_name}({obj}, {start}) = {rhs}')

    def _op_not(self) -> None:
        self._unary_prefix('Not ')

    def _op_umi(self) -> None:
        self._unary_prefix('-')

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

    def _op_argsld(self, *args: str) -> None:
        varname = ' '.join(args[:-1])
        params = self._pop_params(args[-1])
        self._stack.push(F'{varname}({self._join_params(params)})')

    def _op_argsmemld(self, *args: str) -> None:
        var = ' '.join(args[:-1])
        obj = self._stack.pop()
        params = self._pop_params(args[-1])
        self._stack.push(F'{obj}.{var}({self._join_params(params)})')

    def _op_argsdictld(self, *args: str) -> None:
        var = ' '.join(args[:-1])
        obj = self._stack.pop()
        params = self._pop_params(args[-1])
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

    def _op_argsst(self, *args: str) -> None:
        var = ' '.join(args[:-1])
        params = self._pop_params(args[-1])
        val = F'{var}({self._join_params(params)}) = {self._stack.pop()}'
        self._stack.push(val)

    def _op_argsmemst(self, *args: str) -> None:
        var = ' '.join(args[:-1])
        obj = F'{self._stack.pop()}.'
        params = self._pop_params(args[-1])
        val = F'{obj}{var}({self._join_params(params)}) = {self._stack.pop()}'
        self._stack.push(val)

    def _op_argsdictst(self, *args: str) -> None:
        var = ' '.join(args[:-1])
        obj = F'{self._stack.pop()}!'
        params = self._pop_params(args[-1])
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

    def _op_argsmemset(self, *args: str) -> None:
        var = ' '.join(args[:-1])
        obj = self._stack.pop()
        params = self._pop_params(args[-1])
        joined = self._join_params(params)
        val = F'Set {obj}.{var}({joined}) = {self._stack.pop()}'
        self._stack.push(val)

    def _op_argsdictset(self, *args: str) -> None:
        var = ' '.join(args[:-1])
        obj = self._stack.pop()
        params = self._pop_params(args[-1])
        joined = self._join_params(params)
        val = F'Set {obj}!{var}({joined}) = {self._stack.pop()}'
        self._stack.push(val)

    def _op_memldwith(self, var: str) -> None:
        self._with_access('.', var)

    def _op_dictldwith(self, var: str) -> None:
        self._with_access('!', var)

    def _op_argsmemldwith(self, *args: str) -> None:
        var = ' '.join(args[:-1])
        params = self._pop_params(args[-1])
        self._stack.push(F'.{var}({self._join_params(params)})')

    def _op_argsdictldwith(self, *args: str) -> None:
        var = ' '.join(args[:-1])
        params = self._pop_params(args[-1])
        self._stack.push(F'!{var}({self._join_params(params)})')

    def _op_memstwith(self, var: str) -> None:
        self._stack.push(F'.{var} = {self._stack.pop()}')

    def _op_dictstwith(self, var: str) -> None:
        self._stack.push(F'!{var} = {self._stack.pop()}')

    def _op_argsmemstwith(self, *args: str) -> None:
        var = ' '.join(args[:-1])
        params = self._pop_params(args[-1])
        val = F'.{var}({self._join_params(params)}) = {self._stack.pop()}'
        self._stack.push(val)

    def _op_argsdictstwith(self, *args: str) -> None:
        var = ' '.join(args[:-1]) if len(args) > 1 else args[0]
        self._stack.push(F'!{var} = {self._stack.pop()}')

    def _op_memsetwith(self, var: str) -> None:
        self._stack.push(F'Set .{var} = {self._stack.pop()}')

    def _op_dictsetwith(self, var: str) -> None:
        self._stack.push(F'Set !{var} = {self._stack.pop()}')

    def _op_argsmemsetwith(self, *args: str) -> None:
        var = ' '.join(args[:-1])
        params = self._pop_params(args[-1])
        val = F'Set !{var}({self._join_params(params)}) = {self._stack.pop()}'
        self._stack.push(val)

    def _op_argsdictsetwith(self, *args: str) -> None:
        var = ' '.join(args[:-1])
        params = self._pop_params(args[-1])
        val = F'Set !{var}({self._join_params(params)}) = {self._stack.pop()}'
        self._stack.push(val)

    def _op_argscall(self, *args: str) -> None:
        args_list = list(args)
        is_call = args_list[0] == '(Call)'
        if is_call:
            nb = int(args_list[-1], 16)
            name = ' '.join(args_list[1:-1])
            val = F'Call {name}'
        else:
            nb = int(args_list[-1], 16)
            val = ' '.join(args_list[:-1])

        params: list[str] = []
        for _ in range(nb):
            params.append(self._stack.pop())
        params.reverse()

        end_val = ''
        if params:
            if params[0].startswith('(') and not is_call:
                val += params[0]
                end_val = ')'
            else:
                val += F' {params[0]}'
            for p in params[1:]:
                val += F', {p}'
            val += end_val
        self._stack.push(val)

    def _op_argsmemcall(self, *args: str) -> None:
        args_list = list(args)
        target_prefix = F'{self._stack.pop()}.'
        self._build_call(args_list, target_prefix)

    def _op_argsmemcallwith(self, *args: str) -> None:
        args_list = list(args)
        self._build_call(args_list, '.')

    def _op_argsarray(self, *args: str) -> None:
        var = ' '.join(args[:-1])
        params = self._pop_params(args[-1])
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
        '(Str)'  : 'CStr',
        '(Var)'  : 'CVar',
        '(Sng)'  : 'CSng',
        '(Lng)'  : 'CLng',
        '(Int)'  : 'CInt',
        '(Dbl)'  : 'CDbl',
        '(Date)' : 'CDate',
        '(Cur)'  : 'CCur',
        '(Byte)' : 'CByte',
        '(Bool)' : 'CBool',
    }

    def _op_coerce(self, arg: str) -> None:
        fn = self._COERCE_MAP.get(arg)
        if fn is None:
            raise PCodeDecompilerError(F'not implemented coerce type: {arg}')
        self._stack.push(F'{fn}({self._stack.pop()})')

    def _op_coercevar(self, arg: str) -> None:
        if arg == '(Err)':
            self._stack.push(F'CVErr({self._stack.pop()})')
        else:
            raise PCodeDecompilerError(F'not implemented coercevar type: {arg}')

    def _op_context(self, *args: str) -> None:
        pass

    def _op_debug(self) -> None:
        self._stack.push('Debug')

    def _op_deftype(self, type_arg: str, start: str, end: str) -> None:
        type_name = type_arg[1:-1] if type_arg.startswith('(') else type_arg
        start_letter = chr(int(start, 16) + ord('A'))
        end_letter = chr(int(end, 16) + ord('A'))
        if start_letter == end_letter:
            self._stack.push(F'Def{type_name} {start_letter}')
        else:
            self._stack.push(F'Def{type_name} {start_letter}-{end_letter}')

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
        self._stack.push('DoEvents')

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

    def _op_elseiftypeblock(self, type_name: str) -> None:
        obj = self._stack.pop()
        self._stack.push(F'ElseIf TypeOf {obj} Is {type_name} Then')
        self.indent_level -= 1
        self.indent_increase_pending = True

    def _op_end(self) -> None:
        self._stack.push('End')

    def _op_endcontext(self, *args: str) -> None:
        pass

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
        self._stack.push('CurDir')

    def _op_fndir(self, numparams: str = '0x0000') -> None:
        params = self._pop_params(numparams)
        if params:
            self._stack.push(F'Dir({self._join_params(params)})')
        else:
            self._stack.push('Dir')

    def _op_empty0(self, *args: str) -> None:
        self._stack.push('')

    def _op_empty1(self, *args: str) -> None:
        self._stack.push('Empty')

    def _op_fnerror(self, *args: str) -> None:
        self._stack.push('Error')

    def _op_fnformat(self, numparams: str = '0x0000') -> None:
        params = self._pop_params(numparams)
        if params:
            self._stack.push(F'Format({self._join_params(params)})')
        else:
            self._stack.push('Format')

    def _op_fnfreefile(self, *args: str) -> None:
        self._stack.push('FreeFile')

    def _op_fninstr(self) -> None:
        arg2 = self._stack.pop()
        arg1 = self._stack.pop()
        self._stack.push(F'Instr({arg1}, {arg2})')

    def _op_fninstr3(self) -> None:
        a3 = self._stack.pop()
        a2 = self._stack.pop()
        a1 = self._stack.pop()
        self._stack.push(F'Instr({a1}, {a2}, {a3})')

    def _op_fninstr4(self) -> None:
        a4 = self._stack.pop()
        a3 = self._stack.pop()
        a2 = self._stack.pop()
        a1 = self._stack.pop()
        self._stack.push(F'Instr({a1}, {a2}, {a3}, {a4})')

    def _op_fninstrb(self) -> None:
        arg2 = self._stack.pop()
        arg1 = self._stack.pop()
        self._stack.push(F'InstrB({arg1}, {arg2})')

    def _op_fninstrb3(self) -> None:
        a3 = self._stack.pop()
        a2 = self._stack.pop()
        a1 = self._stack.pop()
        self._stack.push(F'InstrB({a1}, {a2}, {a3})')

    def _op_fninstrb4(self) -> None:
        a4 = self._stack.pop()
        a3 = self._stack.pop()
        a2 = self._stack.pop()
        a1 = self._stack.pop()
        self._stack.push(F'InstrB({a1}, {a2}, {a3}, {a4})')

    def _op_fnlbound(self, arg: str) -> None:
        n = int(arg, 16) + 1
        params: list[str] = []
        for _ in range(n):
            params.append(self._stack.pop())
        params.reverse()
        self._stack.push(F'LBound({self._join_params(params)})')

    def _op_fnstrcomp(self) -> None:
        s2 = self._stack.pop()
        s1 = self._stack.pop()
        self._stack.push(F'StrComp({s1}, {s2})')

    def _op_fnstrcomp3(self) -> None:
        a3 = self._stack.pop()
        s2 = self._stack.pop()
        s1 = self._stack.pop()
        self._stack.push(F'StrComp({s1}, {s2}, {a3})')

    def _op_fnstringvar(self, numparams: str = '0x0000') -> None:
        params = self._pop_params(numparams)
        self._stack.push(F'String({self._join_params(params)})')

    def _op_fnstringstr(self, numparams: str = '0x0000') -> None:
        params = self._pop_params(numparams)
        self._stack.push(F'String({self._join_params(params)})')

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
        self._stack.push(F'For {loopvar} = {minvar} To {maxvar}')
        self.indent_increase_pending = True

    def _op_foreach(self) -> None:
        collect = self._stack.pop()
        loopvar = self._stack.pop()
        self._stack.push(F'For Each {loopvar} In {collect}')
        self.indent_increase_pending = True

    def _op_foreachas(self, type_name: str) -> None:
        collect = self._stack.pop()
        loopvar = self._stack.pop()
        self._stack.push(F'For Each {loopvar} In {collect}')
        self.indent_increase_pending = True

    def _op_forstep(self) -> None:
        step = self._stack.pop()
        maxvar = self._stack.pop()
        minvar = self._stack.pop()
        loopvar = self._stack.pop()
        self._stack.push(
            F'For {loopvar} = {minvar} To {maxvar}'
            F' Step {step}')
        self.indent_increase_pending = True

    def _op_funcdefn(self, *args: str) -> None:
        val = ' '.join(args)
        val = val[1:-1]
        self._stack.push(val)
        if not val.startswith('Declare'):
            self.indent_increase_pending = True

    def _op_funcdefnsave(self, *args: str) -> None:
        val = ' '.join(args)
        val = val[1:-1]
        self._stack.push(val)
        if not val.startswith('Declare'):
            self.indent_increase_pending = True

    def _op_getrec(self) -> None:
        record = self._stack.pop()
        record_num = self._stack.pop()
        chan = self._stack.pop()
        if chan:
            self._stack.push(F'Get {chan}, {record_num}, {record}')
        else:
            self._stack.push(F'Get {record_num}, , {record}')

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

    def _op_typeof(self, type_name: str) -> None:
        obj = self._stack.pop()
        self._stack.push(F'TypeOf {obj} Is {type_name}')

    def _op_iftypeblock(self, type_name: str) -> None:
        obj = self._stack.pop()
        self._stack.push(F'If TypeOf {obj} Is {type_name} Then')
        self.indent_increase_pending = True

    def _op_implements(self, *args: str) -> None:
        self._stack.push(F'Implements {self._stack.pop()}')

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

    def _op_line(self, numparams: str) -> None:
        obj = self._stack.pop()
        nb = int(numparams, 16)
        params: list[str] = []
        for _ in range(nb):
            params.append(self._stack.pop())
        params.reverse()
        val = F'{obj}.Line '
        if len(params) >= 4:
            step1 = ''
            step2 = ''
            if params[0] != '0':
                step1 = 'Step '
            if params[1] != '0':
                step2 = 'Step '
            val += F'{step1}({params[2]}, {params[3]})'
            if len(params) >= 6:
                val += F'-{step2}({params[4]}, {params[5]})'
            if len(params) >= 7 and params[6] != '0':
                val += F', {params[6]}'
            if len(params) >= 8 and params[7] != '0':
                val += F', {params[7]}'
        self._stack.push(val)

    def _op_linecont(self, *args: str) -> None:
        pass

    def _op_lineinput(self) -> None:
        var = self._stack.pop()
        num_file = self._stack.pop()
        self._stack.push(F'Line Input #{num_file}, {var}')

    def _op_linenum(self, *args: str) -> None:
        return

    def _op_litcy(self, b1: str, b2: str, b3: str, b4: str) -> None:
        hexstr = b4[2:] + b3[2:] + b2[2:] + b1[2:]
        val = int(hexstr, 16)
        if val >= 0x8000000000000000:
            val -= 0x10000000000000000
        cy = val / 10000
        if cy == int(cy):
            self._stack.push(str(int(cy)))
        else:
            self._stack.push(str(cy))

    def _op_litdate(self, b1: str, b2: str, b3: str, b4: str) -> None:
        from datetime import datetime, timedelta
        hexstr = b4[2:] + b3[2:] + b2[2:] + b1[2:]
        value = struct.unpack('!d', bytes.fromhex(hexstr))[0]
        epoch = datetime(1899, 12, 30)
        try:
            dt = epoch + timedelta(days=value)
            self._stack.push(F'#{dt.strftime("%m/%d/%Y")}#')
        except (OverflowError, ValueError, OSError):
            self._stack.push(F'#<date:{value}>#')

    def _op_litdefault(self) -> None:
        pass

    def _op_litdi2(self, value: str) -> None:
        self._stack.push(str(int(value, 16)))

    def _op_litdi4(self, byte1: str, byte2: str) -> None:
        val = int(byte2 + byte1[2:], 16)
        self._stack.push(str(val))

    def _op_litdi8(self, b1: str, b2: str, b3: str, b4: str) -> None:
        hexstr = b4[2:] + b3[2:] + b2[2:] + b1[2:]
        val = int(hexstr, 16)
        self._stack.push(str(val))

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

    def _op_lithi8(self, b1: str, b2: str, b3: str, b4: str) -> None:
        val = b4[2:] + b3[2:] + b2[2:] + b1[2:]
        while val.startswith('0') and len(val) > 1:
            val = val[1:]
        self._stack.push(F'&H{val}')

    def _op_litnothing(self) -> None:
        self._stack.push('Nothing')

    def _op_litoi2(self, value: str) -> None:
        v = int(value, 16)
        self._stack.push(F'&O{oct(v)[2:]}')

    def _op_litoi4(self, byte1: str, byte2: str) -> None:
        val = byte2[2:] + byte1[2:]
        v = int(val, 16)
        self._stack.push(F'&O{oct(v)[2:]}')

    def _op_litoi8(self, b1: str, b2: str, b3: str, b4: str) -> None:
        val = b4[2:] + b3[2:] + b2[2:] + b1[2:]
        v = int(val, 16)
        self._stack.push(F'&O{oct(v)[2:]}')

    def _op_litr4(self, byte1: str, byte2: str) -> None:
        hexstr = byte2[2:] + byte1[2:]
        value = struct.unpack('!f', bytes.fromhex(hexstr))[0]
        if value == int(value) and not (math.isinf(value) or math.isnan(value)):
            self._stack.push(F'{int(value)}!')
        else:
            self._stack.push(str(value))

    def _op_litr8(
        self, b1: str, b2: str, b3: str, b4: str
    ) -> None:
        hexstr = b4[2:] + b3[2:] + b2[2:] + b1[2:]
        value = struct.unpack('!d', bytes.fromhex(hexstr))[0]
        if value == int(value) and not (math.isinf(value) or math.isnan(value)):
            self._stack.push(F'{int(value)}#')
        else:
            self._stack.push(str(value))

    def _op_litsmalli2(self, value: str) -> None:
        self._stack.push(value)

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
        self._lock_unlock('Lock')

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
        self._stack.push(F'LSet {var} = {val}')

    def _op_me(self, *args: str) -> None:
        self._stack.push('Me')

    def _op_meimplicit(self, *args: str) -> None:
        self._stack.push('MeImplicit')

    def _op_memredim(self, *args: str) -> None:
        obj = self._stack.pop()
        args_list = list(args)
        val = self._redim_body(args_list, F'{obj}.')
        self._stack.push(val)

    def _op_memredimwith(self, *args: str) -> None:
        args_list = list(args)
        val = self._redim_body(args_list, '.')
        self._stack.push(val)

    def _op_memredimas(self, *args: str) -> None:
        obj = self._stack.pop()
        args_list = list(args)
        val = self._redim_body(args_list, F'{obj}.')
        val += self._redim_as_suffix(args_list)
        self._stack.push(val)

    def _op_memredimaswith(self, *args: str) -> None:
        args_list = list(args)
        val = self._redim_body(args_list, '.')
        val += self._redim_as_suffix(args_list)
        self._stack.push(val)

    def _op_mid(self) -> None:
        self._mid_statement('Mid')

    def _op_midb(self) -> None:
        self._mid_statement('MidB')

    def _op_name(self) -> None:
        newname = self._stack.pop()
        oldname = self._stack.pop()
        self._stack.push(F'Name {oldname} As {newname}')

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
        self._stack.push(F'Open {filename} {mode} As {chan}')

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
        self._stack.push(F'Put {chan}, {record_num}, {record}')

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
        val = self._redim_body(args_list)
        self._stack.push(val)

    def _op_redimas(self, *args: str) -> None:
        args_list = list(args)
        val = self._redim_body(args_list)
        val += self._redim_as_suffix(args_list)
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
        self._stack.push(F'RSet {var} = {val}')

    def _op_scale(self, numparams: str) -> None:
        obj = self._stack.pop()
        nb = int(numparams, 16)
        params: list[str] = []
        for _ in range(nb):
            params.append(self._stack.pop())
        params.reverse()
        val = F'{obj}.Scale '
        if len(params) >= 4:
            val += F'({params[0]}, {params[1]})-({params[2]}, {params[3]})'
        self._stack.push(val)

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
        self._lock_unlock('Unlock')

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
            'Dim', 'Global', 'Private', 'Public', 'Protected', 'Friend',
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

        decl_prefix = ''
        if values[0] in decls:
            decl_prefix = F'{values.pop(0)} '
        elif values[0] == 'DimImplicit':
            values.pop(0)
        else:
            for decl in decls:
                if values[0].startswith(decl):
                    decl_prefix = F'{values.pop(0)}, '
                    break

        if ending.strip().startswith('As') and len(values) == 1:
            type_name = ending.strip()[3:]
            self._stack.push(F'{decl_prefix}{var} As {type_name} * {values[0]}')
            return

        if len(values) == 1:
            self._stack.push(F'{decl_prefix}{var}({values[0]}){ending}')
            return

        val = F'{decl_prefix}{var}('
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
        pass

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

    def _op_setorst(self, arg: str) -> None:
        self._stack.push(F'{arg} = {self._stack.pop()}')

    def _op_endenum(self) -> None:
        self._stack.push('End Enum')
        self.indent_level -= 1

    def _op_illegal(self, *args: str) -> None:
        raise PCodeDecompilerError('not implemented: Illegal')

    def _op_newline(self) -> None:
        self._stack.push('')

    def execute(self, opcode: str, *args: str) -> None:
        """
        Dispatch a single opcode with its arguments. Uses a naming convention (_op_ + lowercase
        mnemonic) with getattr lookup, falling back to data-driven tables for binary ops and
        unary functions.
        """
        handler = self._dispatch_overrides.get(opcode)
        if handler is not None:
            handler(*args)
            return
        method_name = F'_op_{opcode.lower()}'
        handler = getattr(self, method_name, None)
        if handler is not None:
            handler(*args)
            return
        binary_sym = _BINARY_OPS.get(opcode)
        if binary_sym is not None:
            self._binary_op(binary_sym)
            return
        unary_name = _UNARY_FNS.get(opcode)
        if unary_name is not None:
            self._unary_fn(unary_name)
            return
        raise PCodeDecompilerError(F'unknown opcode: {opcode}')

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
    Accepts structured PCodeModule objects (or legacy pcodedmp text) and uses VBADecompiler to
    reconstruct readable VBA source code.
    """

    def __init__(self):
        self._stack = VBAStack()
        self._decompiler = VBADecompiler(self._stack)
        self._output: str = ''
        self._output_queue: list[tuple[str, int, bool, bool]] = []

    def decompile_modules(self, modules: list[PCodeModule]) -> str:
        """
        Decompile a list of PCodeModule objects into VBA source code.
        """
        self._output = ''
        for module in modules:
            self._process_structured(module.lines)
        self._output = re.sub(
            r'(End\s(?:Function|Sub|Property|Type|Enum))\n(?=\S)',
            r'\1\n\n',
            self._output,
        )
        return self._output

    def decompile_module(self, module: PCodeModule) -> str:
        """
        Decompile a single PCodeModule into VBA source code.
        """
        self._output = ''
        self._process_structured(module.lines)
        self._output = re.sub(
            r'(End\s(?:Function|Sub|Property|Type|Enum))\n(?=\S)',
            r'\1\n\n',
            self._output,
        )
        return self._output

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

    def _process_structured(
        self,
        pcode_lines: list[PCodeLine],
        print_linenum: bool = False,
    ) -> None:
        dc = self._decompiler

        unindented = 0
        for pcode_line in pcode_lines:
            for mnemonic, _args in pcode_line.opcodes:
                if mnemonic == 'FuncDefn':
                    unindented += 1
                if mnemonic in ('EndFunc', 'EndSub'):
                    unindented -= 1
        dc.unindented = unindented

        for linenum, pcode_line in enumerate(pcode_lines):
            if not pcode_line.opcodes:
                continue
            try:
                self._stack.clear()
                bos_segments: list[list[str]] = []
                for mnemonic, op_args in pcode_line.opcodes:
                    normalized = ' '.join(op_args).split()
                    if mnemonic == 'BoS' and normalized and int(normalized[0], 16) == 0:
                        segment: list[str] = []
                        while self._stack.size() > 0:
                            segment.append(self._stack.pop())
                        segment.reverse()
                        bos_segments.append(segment)
                        dc.has_bos = True
                    else:
                        dc.execute(mnemonic, *normalized)

                if dc.has_bos:
                    trailing: list[str] = []
                    while self._stack.size() > 0:
                        trailing.append(self._stack.pop())
                    trailing.reverse()
                    indent = dc.indent_level * '  '
                    self._add_line(indent, linenum, print_linenum, False)
                    all_segments = list(bos_segments)
                    if trailing:
                        all_segments.append(trailing)
                    for k, segment in enumerate(all_segments):
                        last_segment = k == len(all_segments) - 1
                        for j, part in enumerate(segment):
                            end_of_segment = j == len(segment) - 1
                            if last_segment and end_of_segment:
                                self._add_line(part, linenum)
                            elif end_of_segment and not last_segment:
                                self._add_line(F'{part}: ', linenum, has_end=False)
                            else:
                                self._add_line(F'{part} ', linenum, has_end=False)
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
                for mnemonic, op_args in pcode_line.opcodes:
                    self._add_line(
                        F"'\t# {mnemonic} {' '.join(op_args)}",
                        linenum)
            except Exception as e:
                logger.warning(F'decompiler error at line {linenum}: {e}')
                self._add_line(
                    F"' a generic exception occured at line {linenum}: {e}",
                    linenum, print_linenum)
                for mnemonic, op_args in pcode_line.opcodes:
                    self._add_line(
                        F"'\t# {mnemonic} {' '.join(op_args)}",
                        linenum)

            dc.apply_pending_indent()

        self._output_queue.clear()
