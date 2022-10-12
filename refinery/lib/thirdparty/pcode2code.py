#!/usr/bin/env python
"""
The code of this module is based on the source code of pcode2code, originally
available at the following location:

https://github.com/Big5-sec/pcode2code

The following is the original docstring:

pcode2code is a module aiming at decompiling VBA pcode. It's based on Dr. Vesselin
Vladimirov Bontchev(@VessOnSecurity)'s tool pcodedmp, which makes the disassembly,
while this module is only an interface to print out readable VBA code.
 How it works:
Basically, pcodedmp gives out a bytecode interpretation, representing operations
made on a somewhat stack, with opcodes translation. This program simply parses the
opcodes and manipulates the stack to rectonstruct the original VBA code.
 Author: Nicolas Zilio - @Big5_sec
 License: GPL

The code was altered and modified for work within Binary Refinery, but remains
subject to the original license text, which is as follows:

                     GNU GENERAL PUBLIC LICENSE
                      Version 3, 29 June 2007

    a vba p-code decompiler based on pcodedmp
    Copyright (C) 2019  Nicolas Zilio

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program. If not, see http://www.gnu.org/licenses/.

Also add information on how to contact you by electronic and paper mail.

  You should also get your employer (if you work as a programmer) or school,
if any, to sign a "copyright disclaimer" for the program, if necessary.
For more information on this, and how to apply and follow the GNU GPL, see:
  http://www.gnu.org/licenses/.

  The GNU General Public License does not permit incorporating your program
into proprietary programs.  If your program is a subroutine library, you
may consider it more useful to permit linking proprietary applications with
the library. If this is what you want to do, use the GNU Lesser General
Public License instead of this License. But first, please read:
  http://www.gnu.org/philosophy/why-not-lgpl.html.
"""
import struct


class Pcode2codeException(Exception):
    """
    Simply a custom exception class, permitting to make the difference between generic python exceptions and the one we are pushing
    """
    pass


class Stack:
    """
    Our stack class. Used to implement the operations made in the VBA bytecode, which is somehow stack based
    """

    def __init__(self):
        self.stack = []

    def pop(self):
        if len(self.stack) == 0:
            return None
        return self.stack.pop()

    def push(self, item):
        self.stack.append(item)

    def size(self):
        return len(self.stack)

    def top(self):
        return self.stack[-1]

    def bottom(self):
        return self.stack[0]

    def clearstack(self):
        self.stack = []


class Operations:

    def __init__(self, opstack: Stack):
        self.opstack = opstack
        # number of blocks that will be ignored for indentation
        self.unindented = 0
        # current indentation level
        self.indentlevel = 0
        # boolean indicating if indentation level should be increased after the current command
        self.indentincrease_future = False
        # boolean indicating to print all stack, like in one liner cases
        self.has_bos = False
        # boolean indicating if we are on a onelineif. In this case, closing should not be treated the same as other if blocks
        self.onelineif = False
        self.ops = {
            'Imp'                   : self.imp,
            'Eqv'                   : self.eqv,
            'Xor'                   : self.xor,
            'Or'                    : self.or_,
            'And'                   : self.and_,
            'Eq'                    : self.eq,
            'Ne'                    : self.ne,
            'Le'                    : self.le,
            'Ge'                    : self.ge,
            'Lt'                    : self.lt,
            'Gt'                    : self.gt,
            'Add'                   : self.add,
            'Sub'                   : self.sub,
            'Mod'                   : self.mod,
            'IDiv'                  : self.idiv,
            'Mul'                   : self.mul,
            'Div'                   : self.div,
            'Concat'                : self.concat,
            'Like'                  : self.like,
            'Pwr'                   : self.pwr,
            'Is'                    : self.is_,
            'Not'                   : self.not_,
            'UMi'                   : self.umi,
            'FnAbs'                 : self.fnabs,
            'FnFix'                 : self.fnfix,
            'FnInt'                 : self.fnint,
            'FnSgn'                 : self.fnsgn,
            'FnLen'                 : self.fnlen,
            'FnLenB'                : self.fnlenb,
            'Paren'                 : self.paren,
            'Sharp'                 : self.sharp,
            'LdLHS'                 : self.ldlhs,
            'Ld'                    : self.ld,
            'MemLd'                 : self.memld,
            'DictLd'                : self.dictld,
            'IndexLd'               : self.indexld,
            'ArgsLd'                : self.argsld,
            'ArgsMemLd'             : self.argsmemld,
            'ArgsDictLd'            : self.argsdictld,
            'St'                    : self.st,
            'MemSt'                 : self.memst,
            'DictSt'                : self.dictst,
            'IndexSt'               : self.indexst,
            'ArgsSt'                : self.argsst,
            'ArgsMemSt'             : self.argsmemst,
            'ArgsDictSt'            : self.argsdictst,
            'Set'                   : self.set_,
            'Memset'                : self.memset,
            'Dictset'               : self.dictset,
            'Indexset'              : self.indexset,
            'ArgsSet'               : self.argsset,
            'ArgsMemSet'            : self.argsmemset,
            'ArgsDictSet'           : self.argsdictset,
            'MemLdWith'             : self.memldwith,
            'DictLdWith'            : self.dictldwith,
            'ArgsMemLdWith'         : self.argsmemldwith,
            'ArgsDictLdWith'        : self.argsdictldwith,
            'MemStWith'             : self.memstwith,
            'DictStWith'            : self.dictstwith,
            'ArgsMemStWith'         : self.argsmemstwith,
            'ArgsDictStWith'        : self.argsdictstwith,
            'MemSetWith'            : self.memsetwith,
            'DictSetWith'           : self.dictsetwith,
            'ArgsMemSetWith'        : self.argsmemsetwith,
            'ArgsDictSetWith'       : self.argsdictsetwith,
            'ArgsCall'              : self.argscall,
            'ArgsMemCall'           : self.argsmemcall,
            'ArgsMemCallWith'       : self.argsmemcallwith,
            'ArgsArray'             : self.argsarray,
            'Assert'                : self.assert_,
            'BoS'                   : self.bos,
            'BoSImplicit'           : self.bosimplicit,
            'BoL'                   : self.bol,
            'LdAddressOf'           : self.ldaddressof,
            'MemAddressOf'          : self.memaddressof,
            'Case'                  : self.case,
            'CaseTo'                : self.caseto,
            'CaseGt'                : self.casegt,
            'CaseLt'                : self.caselt,
            'CaseGe'                : self.casege,
            'CaseLe'                : self.casele,
            'CaseNe'                : self.casene,
            'CaseEq'                : self.caseeq,
            'CaseElse'              : self.caseelse,
            'CaseDone'              : self.casedone,
            'Circle'                : self.circle,
            'Close'                 : self.close,
            'CloseAll'              : self.closeall,
            'Coerce'                : self.coerce_,
            'CoerceVar'             : self.coercevar,
            'Context'               : self.context,
            'Debug'                 : self.debug,
            'DefType'               : self.deftype,
            'Dim'                   : self.dim,
            'DimImplicit'           : self.dimimplicit,
            'Do'                    : self.do,
            'DoEvents'              : self.doevents,
            'DoUnitil'              : self.dounitil,
            'DoWhile'               : self.dowhile,
            'Else'                  : self.else_,
            'ElseBlock'             : self.elseblock,
            'ElseIfBlock'           : self.elseifblock,
            'ElseIfTypeBlock'       : self.elseiftypeblock,
            'End'                   : self.end,
            'EndContext'            : self.endcontext,
            'EndFunc'               : self.endfunc,
            'EndIf'                 : self.endif,
            'EndIfBlock'            : self.endifblock,
            'EndImmediate'          : self.endimmediate,
            'EndProp'               : self.endprop,
            'EndSelect'             : self.endselect,
            'EndSub'                : self.endsub,
            'EndType'               : self.endtype,
            'EndWith'               : self.endwith,
            'Erase'                 : self.erase,
            'Error'                 : self.error,
            'EventDecl'             : self.eventdecl,
            'RaiseEvent'            : self.raiseevent,
            'ArgsMemRaiseEvent'     : self.argsmemraiseevent,
            'ArgsMemRaiseEventWith' : self.argsmemraiseeventwith,
            'ExitDo'                : self.exitdo,
            'ExitFor'               : self.exitfor,
            'ExitFunc'              : self.exitfunc,
            'ExitProp'              : self.exitprop,
            'ExitSub'               : self.exitsub,
            'FnCurDir'              : self.fncurdir,
            'FnDir'                 : self.fndir,
            'Empty0'                : self.empty0,
            'Empty1'                : self.empty1,
            'FnError'               : self.fnerror,
            'FnFormat'              : self.fnformat,
            'FnFreeFile'            : self.fnfreefile,
            'FnInStr'               : self.fninstr,
            'FnInStr3'              : self.fninstr3,
            'FnInStr4'              : self.fninstr4,
            'FnInStrB'              : self.fninstrb,
            'FnInStrB3'             : self.fninstrb3,
            'FnInStrB4'             : self.fninstrb4,
            'FnLBound'              : self.fnlbound,
            'FnMid'                 : self.fnmid,
            'FnMidB'                : self.fnmidb,
            'FnStrComp'             : self.fnstrcomp,
            'FnStrComp3'            : self.fnstrcomp3,
            'FnStringVar'           : self.fnstringvar,
            'FnStringStr'           : self.fnstringstr,
            'FnUBound'              : self.fnubound,
            'For'                   : self.for_,
            'ForEach'               : self.foreach,
            'ForEachAs'             : self.foreachas,
            'ForStep'               : self.forstep,
            'FuncDefn'              : self.funcdefn,
            'FuncDefnSave'          : self.funcdefnsave,
            'GetRec'                : self.getrec,
            'GoSub'                 : self.gosub,
            'GoTo'                  : self.goto,
            'If'                    : self.if_,
            'IfBlock'               : self.ifblock,
            'TypeOf'                : self.typeof,
            'IfTypeBlock'           : self.iftypeblock,
            'Implements'            : self.implements,
            'Input'                 : self.input_,
            'InputDone'             : self.inputdone,
            'InputItem'             : self.inputItem,
            'Label'                 : self.label,
            'Let'                   : self.let,
            'Line'                  : self.line,
            'LineCont'              : self.linecont,
            'LineInput'             : self.lineInput,
            'LineNum'               : self.linenum,
            'LitCy'                 : self.litcy,
            'LitDate'               : self.litdate,
            'LitDefault'            : self.litdefault,
            'LitDI2'                : self.litdi2,
            'LitDI4'                : self.litdi4,
            'LitDI8'                : self.litdi8,
            'LitHI2'                : self.lithi2,
            'LitHI4'                : self.lithi4,
            'LitHI8'                : self.lithi8,
            'LitNothing'            : self.litnothing,
            'LitOI2'                : self.litoi2,
            'LitOI4'                : self.litoi4,
            'LitOI8'                : self.litoi8,
            'LitR4'                 : self.litr4,
            'LitR8'                 : self.litr8,
            'LitSmallI2'            : self.litsmalli2,
            'LitStr'                : self.litstr,
            'LitVarSpecial'         : self.litvarspecial,
            'Lock'                  : self.lock,
            'Loop'                  : self.loop,
            'LoopUntil'             : self.loopuntil,
            'LoopWhile'             : self.loopwhile,
            'LSet'                  : self.lset,
            'Me'                    : self.me,
            'MeImplicit'            : self.meimplicit,
            'MemRedim'              : self.memredim,
            'MemRedimWith'          : self.memredimwith,
            'MemRedimAs'            : self.memredimas,
            'MemRedimAsWith'        : self.memredimaswith,
            'Mid'                   : self.mid,
            'MidB'                  : self.midb,
            'Name'                  : self.name,
            'New'                   : self.new,
            'Next'                  : self.next_,
            'NextVar'               : self.nextvar,
            'OnError'               : self.onerror,
            'OnGosub'               : self.ongosub,
            'OnGoto'                : self.ongoto,
            'Open'                  : self.open_,
            'Option'                : self.option,
            'OptionBase'            : self.optionbase,
            'ParamByVal'            : self.parambyval,
            'ParamOmitted'          : self.paramomitted,
            'ParamNamed'            : self.paramnamed,
            'PrintChan'             : self.printchan,
            'PrintComma'            : self.printcomma,
            'PrintEoS'              : self.printeos,
            'PrintItemComma'        : self.printitemcomma,
            'PrintItemNL'           : self.printitemnl,
            'PrintItemSemi'         : self.printitemsemi,
            'PrintNL'               : self.printnl,
            'PrintObj'              : self.printobj,
            'PrintSemi'             : self.printsemi,
            'PrintSpc'              : self.printspc,
            'PrintTab'              : self.printtab,
            'PrintTabComma'         : self.printtabcomma,
            'PSet'                  : self.pset,
            'PutRec'                : self.putrec,
            'QuoteRem'              : self.quoterem,
            'Redim'                 : self.redim,
            'RedimAs'               : self.redimas,
            'Reparse'               : self.reparse,
            'Rem'                   : self.rem,
            'Resume'                : self.resume,
            'Return'                : self.return_,
            'RSet'                  : self.rset,
            'Scale'                 : self.scale,
            'Seek'                  : self.seek,
            'SelectCase'            : self.selectcase,
            'SelectIs'              : self.selectis,
            'SelectType'            : self.selecttype,
            'SetStmt'               : self.setstmt,
            'Stack'                 : self.stack,
            'Stop'                  : self.stop,
            'Type'                  : self.type_,
            'Unlock'                : self.unlock,
            'VarDefn'               : self.vardefn,
            'Wend'                  : self.wend,
            'While'                 : self.while_,
            'With'                  : self.with_,
            'WriteChan'             : self.writechan,
            'ConstFuncExpr'         : self.constfuncexpr,
            'LbConst'               : self.lbconst,
            'LbIf'                  : self.lbif,
            'LbElse'                : self.lbelse,
            'LbElseIf'              : self.lbelseif,
            'LbEndIf'               : self.lbendif,
            'LbMark'                : self.lbmark,
            'EndForVariable'        : self.endforvariable,
            'StartForVariable'      : self.startforvariable,
            'NewRedim'              : self.newredim,
            'StartWithExpr'         : self.startwithexpr,
            'SetOrSt'               : self.setorst,
            'EndEnum'               : self.endenum,
            'Illegal'               : self.illegal,
            'NewLine'               : self.newline
        }

    def imp(self):
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        val = arg1 + ' Imp ' + arg2
        self.opstack.push(val)

    def eqv(self):
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        val = arg1 + ' Eqv ' + arg2
        self.opstack.push(val)

    def xor(self):
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        val = arg1 + ' Xor ' + arg2
        self.opstack.push(val)

    def or_(self):
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        val = arg1 + ' Or ' + arg2
        self.opstack.push(val)

    def and_(self):
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        val = arg1 + ' And ' + arg2
        self.opstack.push(val)

    def eq(self):
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        val = arg1 + ' = ' + arg2
        self.opstack.push(val)

    def ne(self):
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        val = arg1 + ' <> ' + arg2
        self.opstack.push(val)

    def le(self):
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        val = arg1 + ' <= ' + arg2
        self.opstack.push(val)

    def ge(self):
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        val = arg1 + ' >= ' + arg2
        self.opstack.push(val)

    def lt(self):
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        val = arg1 + ' < ' + arg2
        self.opstack.push(val)

    def gt(self):
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        val = arg1 + ' > ' + arg2
        self.opstack.push(val)

    # ex opeline: "Add"
    # gets the two values on stack, pop them, add them and push again
    def add(self):
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        val = arg1 + ' + ' + arg2
        self.opstack.push(val)

    def sub(self):
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        val = arg1 + ' - ' + arg2
        self.opstack.push(val)

    def mod(self):
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        val = arg1 + ' Mod ' + arg2
        self.opstack.push(val)

    def idiv(self):
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        val = arg1 + ' \\ ' + arg2
        self.opstack.push(val)

    def mul(self):
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        val = arg1 + ' * ' + arg2
        self.opstack.push(val)

    def div(self):
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        val = arg1 + ' / ' + arg2
        self.opstack.push(val)

    def concat(self):
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        val = arg1 + ' & ' + arg2
        self.opstack.push(val)

    def like(self):
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        val = arg1 + ' Like ' + arg2
        self.opstack.push(val)

    def pwr(self):
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        val = arg1 + ' ^ ' + arg2
        self.opstack.push(val)

    def is_(self):
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        val = arg1 + ' Is ' + arg2
        self.opstack.push(val)

    def not_(self):
        val = 'Not ' + self.opstack.pop()
        self.opstack.push(val)

    def umi(self):
        val = '-' + self.opstack.pop()
        self.opstack.push(val)

    def fnabs(self):
        arg = self.opstack.pop()
        val = 'Abs(' + arg + ')'
        self.opstack.push(val)

    def fnfix(self):
        arg = self.opstack.pop()
        val = 'Fix(' + arg + ')'
        self.opstack.push(val)

    def fnint(self):
        arg = self.opstack.pop()
        val = 'int(' + arg + ')'
        self.opstack.push(val)

    def fnsgn(self):
        arg = self.opstack.pop()
        val = 'Sgn(' + arg + ')'
        self.opstack.push(val)

    def fnlen(self):
        arg = self.opstack.pop()
        val = 'Len(' + arg + ')'
        self.opstack.push(val)

    def fnlenb(self):
        arg = self.opstack.pop()
        val = 'LenB(' + arg + ')'
        self.opstack.push(val)

    def paren(self):
        arg = self.opstack.pop()
        val = '(' + arg + ')'
        self.opstack.push(val)

    def sharp(self):
        arg = self.opstack.pop()
        val = '#' + arg
        self.opstack.push(val)

    def ldlhs(self):
        raise Pcode2codeException('not implemented ldlhs')

    def ld(self, var):
        """
        command defining a variable
        example: X = Y
        gives:
             # Ld Y
             # St X
        """
        if var == 'id_FFFF': #hacky way to do it because me does not seem to be fully
            var = 'Me'       #parsed by pcodedmp
        self.opstack.push(var)

    def memld(self, var):
        val = self.opstack.pop() + '.' + var
        self.opstack.push(val)

    def dictld(self, var):
        """
        cf fields and collections, also index???
        example: Debug.Print rsTable!Title
        gives:
             # Debug
             # PrintObj
             # Ld rsTable
             # DictLd Title
             # PrintItemNL
        """
        self.opstack.push(self.opstack.pop()+ '!' + var)

    def indexld(self, *args):
        raise Pcode2codeException('not implemented indexld')

    def argsld(self, varname, numparams):
        val = varname + '('
        nb_parameters = int(numparams, 16)
        params = []
        if nb_parameters > 0:
            for i in range(nb_parameters):
                params.append(self.opstack.pop())
            params = params[::-1]
            val = val + params[0]
            
            if nb_parameters > 1:
                for param in params[1:]:
                    val = val + ', ' + param
        val += ')'
        self.opstack.push(val)

    def argsmemld(self, var, numparams):
        nb_parameters = int(numparams, 16)
        val = self.opstack.pop() + '.' + var + '('
        params = []
        if nb_parameters > 0:
            for i in range(nb_parameters):
                params.append(self.opstack.pop())
            params = params[::-1]
            val = val + params[0]

            if nb_parameters > 1:
                for param in params[1:]:
                    val = val + ', ' + param
        val += ')'
        self.opstack.push(val)

    def argsdictld(self, var, numparams):
        """
        command used when an index of an object with an argument is accessed
        example: Debug.Print myobj!toto("titi") 
        gives:
             # Debug
             # PrintObj
             # LitStr 0x0004 "titi"
             # Ld myobj
             # ArgsDictLd toto 0x0001
             # PrintItemNL
        """
        nb_parameters = int(numparams, 16)
        val = self.opstack.pop() + '!' + var + '('
        params = []
        if nb_parameters > 0:
            for i in range(nb_parameters):
                params.append(self.opstack.pop())
            params = params[::-1]
            val = val + params[0]

            if nb_parameters > 1:
                for param in params[1:]:
                    val = val + ', ' + param
        val += ')'
        self.opstack.push(val)

    # example line : Function giqw(str As String) As Variant: Dim bytes() As Byte: bytes = str: giqw = bytes: End Function
    # op line:
    # Line #13:
    #     FuncDefn (Function giqw(str As String) As Variant)
    #     BoS 0x0000 
    #     Dim 
    #     VarDefn bytes (As Byte)
    #     BoS 0x0000 
    #     Ld str 
    #     St bytes 
    #     BoS 0x0000 
    #     Ld bytes 
    #     St giqw 
    #     BoS 0x0000 
    #     EndFunc 
    def st(self, arg):
        param = self.opstack.pop()
        val = arg + ' = ' + param
        self.opstack.push(val)

    def memst(self, var):
        val = self.opstack.pop() + '.' + var
        val = val + ' = ' + self.opstack.pop()
        self.opstack.push(val)

    def dictst(self, var):
        """
        command used when an index is defined directly
        example: myobj!titi = "toto"
        gives:
             # LitStr 0x0004 "toto"
             # Ld myobj
             # DictSt titi
        """
        val = self.opstack.pop() + '!' + var + ' = ' + self.opstack.pop()
        self.opstack.push(val)

    def indexst(self, *args):
        raise Pcode2codeException('not implemented indexst')

    # TODO: to check
    def argsst(self, var, numparams):
        nb_parameters = int(numparams, 16)
        params = []
        if nb_parameters > 0:
            for i in range(nb_parameters):
                params.append(self.opstack.pop())
            params = params[::-1]
            val = var + '(' + params[0]
            if nb_parameters > 1:
                for param in params[1:]:
                    val = val + ', ' + param
            val += ')'

        param2 = self.opstack.pop()
        val += ' = ' + param2
        self.opstack.push(val)

    def argsmemst(self, var, numparams):
        #TODO: to check
        val = self.opstack.pop() + '.'
        nb_parameters = int(numparams,16)
        params = []
        if nb_parameters > 0:
            for i in range(nb_parameters):
                params.append(self.opstack.pop())
            params = params[::-1]
            val = val + var + '(' + params[0]
            if nb_parameters > 1:
                for param in params[1:]:
                    val = val + ', ' + param
            val += ')'

        param2 = self.opstack.pop()
        val += ' = ' + param2
        self.opstack.push(val)

    def argsdictst(self, var, numparams):
        """
        used when an index of an obj with an argument is defined
        example: myobj!titi2("toto") = "toto"
        gives:
             # LitStr 0x0004 "toto"
             # LitStr 0x0004 "toto"
             # Ld myobj
             # ArgsDictSt titi2 0x0001
        """
        val = self.opstack.pop() + '!' 
        nb_parameters = int(numparams,16)
        params = []
        if nb_parameters > 0:
            for i in range(nb_parameters):
                params.append(self.opstack.pop())
            params = params[::-1]
            val = val + var + '(' + params[0]
            if nb_parameters > 1:
                for param in params[1:]:
                    val = val + ', ' + param
            val += ')'

        param2 = self.opstack.pop()
        val += ' = ' + param2
        self.opstack.push(val)
        
        
        
    def set_(self, var):
        val = 'Set ' + var + ' = ' + self.opstack.pop()
        self.opstack.push(val)

    def memset(self, var):
        """
        obtained when a property of an object is set
        example: Set YourObject.Text = lobject
        gives:
             # SetStmt
             # Ld lobject
             # Ld YourObject
             # Memset Text
        """
        val = 'Set ' + self.opstack.pop() + '.' + var + ' = ' + self.opstack.pop()
        self.opstack.push(val)
        
    def dictset(self, var):
        """
        obtained when an index of an object is set
        example: Set YourObject!Text = lobject
        gives:
             # SetStmt
             # Ld lobject
             # Ld YourObject
             # Dictset Text
        """
        val = 'Set ' + self.opstack.pop() + '!' + var + ' = ' + self.opstack.pop()
        self.opstack.push(val)


    def indexset(self, *args):
        raise Pcode2codeException('not implemented indexset')

    def argsset(self, var, nb):
        """
        obtained when an argument of an object is set
        example: Set YourObject(ggg) = lobject
        gives:
             # SetStmt
             # Ld lobject
             # Ld ggg
             # ArgsSet YourObject 0x0001
        """
        val = 'Set ' + var + '(' + self.opstack.pop() + ') = ' + self.opstack.pop()
        self.opstack.push(val)

    def argsmemset(self, var, numparams):
        """
        obtained when an argument of a property of an object is set
        example: Set YourObject.Text2("titi") = lobject
        gives:
             # SetStmt
             # Ld lobject
             # LitStr 0x0004 "titi"
             # Ld YourObject
             # ArgsMemSet Text2 0x0001
        """
        nb_parameters = int(numparams, 16)
        val = 'Set ' + self.opstack.pop() + '.' + var + '('
        params = []
        if nb_parameters > 0:
            for i in range(nb_parameters):
                params.append(self.opstack.pop())
            params = params[::-1]
            val = val + params[0]

            if nb_parameters > 1:
                for param in params[1:]:
                    val = val + ', ' + param
        val += ') = ' + self.opstack.pop()
        self.opstack.push(val)

        
    def argsdictset(self, var, numparams):
        """
        obtained when an argument of a property of an object is set
        example: Set YourObject.Text2("titi") = lobject
        gives:
             # SetStmt
             # Ld lobject
             # LitStr 0x0004 "titi"
             # Ld YourObject
             # ArgsMemSet Text2 0x0001
        """
        nb_parameters = int(numparams, 16)
        val = 'Set ' + self.opstack.pop() + '!' + var + '('
        params = []
        if nb_parameters > 0:
            for i in range(nb_parameters):
                params.append(self.opstack.pop())
            params = params[::-1]
            val = val + params[0]

            if nb_parameters > 1:
                for param in params[1:]:
                    val = val + ', ' + param
        val += ') = ' + self.opstack.pop()
        self.opstack.push(val)


    def memldwith(self, var):
        """
        command defining a part of an object like .<prop>
        example: with blah <....> .Name 
        gives:  # MemLdWith Name
        """
        self.opstack.push('.' + var)

    def dictldwith(self, var):
        """
        accessing an index in a with block
        example: With <smth>.... Debug.Print !au_lname ... end with
        gives:
             # Debug
             # PrintObj
             # DictLdWith au_lname
             # PrintItemNL
        """
        self.opstack.push('!' + var)

    def argsmemldwith(self, var, numparams):
        """
        example: .CodePane.SetSelection .ProcStartLine(sProc, ProcType) + lLine, 1, .ProcStartLine(sProc, ProcType) + lLine + 1, 1
        gives:
             # Ld sProc
             # Ld ProcType
             # ArgsMemLdWith ProcStartLine 0x0002
             # Ld lLine
             # Add
             # LitDI2 0x0001
             # Ld sProc
             # Ld ProcType
             # ArgsMemLdWith ProcStartLine 0x0002
             # Ld lLine
             # Add
             # LitDI2 0x0001
             # Add
             # LitDI2 0x0001
             # MemLdWith CodePane
             # ArgsMemCall SetSelection 0x0004
        """
        nb_parameters = int(numparams, 16)
        val = '.' + var + '('
        params = []
        if nb_parameters > 0:
            for i in range(nb_parameters):
                params.append(self.opstack.pop())
            params = params[::-1]
            val = val + params[0]

            if nb_parameters > 1:
                for param in params[1:]:
                    val = val + ', ' + param
        val += ')'
        self.opstack.push(val)

        
    def argsdictldwith(self, var, numparams):
        """
        command used when an index of an object with an argument is accessed with a with block
        example: With myobj ... Debug.Print !toto("titi") ... end with
        gives:
             # Debug
             # PrintObj
             # LitStr 0x0004 "titi"
             # ArgsDictLdWith toto 0x0001
             # PrintItemNL
        """
        nb_parameters = int(numparams, 16)
        val = '!' + var + '('
        params = []
        if nb_parameters > 0:
            for i in range(nb_parameters):
                params.append(self.opstack.pop())
            params = params[::-1]
            val = val + params[0]

            if nb_parameters > 1:
                for param in params[1:]:
                    val = val + ', ' + param
        val += ')'
        self.opstack.push(val)


    def memstwith(self, var):
        """
        command defining a part of an object like .<prop> = <smthg>
        example: .Name = "Coho Vineyard"
        gives:
             # LitStr 0x000D "Coho Vineyard"
             # MemStWith Name
        """
        self.opstack.push('.' + var + ' = ' + self.opstack.pop())

        
    def dictstwith(self, var):
        """
        command defining a part of an object like !<index> = <smthg>
        example: With ... !Name = "Coho Vineyard" ... end with
        gives:
             # LitStr 0x000D "Coho Vineyard"
             # DictStWith Name
        """
        self.opstack.push('!' + var + ' = ' + self.opstack.pop())

        
    def argsmemstwith(self, var, numparams):
        """
        command defining a property of an object with arguments in a with statement
        example: With ... .Name(1,2) = b ... end with
        gives:
             # Ld B
             # LitDI2 0x0001
             # LitDI2 0x0002
             # ArgsMemStWith Name 0x0002
        """
        nb_parameters = int(numparams, 16)
        val = '.' + var + '('
        params = []
        if nb_parameters > 0:
            for i in range(nb_parameters):
                params.append(self.opstack.pop())
            params = params[::-1]
            val = val + params[0]

            if nb_parameters > 1:
                for param in params[1:]:
                    val = val + ', ' + param
        val += ') = ' + self.opstack.pop()
        self.opstack.push(val)

    def argsdictstwith(self, var, *args):
        """
        command defining a part of an object like !<index> = <smthg> in a with block
        example: !Name = "Coho Vineyard"
        gives:
             # LitStr 0x000D "Coho Vineyard"
             # DictStWith Name
        """
        self.opstack.push('!' + var + ' = ' + self.opstack.pop())


    def memsetwith(self, var):
        """
        command defining a set on an index of an object in a with block
        example: with <smth> ... Set .Name = "Coho Vineyard"
        gives:
             # SetStmt
             # LitStr 0x000D "Coho Vineyard"
             # memSetWith Name
        """
        self.opstack.push('Set .' + var + ' = ' + self.opstack.pop())

        
    def dictsetwith(self, var):
        """
        command defining a set on an index of an object in a with block
        example: with <smth> ... Set !Name = "Coho Vineyard"
        gives:
             # SetStmt
             # LitStr 0x000D "Coho Vineyard"
             # DictSetWith Name
        """
        self.opstack.push('Set !' + var + ' = ' + self.opstack.pop())

    def argsmemsetwith(self, var, numparams):
        """
        command defining a set on an index with an argument of an object in a with block
        example: with <smth> ... Set .nini("gg", "ff", "uu") = "toto"
        gives:
             # SetStmt
             # LitStr 0x0004 "toto"
             # LitStr 0x0002 "gg"
             # LitStr 0x0002 "ff"
             # LitStr 0x0002 "uu"
             # ArgsMemSetWith nini 0x0003
        """
        nb_parameters = int(numparams, 16)
        val = 'Set !' + var + '('
        params = []
        if nb_parameters > 0:
            for i in range(nb_parameters):
                params.append(self.opstack.pop())
            params = params[::-1]
            val = val + params[0]

            if nb_parameters > 1:
                for param in params[1:]:
                    val = val + ', ' + param
        val += ') = ' + self.opstack.pop()
        self.opstack.push(val)

    def argsdictsetwith(self, var, numparams):
        """
        command defining a set on an index with an argument of an object in a with block
        example: with <smth> ... Set !nini("gg", "ff", "uu") = "toto"
        gives:
             # SetStmt
             # LitStr 0x0004 "toto"
             # LitStr 0x0002 "gg"
             # LitStr 0x0002 "ff"
             # LitStr 0x0002 "uu"
             # ArgsDictSetWith nini 0x0003
        """
        nb_parameters = int(numparams, 16)
        val = 'Set !' + var + '('
        params = []
        if nb_parameters > 0:
            for i in range(nb_parameters):
                params.append(self.opstack.pop())
            params = params[::-1]
            val = val + params[0]

            if nb_parameters > 1:
                for param in params[1:]:
                    val = val + ', ' + param
        val += ') = ' + self.opstack.pop()
        self.opstack.push(val)

    
    def argscall(self, *args):

        if args[0] == '(Call)':
            nb_parameters = int(args[2],16)
            val = 'Call ' + args[1] + '('
            end_val = ')'
        else:
            val = args[0]
            nb_parameters = int(args[1],16)           
            end_val = ''
            
        params = []
        #print 'func:' + funcname
        #print 'nbparameters : ' + str(nb_parameters)
        if nb_parameters > 0:
            for i in range(nb_parameters):
                params.append(self.opstack.pop())
            params = params[::-1]
            if ((params[0].startswith('(')) or (args[0] == '(Call)')):               
                val = val + params[0]
            else:
                val = val + ' ' + params[0]

            if nb_parameters > 1:
                for param in params[1:]:
                    val = val + ', ' + param
            val += end_val
        self.opstack.push(val)

    def argsmemcall(self, *args):
        """
        command to call a function of an object
        example: a43g0xT.run ayUBnLK01, 0
        gives : 
           # Ld ayUBnLK01
           # LitDI2 0x0000
           # Ld a43g0xT
           # ArgsMemCall run 0x0002
        """
        args = list(args)
        parenthesis = False
        if args[0] == '(Call)':
            args.pop(0)
            val = 'Call ' + self.opstack.pop() + '.' + args[0] + '('
            parenthesis = True
        else:
            val = self.opstack.pop() + '.' + args[0]

        nb_parameters = int(args[1],16)           
        end_val = ''
            
        params = []
        if nb_parameters > 0:
            for i in range(nb_parameters):
                params.append(self.opstack.pop())
            params = params[::-1]
            if params[0].startswith('('):               
                val = val + params[0]
                end_val = ')'
            else:
                if not parenthesis:
                    val = val + ' ' +params[0]
                else:
                    val = val + params[0]
            
            if nb_parameters > 1:
                for param in params[1:]:
                    val = val + ', ' + param
        if parenthesis == True:
            end_val = ')'
        self.opstack.push(val + end_val)

    def argsmemcallwith(self, *args):
        """
        command when a function of an object is called in a with definition
        example: With a ... call .a(1,2) ... end with
        gives: 
             # LitDI2 0x0001
             # LitDI2 0x0002
             # ArgsMemCallWith (Call) a 0x0002
        """
        parenthesis = False
        args = list(args)
        if args[0] == '(Call)':
            args.pop(0)
            parenthesis = True
            val = 'Call .' + args[0] + '('
        else:
            val = '.' + args[0]
            
        nb_parameters = int(args[1],16)           
        end_val = ''
            
        params = []
        if nb_parameters > 0:
            for i in range(nb_parameters):
                params.append(self.opstack.pop())
            params = params[::-1]
            if params[0].startswith('('):               
                val = val + params[0]
                end_val = ')'
            else:
                if not parenthesis:
                    val = val + ' ' + params[0]
                else:
                    val = val + params[0]
            
            if nb_parameters > 1:
                for param in params[1:]:
                    val = val + ', ' + param

        if parenthesis:
            end_val = ')'
        self.opstack.push(val + end_val)
        

    def argsarray(self, var, numparams):
        val = var + '('
        nb_parameters = int(numparams,16)
        params = []
        if nb_parameters > 0:
            for i in range(nb_parameters):
                params.append(self.opstack.pop())
            params = params[::-1]
            val = val + params[0]
            
            if nb_parameters > 1:
                for param in params[1:]:
                    val = val + ', ' + param
        val += ')'
        self.opstack.push(val)

    def assert_(self):
        """
        command for debug.asser
        example: Debug.Assert blnAssert
        gives : 
              # Ld blnAssert
              # Assert
        """
        self.opstack.push('Debug.Assert ' + self.opstack.pop())

    def bos(self, valarg):
        arg = int(valarg,16)
        if arg == 0:
            val = self.opstack.pop() + ':'
        self.opstack.push(val)
        self.has_bos = True

    def bosimplicit(self, *args):
        """
        appears useless, but in this case we still need to print whole stack
        example: If Mid$(theString, i, 1) <> Chr$(0) Then Exit For
        gives:
             # Ld theString
             # Ld i
             # LitDI2 0x0001
             # ArgsLd Mid$ 0x0003
             # LitDI2 0x0000
             # ArgsLd Chr$ 0x0001
             # Ne
             # If
             # BoSImplicit
             # ExitFor
             # EndIf
        """
        self.has_bos = True
        
    def bol(self, *args):
        raise Pcode2codeException('not implemented bol')

    def ldaddressof(self, var):
        """
        command for AddressOf keyword
        example: EnumFontFamilies hDC, vbNullString, AddressOf EnumFontFamProc, LB
        gives:
             # Ld hDC
             # Ld vbNullString
             # LdAddressOf EnumFontFamProc
             # Ld LB
             # ArgsCall EnumFontFamilies 0x0004
        """
        self.opstack.push('AddressOf ' + var)

    def memaddressof(self, var):
        """
        command for AddressOf keyword on a property of an object
        example: MsgBox AddressOf myobj.toto
        gives:
             # Ld myobj
             # MemAddressOf toto
             # ArgsCall MsgBox 0x0001
        """
        self.opstack.push('AddressOf ' + self.opstack.pop() + '.' + var)

    def case(self):
        """
        command handling choice in select case where choice is one value 
        example: Case 0
        gives:
             # LitDI2 0x0000
             # Case
             # CaseDone

        """
        self.opstack.push('Case ' + self.opstack.pop())

    def caseto(self):
        """
        command handling choice in select case where choice is from one value to one other value
        example: Case 0 To 30
        gives:
             # LitDI2 0x0000
             # LitDI2 0x001E
             # CaseTo
             # CaseDone
        """
        val = self.opstack.pop()
        self.opstack.push('Case ' + self.opstack.pop() + ' To ' + val)


    def casegt(self):
        """
        command handling choice in select case where choice is lower than a value
        example: Case Is > 100
        gives:
             # LitDI2 0x0064
             # CaseGt
             # CaseDone
        """
        self.opstack.push('Case Is > ' + self.opstack.pop())

    def caselt(self):
        """
        command handling choice in select case where choice is lower than a value
        example: Case Is < 0
        gives:
             # LitDI2 0x0002
             # CaseLt
             # CaseDone
        """
        self.opstack.push('Case Is < ' + self.opstack.pop())

    def casege(self):
        """
        command handling choice in select case where choice is greater or equal than a value
        example: TODO: to check
        gives:
        """
        self.opstack.push('Case Is >= ' + self.opstack.pop())

    def casele(self):
        """
        command handling choice in select case where choice is lower or equal than a value
        example: TODO: to check
        gives:
        """
        self.opstack.push('Case Is <= ' + self.opstack.pop())

    def casene(self):
        """
        command handling choice in select case where choice is different to a value
        example: TODO: to check
        gives:
        """
        self.opstack.push('Case Is <> ' + self.opstack.pop())

    def caseeq(self):
        """
        command handling choice in select case where choice is equal to a value
        example: TODO: to check
        gives:
        """
        self.opstack.push('Case Is = ' + self.opstack.pop())

    def caseelse(self):
        """
        command defining a "Case Else" stmt
        example: Case Else
        gives: 
             # CaseElse
        """
        self.opstack.push('Case Else')

    def casedone(self):
        #pass on purpose, please see previous examples
        pass

    def circle(self, useless):
        """
        command used when the circle method of an object is called
        example: Me.Circle (sngHCtr, sngVCtr), sngRadius
        gives:
             # Ld sngHCtr
             # Ld sngVCtr
             # Ld sngRadius
             # LitDI2 0x0000
             # LitDI2 0x0000
             # LitDI2 0x0000
             # LitDI2 0x0000
             # Ld id_FFFF
             # Circle 0x001E
        """
        val = self.opstack.pop() + '.Circle ('
        params = []
        for i in range(7):
            params.append(self.opstack.pop())
        params = params[::-1]

        val += params[0] + ', ' + params[1] + '), ' + params[2]
        all_empty = True
        for param in params[3:]:
            if param != '0':
                all_empty = False

        if all_empty:
            self.opstack.push(val)
        else:
            for param in params[3:]:
                if param == '0':
                    val = val + ', <tbr>'
                else:
                    val = val + ', ' + param
            val = val.replace(', <tbr>' , '')
            self.opstack.push(val)


    def close(self, numparams):
        val = 'Close '
        nb_parameters = int(numparams,16)
        params = []
        if nb_parameters > 0:
            for i in range(nb_parameters):
                params.append(self.opstack.pop())
            params = params[::-1]
            val = val + params[0]
            
            if nb_parameters > 1:
                for param in params[1:]:
                    val = val + ', ' + param
        self.opstack.push(val)

    def closeall(self):
        """
        command used when close is called with no arguments, effectively closing all files
        example: Close
        gives: # CloseAll
        """
        self.opstack.push('Close')

    def coerce_(self, arg):
        """
        command used for variable conversion
        example1: MyLong2 = CLng(MyVal2)
        gives:
             # Ld MyVal2
             # Coerce (Lng)
             # St MyLong2
        example2: MyInt = CInt(MyDouble)
        gives:
             # Ld MyDouble
             # Coerce (Int)
             # St MyInt
        """
        if arg == '(Str)':
            self.opstack.push('CStr(' + self.opstack.pop() + ')')
        elif arg == '(Var)':
            self.opstack.push('CVar(' + self.opstack.pop() + ')')
        elif arg == '(Sng)':
            self.opstack.push('CSng(' + self.opstack.pop() + ')')
        elif arg == '(Lng)':
            self.opstack.push('CLng(' + self.opstack.pop() + ')')
        elif arg == '(Int)':
            self.opstack.push('CInt(' + self.opstack.pop() + ')')
        elif arg == '(Dbl)':
            self.opstack.push('CDbl(' + self.opstack.pop() + ')')
        elif arg == '(Date)':
            self.opstack.push('CDate(' + self.opstack.pop() + ')')
        elif arg == '(Cur)':
            self.opstack.push('CCur(' + self.opstack.pop() + ')')
        elif arg == '(Byte)':
            self.opstack.push('CByte(' + self.opstack.pop() + ')')
        elif arg == '(Bool)':
            self.opstack.push('CBool(' + self.opstack.pop() + ')')
        else:
            raise Pcode2codeException('not implemented coerce')
        
    def coercevar(self, arg):
        """
        example1: MyError = CVErr(32767)
        gives: # CoerceVar (Err)
        """
        if arg == '(Err)':
            self.opstack.push('CVErr(' + self.opstack.pop() + ')')
        else:
            raise Pcode2codeException('not implemented coercevar')

    def context(self, *args):
        raise Pcode2codeException('not implemented context')

    def debug(self):
        """
        seems used to invoke debug object
        example: Debug.Print MyVar
        gives:
             # Debug
             # PrintObj
             # Ld MyVar
             # PrintItemNL
        """
        self.opstack.push('Debug')

    def deftype(self, *args):
        """
        command used when def<type> is used.
        TODO: bytes to know ranges appear random. How to do it?
        """
        raise Pcode2codeException('not implemented deftype')

    # Dim hiz7dgus As String
    # Private Const DefaultBufferSize& = 32768
    # Private CRC_32_Tab(0 To 255) As Long
    # ======================
    # Line #7:
    # 	Dim 
    # 	VarDefn hiz7dgus (As String)
    # Line #8:
    # Line #9:
    # 	Dim (Private Const) 
    # 	LitDI4 0x8000 0x0000 
    # 	VarDefn DefaultBufferSize
    # Line #10:
    # Line #11:
    # 	Dim (Private) 
    # 	LitDI2 0x0000 
    # 	LitDI2 0x00FF 
    # 	VarDefn CRC_32_Tab (As Long)
    def dim(self, *args):
        # args is a tuple, we treat it only when its not empty
        # example of args : (As String), (As Long)...
        if args != ():
            val = args[0]
            for arg in args[1:]:
                val += ' ' + arg
            val = val[1:-1]
        else:
            val = 'Dim'
        self.opstack.push(val)

    def dimimplicit(self):
        self.opstack.push('DimImplicit')

    def do(self):
        """
        command handling "Do" keyword
        example: Do (we have then the loop and so on)
        gives:
             # Do
        """
        self.opstack.push('Do')
        self.indentincrease_future = True

    def doevents(self, *args):
        raise Pcode2codeException('not implemented doevents')

    def dounitil(self):
        """
        command handling "do until" definitions
        example: Do Until Response = "youpi"
        gives:
             # Ld Response
             # ListStr 0x0005 "youpi"
             # Eq
             # DoUnitil
        """
        self.opstack.push('Do Until ' + self.opstack.pop())
        self.indentincrease_future = True

    def dowhile(self):
        """
        command handling "do while" definitions
        example: Do While Reponse <> "youpi"
        gives:
             # Ld Response
             # LitStr 0x0005 "youpi"
             # Ne
             # DoWhile
        """
        self.opstack.push('Do While ' + self.opstack.pop())
        self.indentincrease_future = True

    def else_(self):
        """
        command used for a "else" in a if oneliner
        example: If X < 4 Then MsgBox "hi" Else MsgBox "ho"
        gives:
             # Ld X
             # LitDI2 0x0004
             # Lt
             # If
             # BoSImplicit
             # LitStr 0x0002 "hi"
             # ArgsCall MsgBox 0x0001
             # Else
             # BoSImplicit
             # LitStr 0x0002 "Ho"
             # ArgsCall MsgBox 0x0001
             # EndIf
        """
        self.opstack.push('Else')

    def elseblock(self):
        """
        command defining a new "else" for a block
        example: Else
        gives: #Else
        """
        self.opstack.push('Else')
        self.indentlevel = self.indentlevel - 1
        self.indentincrease_future = True

    def elseifblock(self):
        """
        command defining a new "else if" block
        example: ElseIf dayW = DayOfWeek.Thursday Then
        gives:
             # Ld dayW
             # Ld DayOfWeek
             # MemLd Thursday
             # Eq
             # ElseIfBlock
        """
        self.opstack.push('ElseIf ' + self.opstack.pop() + ' Then')
        self.indentlevel = self.indentlevel - 1
        self.indentincrease_future = True

    def elseiftypeblock(self, *args):
        raise Pcode2codeException('not implemented elseiftypeblock')

    def end(self):
        self.opstack.push('End')

    def endcontext(self, *args):
        raise Pcode2codeException('not implemented endcontext')

    def endfunc(self):
        self.opstack.push('End Function')
        self.indentlevel = self.indentlevel - 1

    def endif(self):
        if self.onelineif == True:
            self.onelineif = False
        else:
            self.opstack.push('End If')
            self.indentlevel = self.indentlevel - 1

    def endifblock(self):
        self.opstack.push('End If')
        self.indentlevel = self.indentlevel - 1

    def endimmediate(self, *args):
        raise Pcode2codeException('not implemented endimmediate')

    def endprop(self):
        """
        command handling the end of a property
        example: End Property
        gives: 
             #EndProp
        """
        self.opstack.push('End Property')
        self.indentlevel = self.indentlevel -1

    def endselect(self):
        """
        command defining a stmt of "End Select", closing a select case.
        example: End Select
        gives: 
             # EndSelect
        """
        self.opstack.push('End Select')
        self.indentlevel = self.indentlevel - 1

    def endsub(self):
        self.opstack.push('End Sub')
        self.indentlevel = self.indentlevel - 1

    def endtype(self):
        """
        command to end a new type definition
        example: End Type
        gives:
             #EndType
        """
        self.opstack.push('End Type')
        self.indentlevel = self.indentlevel - 1

    def endwith(self):
        """
        command to end a new with definition
        example: End With
        gives: #EndWith
        """
        self.opstack.push('End With')
        self.indentlevel = self.indentlevel - 1
        

    def erase(self, nb_params):
        """
        command for Erase function keyword
        example: Erase threeDimArray, twoDimArray
        gives:
             # Ld threeDimArray
             # Ld twoDimArray
             # Erase 0x0002
        """
        nb_args = int(nb_params, 16)
        val = ''
        params = []
        for i in range(nb_args):
            params.append(self.opstack.pop())
            params = params[::-1]
        val = params[0]
            
        if nb_args > 1:
            for param in params[1:]:
                val = val + ', ' + param

        self.opstack.push('Erase ' + val)


    def error(self):
        """
        command used for Error keyword
        example: Error 11
        gives:
             # LitDI2 0x000B
             # Error
        """
        self.opstack.push('Error ' + self.opstack.pop())

    def eventdecl(self, *args):
        """
        command for declaring a new event in VBA
        example: Event LogonCompleted(UserName As String)
        gives : 
           # EventDecl (Sub LogonCompleted(UserName As String))
        """
        val = args[1]
        for arg in args[2:-1]: #strip parenthesis
            val += ' ' + arg
        self.opstack.push('Event ' + val + ' ' + args[-1][:-1])

    def raiseevent(self, evt_name, nb_params):
        """
        command when RaiseEvent is used
        example: RaiseEvent LogonCompleted("AntoineJean")
        gives:
             # LitStr 0x000A "AntoineJan"
             # RaiseEvent LogonCompleted 0x0001
        """
        nb_args = int(nb_params, 16)
        val = ''
        params = []
        if nb_args > 0:
            for i in range(nb_args):
                params.append(self.opstack.pop())
            params = params[::-1]
            val = '('+ params[0]
            
            if nb_args > 1:
                for param in params[1:]:
                    val = val + ', ' + param
            val += ')'
                    
        self.opstack.push('RaiseEvent ' + evt_name + val)
            

    def argsmemraiseevent(self, var, numparams):
        """
        command used when a raiseevent is called on a property of an object
        example: RaiseEvent myobj.LogonCompleted("AntoineJan")
        gives:
             # LitStr 0x000A "AntoineJan"
             # Ld myobj
             # ArgsMemRaiseEvent LogonCompleted 0x0001
        """
        nb_args = int(numparams, 16)
        val = 'RaiseEvent ' + self.opstack.pop() + '.' + var + '('
        params = []
        if nb_args > 0:
            for i in range(nb_args):
                params.append(self.opstack.pop())
            params = params[::-1]
            val += params[0]
            
            if nb_args > 1:
                for param in params[1:]:
                    val = val + ', ' + param
            val += ')'
        self.opstack.push(val)

    def argsmemraiseeventwith(self, var, numparams):
        """
        command used when a raiseevent is called on a property of an object within a with block
        example: with myobj ... RaiseEvent .LogonCompleted("AntoineJan") ... end with
        gives:
             # LitStr 0x000A "AntoineJan"
             # ArgsMemRaiseEventWith LogonCompleted 0x0001
        """
        nb_args = int(numparams, 16)
        val = 'RaiseEvent .' + var + '('
        params = []
        if nb_args > 0:
            for i in range(nb_args):
                params.append(self.opstack.pop())
            params = params[::-1]
            val += params[0]
            
            if nb_args > 1:
                for param in params[1:]:
                    val = val + ', ' + param
            val += ')'
        self.opstack.push(val)
    
    def exitdo(self):
        #TODO: comment
        self.opstack.push('Exit Do')

    def exitfor(self):
        #TODO: comment
        self.opstack.push('Exit For')

    def exitfunc(self):
        #TODO: comment
        self.opstack.push('Exit Function')
    
    def exitprop(self):
        #TODO: comment
        self.opstack.push('Exit Property')
    
    def exitsub(self):
        #TODO: comment
        self.opstack.push('Exit Sub')
    
    def fncurdir(self, *args):
        #val = 'CurDir(' + self.opstack.pop() + ')'
        #self.opstack.push(val)
        raise Pcode2codeException('not implemented fncurdir')
    
    def fndir(self, *args):
        raise Pcode2codeException('not implemented fndir')
    
    def empty0(self, *args):
        raise Pcode2codeException('not implemented empty0')
    
    def empty1(self, *args):
        raise Pcode2codeException('not implemented empty1')
    
    def fnerror(self, *args):
        raise Pcode2codeException('not implemented fnerror')
    
    def fnformat(self, *args):
        raise Pcode2codeException('not implemented format')
    
    def fnfreefile(self, *args):
        raise Pcode2codeException('not implemented fnfreefile')
    
    def fninstr(self):
        """
        command used when calling Instr function with 2 arguments
        example: MyPos = InStr(SearchString, SearchChar)
        gives:
             # Ld SearchString
             # Ld SearchChar
             # FnInStr
             # St MyPos
        """
        arg2 = self.opstack.pop()
        self.opstack.push('Instr(' + self.opstack.pop() + ', ' + arg2 + ')')
    
    def fninstr3(self):
        """
        command used when calling Instr function with 3 arguments
        example: MyPos = InStr(1, SearchString, "W")
        gives:
             # LitDI2 0x0001
             # Ld SearchString
             # LitStr 0x0001 "W"
             # FnInStr3
             # St MyPos
        """
        arg3 = self.opstack.pop()
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        self.opstack.push('Instr(' + arg1 + ', ' + arg2 + ', ' + arg3 + ')')
    
    def fninstr4(self):
        """
        command used when calling Instr function with 4 arguments
        example: MyPos = InStr(4, SearchString, SearchChar, 1)
        gives:
             # LitDI2 0x0004
             # Ld SearchString
             # Ld SearchChar
             # LitDI2 0x0001
             # FnInStr4
             # St MyPos
        """
        arg4 = self.opstack.pop()
        arg3 = self.opstack.pop()
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        self.opstack.push('Instr(' + arg1 + ', ' + arg2 + ', ' + arg3 + ', ' + arg4 + ')')
    
    def fninstrb(self):
        """
        command used when calling InstrB function with 2 arguments
        example: TODO: make sure here
        gives:
        """
        arg2 = self.opstack.pop()
        self.opstack.push('InstrB(' + self.opstack.pop() + ', ' + arg2 + ')')

        
    def fninstrb3(self):
        """
        command used when calling InstrB function with 3 arguments
        example: TODO: make sure here
        gives:

        """
        arg3 = self.opstack.pop()
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        self.opstack.push('InstrB(' + arg1 + ', ' + arg2 + ', ' + arg3 + ')')

        
    def fninstrb4(self):
        """
        command used when calling InstrB function with 4 arguments
        example: TODO: make sure here
        gives:

        """
        arg4 = self.opstack.pop()
        arg3 = self.opstack.pop()
        arg2 = self.opstack.pop()
        arg1 = self.opstack.pop()
        self.opstack.push('Instr(' + arg1 + ', ' + arg2 + ', ' + arg3 + ', ' + arg4 + ')')
    
    def fnlbound(self, arg):
        """
        command indicating the use of the LBound function
        strangely enough, there is an indication of the number of arguments to be popped out of the stack
        but this number is not good.
        example: Lower = LBound(TwoDArray, 2)
        gives: 
             # Ld TwoDArray
             # LitDI2 0x0002
             # FnLBound 0x0001
             # St Lower
        """
        nb_parameters = int(arg,16) + 1
        params = []
        val = '('
        if nb_parameters > 0:
            for i in range(nb_parameters):
                params.append(self.opstack.pop())
            params = params[::-1]
            val = val + params[0]
            
            if nb_parameters > 1:
                for param in params[1:]:
                    val = val + ', ' + param
        val += ')'
        val = 'LBound' + val
        self.opstack.push(val)
    
    def fnmid(self):
        val = 'Mid(' + self.opstack.pop() + ')'
        self.opstack.push(val)
    
    def fnmidb(self):
        val = 'MidB(' + self.opstack.pop() + ')'
        self.opstack.push(val)
    
    def fnstrcomp(self):
        """
        command used when strcomp function with 2 arguments is called
        example: MyComp = StrComp(MyStr2, MyStr1)
        gives:
             # Ld MyStr2
             # Ld MyStr1
             # FnStrComp
             # St MyComp
        """
        str2 = self.opstack.pop()
        str1 = self.opstack.pop()
        self.opstack.push('StrComp(' + str1 + ', ' + str2 + ')')
            
    def fnstrcomp3(self):
        """
        command used when strcomp function with 3 arguments is called
        example: MyComp = StrComp(MyStr1, MyStr2, 0)
        gives:
             # Ld MyStr1
             # Ld MyStr2
             # LitDI2 0x0000
             # FnStrComp3
             # St MyComp
        """
        third_arg = self.opstack.pop()
        str2 = self.opstack.pop()
        str1 = self.opstack.pop()
        self.opstack.push('StrComp(' + str1 + ', ' + str2 + ', ' + third_arg + ')')
    
    def fnstringvar(self, *args):
        raise Pcode2codeException('not implemented fnstringvar')
    
    def fnstringstr(self, *args):
        raise Pcode2codeException('not implemented fnstringstr')
   
    def fnubound(self, arg):
        """
        command used when calling Ubound function
        example: uL = UBound(sb_)
        gives:     
             # Ld sb_ 
             # FnUBound 0x0000 
             # St uL
        """
        nb_parameters = int(arg,16) + 1
        params = []
        val = '('
        if nb_parameters > 0:
            for i in range(nb_parameters):
                params.append(self.opstack.pop())
            params = params[::-1]
            val = val + params[0]
            
            if nb_parameters > 1:
                for param in params[1:]:
                    val = val + ', ' + param
        val += ')'
        val = 'UBound' + val
        self.opstack.push(val)
            
    def for_(self):
        maxvar = self.opstack.pop()
        minvar = self.opstack.pop()
        loopvar = self.opstack.pop()
        val = 'For ' + loopvar + ' = ' + minvar + ' To ' + maxvar
        self.opstack.push(val)
        self.indentincrease_future = True
            
    def foreach(self):
        """
        command defining a new for each loop definition
        example: For Each MyObject In MyClasses
        gives:
             # StartForVariable
             # Ld MyObject
             # EndForVariable
             # Ld MyClasses
             # ForEach
        """
        collect = self.opstack.pop()
        loopvar = self.opstack.pop()
        val = 'For Each ' + loopvar + ' In ' + collect
        self.opstack.push(val)
        self.indentincrease_future = True
    
    def foreachas(self, *args):
        raise Pcode2codeException('not implemented foreachas')
            
    def forstep(self):
        step = self.opstack.pop()
        maxvar = self.opstack.pop()
        minvar = self.opstack.pop()
        loopvar = self.opstack.pop()
        val = 'For ' + loopvar + ' = ' + minvar + ' To ' + maxvar + ' Step ' + step
        self.opstack.push(val)
        self.indentincrease_future = True
            
    def funcdefn(self, *args: str):
        val = args[0]
        for arg in args[1:]:
            val += ' ' + arg
        val = val[1:-1]
        self.opstack.push(val)
        if not val.startswith('Declare'):
            self.indentincrease_future = True
            
    def funcdefnsave(self, *args):
        raise Pcode2codeException('not implemented funcdefnsave')
            
    def getrec(self):
        """
        command to Get from a channel with a record: get channel, record, var
        example: Get #1, RecordNumber, MyRecord
        gives:
             # LitDI2 0x0001
             # Sharp
             # Ld RecordNumber
             # Ld MyRecord
             # GetRec
        """
        record = self.opstack.pop()
        record_num = self.opstack.pop()
        chan = self.opstack.pop()
        if chan is not None:
            self.opstack.push('Get ' + chan + ', ' + record_num + ', ' + record)
        else:
            self.opstack.push('Get ' + record_num + ', , ' + record) # kindly ugly
            
    def gosub(self, var):
        """
        command used when gosub is used
        example: If Num > 0 Then GoSub MyRoutine 
        gives:
             # Ld Num
             # LitDI2 0x0000
             # Gt
             # If
             # BoSImplicit
             # GoSub MyRoutine
             # EndIf
        """
        self.opstack.push('GoSub ' + var)
            
    def goto(self, var):
        """
        command used when a goto <label> is defined
        example: GoTo label1
        gives: # GoTo label1
        """
        self.opstack.push('GoTo ' + var)

            
    def if_(self, *args):
        val = 'If ' + self.opstack.pop() + ' Then'
        self.onelineif = True
        self.opstack.push(val)
    
    def ifblock(self):
        val = 'If ' + self.opstack.pop() + ' Then'
        self.opstack.push(val)
        self.indentincrease_future = True
    
    def typeof(self, *args):
        """
        command used when TypeOf function is used
        TODO: associated type is obscure for now
        """
        raise Pcode2codeException('not implemented typeof')
            
    def iftypeblock(self, *args):
        raise Pcode2codeException('not implemented iftypeblock')
            
    def implements(self, *args):
        """
        command used when Implements instruction is used
        TODO: associated type is obscure for now        
        """
        raise Pcode2codeException('not implemented implements')
            
    def input_(self):
        """
        command used when Input function is called
        example : Input #1, MyString, MyNumber
        gives: 
             # LitDI2 0x0001
             # Sharp
             # Input
             # Ld MyString
             # InputItem
             # Ld MyNumber
             # InputItem
             # InputDone        
        """
        self.opstack.push('Input ' + self.opstack.pop())
        
    def inputdone(self):
        """
        command used when Input function is called
        example : Input #1, MyString, MyNumber
        gives: 
             # LitDI2 0x0001
             # Sharp
             # Input
             # Ld MyString
             # InputItem
             # Ld MyNumber
             # InputItem
             # InputDone        
        """
        elmts = []
        while self.opstack.size() >= 1:
            elmts.append(self.opstack.pop())
        elmts = elmts[::-1]
        val = elmts[0]
        for elmt in elmts[1:]:
            val += elmt
        self.opstack.push(val)

            
    def inputItem(self):
        """
        command used when Input function is called
        example : Input #1, MyString, MyNumber
        gives: 
             # LitDI2 0x0001
             # Sharp
             # Input
             # Ld MyString
             # InputItem
             # Ld MyNumber
             # InputItem
             # InputDone        
        """
        self.opstack.push(', ' + self.opstack.pop())
            
    def label(self, arg):
        """
        command defining a new label
        example: MyString:
        gives:
             # Label MyString
        """
        self.opstack.push(arg+':')
            
    def let(self, *args):
        """
        command used when let keywork is used
        example: Let MyStr  = "Hello World"
        gives:
             # Let
             # LitStr 0x000B "Hello World"
             # St MyStr
        """
        self.opstack.push('Let')
        self.has_bos = True #we use this hackish way to print it even if not in stack top

            
    def line(self, *args):
        raise Pcode2codeException('not implemented line')
            
    def linecont(self, *args):
        #pass on purpose
        pass
            
    def lineInput(self):
        """
        command used when Line Input instruction is used (to read one line at a time a file)
        example: Line Input #1, TextLine
        gives:
             # LitDI2 0x0001
             # Ld TextLine
             # LineInput
        """
        var = self.opstack.pop()
        num_file = self.opstack.pop()
        self.opstack.push('Line Input #' + num_file + ', ' + var)
            
    def linenum(self, *args):
        # ignoring this seems to work fine.
        return
            
    def litcy(self, *args):
        raise Pcode2codeException('not implemented litcy')
            
    def litdate(self, *args):
        """
        command to define a date literal
        TODO: but wtf how to get date?
        example1: MyDate = #2/12/1969#
        gives: LitDate 0x0000 0x0000 0xA780 0x40D8
        example2: MyDate = #2/12/1970#
        gives: LitDate 0x0000 0x0000 0x02C0 0x40D9
        example3: MyDate = #2/12/1971#
        gives: LitDate 0x0000 0x0000 0x5E00 0x40D9
        example4: MyDate = #2/11/1969#
        gives: LitDate 0x0000 0x0000 0xA740 0x40D8
        example5: MyDate = #2/10/1969#
        gives: LitDate 0x0000 0x0000 0xA700 0x40D8
        example6: MyDate = #3/12/1969#
        gives: LitDate 0x0000 0x0000 0xAE80 0x40D8
        example7: MyDate = #4/12/1969#
        gives: LitDate 0x0000 0x0000 0xB640 0x40D8


        1 year = 23360 (0x5b40) si on fait last2bytes.first2bytes
        1 month = 64 (0x40) sur second octet
        1 day = 
        """
        raise Pcode2codeException('a date is defined here, but it cannot be reconstructed')
            
    def litdefault(self):
        """
        appears to be useless
        example: Open "TESTFILE" For Output As #1 
        gives:
             # LitStr 0x0008 "TESTFILE"
             # LitDI2 0x0001
             # Sharp
             # LitDefault
             # Open (For Output)
        example2: Lock #1, RecordNumber
        gives:
             # LitDI2 0x0001
             # Sharp
             # Ld RecordNumber
             # LitDefault
             # Lock
        example3: same for unlock
        """
        #pass on purpose
        pass

    # integer representation on 2 bytes (decimal base10)
    def litdi2(self, value):
        self.opstack.push(str(int(value,16)))

    # integer representation on 4 bytes (decimal base10)
    def litdi4(self, byte1, byte2):
        val = int(byte2+byte1[2:], 16)
        self.opstack.push(str(val))
        
    def litdi8(self, *args):
        raise Pcode2codeException('not implemented litdi8')
            
    def lithi2(self, byte):
        val = byte[2:]
        while val.startswith('0') and len(val) > 1:
            val = val[1:]
        val = '&H' + val
        self.opstack.push(val)
            
    def lithi4(self, byte1, byte2):
        val = byte2[2:]+byte1[2:]
        while val.startswith('0') and len(val) > 1:
            val = val[1:]
        val = '&H' + val
        self.opstack.push(val)
            
    def lithi8(self, *args):
        raise Pcode2codeException('not implemented lithi8')
            
    def litnothing(self):
        """
        command defining the "Nothing" variable
        example: Set Inst = Nothing
        gives:
             # SetStmt
             # LitNothing
             # Set Inst
        """
        self.opstack.push('Nothing')
            
    def litoi2(self, value):
        """
        command used when an octal is defined on a two bytes byte array
        example: B = &O1
        gives:
             # LitOI2 0x0001
             # St B
        """
        var = int(value,16)
        var2 = str(oct(var))[2:]
        self.opstack.push('&O' + var2)
            
    def litoi4(self, byte1, byte2):
        """
        command used when an octal is defined on a two bytes byte array
        example: B = &O12345644444
        gives:
             # LitOI4 0x4924 0x5397
             # St B
        """        
        val = byte2[2:]+byte1[2:]
        var = int(val,16)
        var2 = str(oct(var))[2:]
        self.opstack.push('&O' + var2)
        
            
    def litoi8(self, *args):
        raise Pcode2codeException('not implemented litoi8')
            
    def litr4(self, byte1, byte2):
        """
        command used when a floating point on 32 bit is declared
        """
        val = byte2[2:]+byte1[2:]
        self.opstack.push(str(struct.unpack("!f", bytes.fromhex(val))[0]))
            
    def litr8(self, byte1, byte2, byte3, byte4):
        """
        command used when a floating point on 64 bit is declared
        """
        val = byte4[2:]+byte3[2:]+byte2[2:]+byte1[2:]
        self.opstack.push(str(struct.unpack("!d", bytes.fromhex(val))[0]))
            
    def litsmalli2(self, *args):
        raise Pcode2codeException('not implemented malli2')
            
    def litstr(self, mylen, *args):
        val = args[0]
        for arg in args[1:]:
            val += ' ' + arg
        if len(val)>=2:
            #assert(val[0]=='"' and val[-1]=='"')
            val = val[1:-1]
            val = val.replace('"', '""')
            val = '"' + val + '"'

        self.opstack.push(val)
            
    def litvarspecial(self, var):
        self.opstack.push(var[1:-1])
            
    def lock(self):
        """
        command to lock a record
        example: Lock #1, RecordNumber
        gives:
             # LitDI2 0x0001
             # Sharp
             # Ld RecordNumber
             # LitDefault
             # Lock
        """
        if self.opstack.size() == 3:
            last_record = self.opstack.pop()
            first_record = self.opstack.pop()
            chan = self.opstack.pop()
            self.opstack.push('Lock ' + chan + ', ' + first_record + ' To ' + last_record)
        elif self.opstack.size() == 2:
            record = self.opstack.pop()
            chan = self.opstack.pop()
            self.opstack.push('Lock ' + chan + ', ' + record)
        elif self.opstack.size() == 1:
            chan = self.opstack.pop()
            self.opstack.push('Lock ' + chan)
            
    def loop(self):
        self.opstack.push('Loop')
        self.indentlevel = self.indentlevel - 1
            
    def loopuntil(self):
        """
        command defining a loop until statement for "do"
        example: Loop Until TheName = ""
        gives:
             # Ld TheName
             # LitStr 0x0000 ""
             # Eq
             # LoopUntil
        """
        self.opstack.push('Loop Until ' + self.opstack.pop())
        self.indentlevel = self.indentlevel - 1
            
    def loopwhile(self):
        """
        command handling " while" definitions
        example: Loop While Reponse = 5
        gives:
             # Ld Response
             # LitDI2  0x0005
             # Eq
             # LoopWhile
        """
        self.opstack.push('Loop While ' + self.opstack.pop())
        self.indentlevel = self.indentlevel - 1

            
    def lset(self):
        """
        command for RSet keyword
        example: LSet MyString = "Right->"
        gives:
             # LitStr 0x0007 "Right->"
             # Ld MyString
             # RSet
        """
        var = self.opstack.pop()
        val = self.opstack.pop()
        self.opstack.push('LSet ' + var + ' = ' + val)
            
    def me(self, *args):
        raise Pcode2codeException('not implemented me')
            
    def meimplicit(self, *args):
        """
        command used when the object is the current form
        example: Print 
        gives:
             # MeImplicit
             # PrintObj
             # PrintNL
        """
        self.opstack.push('MeImplicit') #just pushing a specific marker to change treatment later
            
    def memredim(self, *args):
        """
        command used when a property of an object is redim
        example: ReDim myobj.foo(30)
        gives:
             # OptionBase
             # LitDI2 0x001E
             # Ld myobj
             # MemRedim foo 0x0001 (As Variant)
        """
        val = self.opstack.pop()
        args = list(args)
        preserve = False
        if args[0] == '(Preserve)':
            args.pop(0)
            preserve = True

        nb_params = int(args[1], 16)

        values = []
        # gather all stack
        while self.opstack.size() > 0:
            values.append(self.opstack.pop())
        values = values[::-1]

        if values[0].startswith('ReDim'): # in case redim of multiple variables
            val = values.pop(0) + ', ' + val + '.' + args[0] + '('
        else:
            val2 = 'ReDim '
            if preserve:
                val2 += 'Preserve '
            val2 += val + '.' + args[0] + '('
            val = val2

        curr_val1 = values.pop(0)
        curr_val2 = values.pop(0)
        if curr_val1 == 'OptionBase':
            val += curr_val2 
        else:
            val += curr_val1 + ' To ' + curr_val2 

        while len(values) > 0:
            val += ', '
            curr_val1 = values.pop(0)
            curr_val2 = values.pop(0)
            if curr_val1 == 'OptionBase':
                val += curr_val2 
            else:
                val += curr_val1 + ' To ' + curr_val2 

        val += ')'
        self.opstack.push(val)
            
    def memredimwith(self, *args):
        """
        command used when a property of an object is redim within a with
        example: with myobj ... ReDim .foo(30) .. end with
        gives:
             # OptionBase
             # LitDI2 0x001E
             # MemRedimWith foo 0x0001 (As Variant)
        """
        val = ''
        args = list(args)
        preserve = False
        if args[0] == '(Preserve)':
            args.pop(0)
            preserve = True

        nb_params = int(args[1], 16)

        values = []
        # gather all stack
        while self.opstack.size() > 0:
            values.append(self.opstack.pop())
        values = values[::-1]

        if values[0].startswith('ReDim'): # in case redim of multiple variables
            val = values.pop(0) + ', ' + '.' + args[0] + '('
        else:
            val += 'ReDim '
            if preserve:
                val += 'Preserve '
            val += '.' + args[0] + '('

        curr_val1 = values.pop(0)
        curr_val2 = values.pop(0)
        if curr_val1 == 'OptionBase':
            val += curr_val2 
        else:
            val += curr_val1 + ' To ' + curr_val2 

        while len(values) > 0:
            val += ', '
            curr_val1 = values.pop(0)
            curr_val2 = values.pop(0)
            if curr_val1 == 'OptionBase':
                val += curr_val2 
            else:
                val += curr_val1 + ' To ' + curr_val2 

        val += ')'
        self.opstack.push(val)

            
    def memredimas(self, *args):
        """
        command used when a redim is defined on a property of an object with a As in the end
        example: ReDim myobj.mytab(50) As Double
        gives:
             # OptionBase
             # LitDI2 0x003C
             # Ld myobj
             # MemRedimAs Tab 0x0001 (As Double)
        """
        val = self.opstack.pop()
        args = list(args)
        preserve = False
        if args[0] == '(Preserve)':
            args.pop(0)
            preserve = True

        nb_params = int(args[1], 16)

        values = []
        # gather all stack
        while self.opstack.size() > 0:
            values.append(self.opstack.pop())
        values = values[::-1]

        if values[0].startswith('ReDim'): # in case redim of multiple variables
            val = values.pop(0) + ', ' + val + '.' + args[0] + '('
        else:
            val2 = 'ReDim '
            if preserve:
                val2 += 'Preserve '
            val2 += val + '.' + args[0] + '('
            val = val2
            
        curr_val1 = values.pop(0)
        curr_val2 = values.pop(0)
        if curr_val1 == 'OptionBase':
            val += curr_val2 
        else:
            val += curr_val1 + ' To ' + curr_val2 

        while len(values) > 0:
            val += ', '
            curr_val1 = values.pop(0)
            curr_val2 = values.pop(0)
            if curr_val1 == 'OptionBase':
                val += curr_val2 
            else:
                val += curr_val1 + ' To ' + curr_val2 

        val += ')'

        args.pop(0) #remove var
        args.pop(0) # remove nb_params
        if len(args)> 0: # do we have smthng like "(As <type>)"
            if args[-1] != 'Variant)':
                val += ' ' + args[0][1:] + ' ' + args[1][:-1]
        self.opstack.push(val)
            
    def memredimaswith(self, *args):
        """
        command used when a redim is defined on a property of an object with a As in the end, within a with block
        example: With myobj ... ReDim .mytab(70) As Integer ... End With 
        gives:
             # OptionBase
             # LitDI2 0x0046
             # MemRedimAsWith Tab 0x0001 (As Integer)
        """
        val = ''
        args = list(args)
        preserve = False
        if args[0] == '(Preserve)':
            args.pop(0)
            preserve = True

        nb_params = int(args[1], 16)

        values = []
        # gather all stack
        while self.opstack.size() > 0:
            values.append(self.opstack.pop())
        values = values[::-1]

        if values[0].startswith('ReDim'): # in case redim of multiple variables
            val = values.pop(0) + ', ' + '.' + args[0] + '('
        else:
            val += 'ReDim '
            if preserve:
                val += 'Preserve '
            val += '.' + args[0] + '('
            
        curr_val1 = values.pop(0)
        curr_val2 = values.pop(0)
        if curr_val1 == 'OptionBase':
            val += curr_val2 
        else:
            val += curr_val1 + ' To ' + curr_val2 

        while len(values) > 0:
            val += ', '
            curr_val1 = values.pop(0)
            curr_val2 = values.pop(0)
            if curr_val1 == 'OptionBase':
                val += curr_val2 
            else:
                val += curr_val1 + ' To ' + curr_val2 

        val += ')'

        args.pop(0) #remove var
        args.pop(0) # remove nb_params
        if len(args)> 0: # do we have smthng like "(As <type>)"
            if args[-1] != 'Variant)':
                val += ' ' + args[0][1:] + ' ' + args[1][:-1]
        self.opstack.push(val)
            
    def mid(self):
        """
        command used when Mid funtion is used to set a sub string part, e.g. as an instruction
        example: Mid(MyString, 5, 3) = "fox"
        gives:
             # LitStr 0x0003 "fox"
             # Ld MyString
             # LitDI2 0x0005
             # LitDI2 0x0003
             # Mid
        """
        if self.opstack.size() > 3:
            length = self.opstack.pop()
            start = self.opstack.pop()
            obj = self.opstack.pop()
            str1 = self.opstack.pop()
            self.opstack.push('Mid(' + obj + ', ' + start + ', ' + length + ') = ' + str1)
        else:
            start = self.opstack.pop()
            obj = self.opstack.pop()
            str1 = self.opstack.pop()
            self.opstack.push('Mid(' + obj + ', ' + start + ') = ' + str1)            
            
    def midb(self):
        """
        command used when Mid funtion is used to set a sub string part, e.g as an instruction
        example: MidB(MyString, 5, 3) = "fox"
        gives:
             # LitStr 0x0003 "fox"
             # Ld MyString
             # LitDI2 0x0005
             # LitDI2 0x0003
             # MidB
        """
        if self.opstack.size() > 3:
            length = self.opstack.pop()
            start = self.opstack.pop()
            obj = self.opstack.pop()
            str1 = self.opstack.pop()
            self.opstack.push('MidB(' + obj + ', ' + start + ', ' + length + ') = ' + str1)
        else:
            start = self.opstack.pop()
            obj = self.opstack.pop()
            str1 = self.opstack.pop()
            self.opstack.push('MidB(' + obj + ', ' + start + ') = ' + str1)            

            
    def name(self):
        """
        command for the name keyword, permitting to rename variables
        example: Name OldName As NewName
        gives:
             # Ld OldName
             # Ld NewName
             # Name
        """
        newname = self.opstack.pop()
        oldname = self.opstack.pop()
        self.opstack.push('Name ' + oldname + ' As ' + newname) 
            
    def new(self, var):
        self.opstack.push('New ' + var)
            
    def next_(self):
        self.opstack.push('Next')
        self.indentlevel = self.indentlevel - 1
        self.indentincrease_future = False
            
    def nextvar(self):
        self.opstack.push('Next ' + self.opstack.pop())
        self.indentlevel = self.indentlevel - 1
            
    def onerror(self, *args):
        """
        command defining "on error" statements
        example1: On Error GoTo ErrorHandler
        gives:
             # OnError ErrorHandler
        example2: On Error GoTo 0
        gives: 
             # OnError (GoTo 0)
        example3: On Error Resume Next
        gives: 
             # OnError (Resume Next)
        """
        if args[0] == '(Resume':
            self.opstack.push('On Error Resume Next')
        elif args[0] == '(GoTo':
            self.opstack.push('On Error GoTo 0')
        else:
            #TODO: to check
            self.opstack.push('On Error GoTo ' + args[0])
            
    def ongosub(self, nb, *args):
        """
        command used for gosub on a variable
        example: On Number GoSub Sub1, Sub2
        gives:
             # Ld Number
             # OnGoSub 0x0004 Sub1, Sub2
        """
        val = 'On ' + self.opstack.pop() + ' GoSub '
        val2 = args[0]
        for arg in args[1:]:
            val2 += ' ' + arg
        self.opstack.push(val + val2)
            
    def ongoto(self, nb, *args):
        """
        command used for goto on a variable
        example: On Number GoTo Line1, Line2
        gives:
             # Ld Number
             # OnGoto 0x0004 Line1, Line2
        """
        val = 'On ' + self.opstack.pop() + ' GoTo '
        val2 = args[0]
        for arg in args[1:]:
            val2 += ' ' + arg
        self.opstack.push(val + val2)
            
    def open_(self, *args):
        """
        command used for Open function
        example: Open "TESTFILE" For Output As #1
        gives:
             # LitStr 0x0008 "TESTFILE"
             # LitDI2 0x0001
             # Sharp
             # LitDefault
             # Open (For Output)
        example2: Open "TESTFILE" For Binary Access Write Lock Write As #1
        gives:
             # LitStr 0x0008 "TESTFILE"
             # LitDI2 0x0001
             # Sharp
             # LitDefault
             # Open (For Binary Access Write Lock Write)
        """
        chan = self.opstack.pop()
        val = args[0][1:] # avoid parenthesis
        for arg in args[1:]:
            val += ' ' + arg
        val = val[:-1] #avoid parenthesis
        self.opstack.push('Open ' + self.opstack.pop() + ' ' + val + ' As ' + chan)
            
    def option(self, *args):
        """
        command for option keyword
        example: Option Explicit
        gives : 
           # Option (Explicit)
        example2: Option Compare Binary
        gives :
           # Option (Compare Binary)
        """
        val = args[0][1:]
        if len(args)>1:
            for arg in args[1:]: #strip parenthesis
                val += ' ' + arg
        self.opstack.push('Option ' + val[:-1])
            
    def optionbase(self):
        """
        used in the following case: when a table dimension is not declared from base to end, but only size;
        to treat it, we will push a magic value on stack like for dim and dimimplicit, and vardef will treat it directly
        example1: Dim MyArray(20)
        gives: 
             # Dim
             # OptionBase
             # LitDI2 0x0014
             # VarDefn MyArray
        """
        self.opstack.push('OptionBase')
            
    def parambyval(self):
        """
        command used when Byval keyword is used
        example: a ByVal b
        gives:
             # Ld B
             # ParamByVal
             # ArgsCall a 0x0001
        """
        self.opstack.push('ByVal ' + self.opstack.pop())
            
    def paramomitted(self):
        """
        command used when a parameter is left blank in a function call
        example: MsgBox Msg, , "Deferred Error Test"
        gives:
             # Ld Msg
             # ParamOmitted
             # LitStr 0x0013 "Deferred Error Test"
             # ArgsCall MsgBox 0x0003
        """
        self.opstack.push('')
            
    def paramnamed(self, var):
        """
        command used when a call is made with named parameters
        example: MyClasses.Add Item:=Inst, Key:=CStr(Num)
        gives:
             # Ld Inst
             # ParamNamed Item
             # Ld Num
             # Coerce (Str)
             # ParamNamed Key
             # Ld MyClasses
             # ArgsMemCall Add 0x0002
        """
        self.opstack.push(var + ':=' + self.opstack.pop())
            
    def printchan(self):
        """
        command defining "print" to a channel
        example: Print #1, MyBool; " is a Boolean value"
        gives:
             # LitDI2 0x0001
             # Sharp
             # PrintChan
             # Ld MyBool
             # PrintItemSemi
             # LitStr 0x0013 " is a Boolean value"
             # PrintItemNL
        """
        self.opstack.push('Print ' +self.opstack.pop() + ',')
    
    def printcomma(self, *args):
        """
        command used when a colon is used in Print
        example: Debug.Print Spc(30), "Thirty spaces later...
        gives:
             # Debug
             # PrintObj
             # LitDI2 0x001E
             # PrintSpc
             # PrintComma
             # LitStr 0x0016 "Thirty spaces later..."
             # PrintItemNL
        """
        self.opstack.push(',')
            
    def printeos(self):
        """
        used at the end of some print when there is nothing, instead of printitemnl
        """
        elmts = []
        while self.opstack.size() >= 1:
            elmts.append(self.opstack.pop())
        elmts = elmts[::-1]
        val = elmts[0]
        for elmt in elmts[1:]:
            if ((elmt == ';') or (elmt == ',')) and (elmts.index(elmt) != 1):
                val+= elmt
            else:
                val += ' ' + elmt
        self.opstack.push(val)

            
    def printitemcomma(self):
        """
        command defining ",", used for example when writing 
        example: Write #1, "Hello World", 234
        gives:
             # LitDI2 0x0001
             # Sharp
             # WriteChan
             # LitStr 0x000B "Hello World"
             # PrintItemComma
             # LitDI2 0x00EA
             # PrintItemNL
             # QuoteRem 0x0020 0x001C " Write comma-delimited data."
        """
        elmts = []
        while self.opstack.size() >= 1:
            elmts.append(self.opstack.pop())
        elmts = elmts[::-1]
        val = elmts[0]
        for elmt in elmts[1:]:
            val += ' ' + elmt
        self.opstack.push(val + ',')
            
    def printitemnl(self):
        """
        TODO: not sure what's it is used for
        example1: Write #1, MyBool; " is a Boolean value"
        gives:
             # LitDI2 0x0001
             # Sharp
             # WriteChan
             # Ld MyBool
             # PrintItemSemi
             # LitStr 0x0013 " is a Boolean value"
             # PrintItemNL
        example2:  Debug.Print i
        gives:
             # Debug
             # PrintObj
             # Ld i
             # PrintItemNL
        """
        elmts = []
        while self.opstack.size() >= 1:
            elmts.append(self.opstack.pop())
        elmts = elmts[::-1]
        val = elmts[0]
        for elmt in elmts[1:]:
            if ((elmt == ';') or (elmt == ',')) and (elmts.index(elmt) != 1):
                val+= elmt
            else:
                val += ' ' + elmt
        self.opstack.push(val)
            
    def printitemsemi(self):
        """
        command defining ";", used for example when writing 
        example: Write #1, MyBool; " is a Boolean value"
        gives:
             # LitDI2 0x0001
             # Sharp
             # WriteChan
             # Ld MyBool
             # PrintItemSemi
             # LitStr 0x0013 " is a Boolean value"
             # PrintItemNL
        """
        elmts = []
        while self.opstack.size() >= 1:
            elmts.append(self.opstack.pop())
        elmts = elmts[::-1]
        val = elmts[0]
        for elmt in elmts[1:]:
            val += ' ' + elmt
        self.opstack.push(val + ';')
            
    def printnl(self):
        """
        really not sure about this one
        example: Write #1,     
        gives:
             # LitDI2 0x0001
             # Sharp
             # WriteChan
             # PrintNL
        """
        elmts = []
        while self.opstack.size() >= 1:
            elmts.append(self.opstack.pop())
        elmts = elmts[::-1]
        val = elmts[0]
        for elmt in elmts[1:]:
            val += ' ' + elmt
        self.opstack.push(val)
    
    def printobj(self):
        """
        appears to call the print method of an object
        example:  Debug.Print i
        gives:
             # Debug
             # PrintObj
             # Ld i
             # PrintItemNL
        """
        if self.opstack.top() == 'MeImplicit':
            self.opstack.pop()
            self.opstack.push('Print')
        else:
            self.opstack.push(self.opstack.pop() + '.Print')
            
    def printsemi(self, *args):
        """
        command used when a semicolon is used in Print
        example: Debug.Print Spc(30); "Thirty spaces later...
        gives:
             # Debug
             # PrintObj
             # LitDI2 0x001E
             # PrintSpc
             # PrintSemi
             # LitStr 0x0016 "Thirty spaces later..."
             # PrintItemNL
        """
        self.opstack.push(';')
            
    def printspc(self):
        """
        command used when SPC(n) is used in Print
        example: Debug.Print Spc(30); "Thirty spaces later...
        gives:
             # Debug
             # PrintObj
             # LitDI2 0x001E
             # PrintSpc
             # PrintSemi
             # LitStr 0x0016 "Thirty spaces later..."
             # PrintItemNL
        """
        self.opstack.push('Spc(' + self.opstack.pop() + ')')
            
    def printtab(self, *args):
        """
        command used when Tab(n) is used in Print
        example: Debug.Print Tab(30); "Thirty spaces later...
        gives:
             # Debug
             # PrintObj
             # LitDI2 0x001E
             # PrintTab
             # PrintSemi
             # LitStr 0x0016 "Thirty spaces later..."
             # PrintItemNL
        """
        self.opstack.push('Tab(' + self.opstack.pop() + ')')
            
    def printtabcomma(self):
        """
        command used when Tab with no arg is used in Print
        example: Debug.Print Tab, "Thirty spaces later...
        gives:
             # Debug
             # PrintObj
             # PrintTabComma
             # PrintComma
             # LitStr 0x0016 "Thirty spaces later..."
             # PrintItemNL
        """
        self.opstack.push('Tab')
            
    def pset(self, numparams):
        """
        command used when the pset method of an object is called
        example: Me.PSet (intI, sngMidPt)
        gives:
             # Ld intI
             # Ld sngMidPt
             # LitDI2 0x0000
             # Ld id_FFFF
             # PSet 0x0002
        """
        val = self.opstack.pop() + '.PSet('
        first_arg = self.opstack.pop()
        if first_arg != '0':
            val += first_arg + ', '
            
        nb_args = int(numparams, 16)
        params = []
        if nb_args > 0:
            for i in range(nb_args):
                params.append(self.opstack.pop())
            params = params[::-1]

            val += params[0]
            for param in params[1:]:
                val = val + ', ' + param
        val +=')'
        self.opstack.push(val)
            
    def putrec(self):
        """
        command to Put to a channel with a record: Put channel, record, var
        example: Put #1, RecordNumber, MyRecord
        gives:
             # LitDI2 0x0001
             # Sharp
             # Ld RecordNumber
             # Ld MyRecord
             # PutRec
        """
        record = self.opstack.pop()
        record_num = self.opstack.pop()
        chan = self.opstack.pop()
        self.opstack.push(F'Put {chan}, {record_num}, {record}')
            
    def quoterem(self, val1, lenvar, *args):
        """
        command handling comments definition with '
        multiple cases:
        example : MsgBox "toto" 'a message to send
        gives:
             # LitStr 0x0004 "toto"
             # ArgsCall MsgBox 0x0001
             # QuoteRem 0x000F 0x11

        example : TODO macaroni
        gives: TODO macaroni
        """
        val = "'" + args[0][1:]
        for arg in args[1:] :
            val += ' ' + arg
        val = val[:-1]
        if self.opstack.size() != 0:
            val = self.opstack.pop() + ' ' + val
        self.opstack.push(val)


    def redim(self, *args):
        """
        command used when redim function is used
        example : ReDim temp(4)
        gives:
             # OptionBase
             # LitDI2 0x0004
             # Redim temp 0x0001 (As Variant)
        """
        val = ''
        args = list(args)
        preserve = False
        if args[0] == '(Preserve)':
            args.pop(0)
            preserve = True

        nb_params = int(args[1], 16)

        values = []
        # gather all stack
        while self.opstack.size() > 0:
            values.append(self.opstack.pop())
        values = values[::-1]

        if values[0].startswith('ReDim'): # in case redim of multiple variables
            val = values.pop(0) + ', ' + args[0] + '('
        else:
            val += 'ReDim '
            if preserve:
                val += 'Preserve '
            val += args[0] + '('
            
        curr_val1 = values.pop(0)
        curr_val2 = values.pop(0)
        if curr_val1 == 'OptionBase':
            val += curr_val2 
        else:
            val += curr_val1 + ' To ' + curr_val2 

        while len(values) > 0:
            val += ', '
            curr_val1 = values.pop(0)
            curr_val2 = values.pop(0)
            if curr_val1 == 'OptionBase':
                val += curr_val2 
            else:
                val += curr_val1 + ' To ' + curr_val2 

        val += ')'
        self.opstack.push(val)

        
    def redimas(self, *args):
        """
        command used when a redim is defined with a As in the end
        example: ReDim mytab(50) As Double
        gives:
             # OptionBase
             # LitDI2 0x0032
             # RedimAs mytab 0x0001 (As Double)
        """
        val = ''
        args = list(args)
        preserve = False
        if args[0] == '(Preserve)':
            args.pop(0)
            preserve = True

        nb_params = int(args[1], 16)

        values = []
        # gather all stack
        while self.opstack.size() > 0:
            values.append(self.opstack.pop())
        values = values[::-1]

        if values[0].startswith('ReDim'): # in case redim of multiple variables
            val = values.pop(0) + ', ' + args[0] + '('
        else:
            val += 'ReDim '
            if preserve:
                val += 'Preserve '
            val += args[0] + '('
            
        curr_val1 = values.pop(0)
        curr_val2 = values.pop(0)
        if curr_val1 == 'OptionBase':
            val += curr_val2 
        else:
            val += curr_val1 + ' To ' + curr_val2 

        while len(values) > 0:
            val += ', '
            curr_val1 = values.pop(0)
            curr_val2 = values.pop(0)
            if curr_val1 == 'OptionBase':
                val += curr_val2 
            else:
                val += curr_val1 + ' To ' + curr_val2 

        val += ')'

        args.pop(0) #remove var
        args.pop(0) # remove nb_params
        if len(args)> 0: # do we have smthng like "(As <type>)"
            if args[-1] != 'Variant)':
                val += ' ' + args[0][1:] + ' ' + args[1][:-1]
        self.opstack.push(val)
            
    def reparse(self, *args):
        """
        opcode used when a non valid statement is employed
        """
        val = args[1][1:]
        for arg in args[2:]:
            val += ' ' + arg
        val = val[:-1] # avoid double quotes
        self.opstack.push(val)


    def rem(self, *args):
        """
        command for Rem keyword
        example: Rem This entire line is a comment
        gives:  # Rem 0x001F " This entire line is a comment."
        """
        val = args[2] # avoid space+double quote
        for arg in args[3:]:
            val += ' ' + arg
        val = val[:-1] #avoid double quote
        self.opstack.push('Rem ' + val)
        
            
    def resume(self, *args):
        """
        command used when resume keyword is used 
        example1: Resume
        gives: # Resume
        example2: Resume Next
        gives: # Resume (Next)
        example3: Resume titi
        gives: # Resume titi
        """
        if args == ():
            self.opstack.push('Resume')
        else:
            if args[0] == '(Next)':
                self.opstack.push('Resume Next')
            else:
                self.opstack.push('Resume ' + args[0])
            
    def return_(self):
        #TODO: comment
        self.opstack.push('Return')
            
    def rset(self):
        """
        command for RSet keyword
        example: RSet MyString = "Right->"
        gives:
             # LitStr 0x0007 "Right->"
             # Ld MyString
             # RSet
        """
        var = self.opstack.pop()
        val = self.opstack.pop()
        self.opstack.push('RSet ' + var + ' = ' + val)
            
    def scale(self, *args):
        """
        command used when an object scale method is used
        example: Me.Scale 
        gives:
             # LitDI2 0x0000
             # LitDI2 0x0000
             # Ld sngNewH
             # Ld sngNewV
             # Ld id_FFFF
             # Scale 0x0000
        TODO: what to do with this command?
        """
        raise Pcode2codeException('not implemented scale')
            
    def seek(self):
        """
        opcode used when seek is used to search in a file
        example: Seek #1, 2
        gives:
             # LitDI2 0x0001
             # Sharp
             # LitDI2 0x0002
             # Seek
        """
        data = self.opstack.pop()
        self.opstack.push('Seek ' + self.opstack.pop() + ', ' + data)
            
    def selectcase(self):
        """
        command handling a "select case" definition against a variable
        example : Select Case x
        gives:
             # Ld x
             # SelectCase
        """
        self.opstack.push('Select Case ' + self.opstack.pop())
        self.indentincrease_future = True
    
    def selectis(self, *args):
        raise Pcode2codeException('not implemented selectis')
            
    def selecttype(self, *args):
        raise Pcode2codeException('not implemented selecttype')
            
    def setstmt(self):
        # TODO: comment
        #pass on purpose
        pass
            
    def stack(self, *args):
        raise Pcode2codeException('not implemented stack')
            
    def stop(self):
        #TODO: comment
        self.opstack.push('Stop')
            
    def type_(self, *args):
        """
        command for Type keyword, #TODO: beware because it's also used for enum keyword
        example: Type EmployeeRecord
        gives : 
           # Type EmployeeRecord
        """
        if args[0] == '(Private)':
            self.opstack.push('Private Type ' + args[1])
        elif args[0] == '(Public)':
            self.opstack.push('Public Type ' + args[1])
        else:
            self.opstack.push('Type ' + args[0])
        self.indentincrease_future = True
            
    def unlock(self):
        """
        command to unlock a record
        example: Unlock #1, RecordNumber
        gives:
             # LitDI2 0x0001
             # Sharp
             # Ld RecordNumber
             # LitDefault
             # Unlock
        """
        if self.opstack.size() == 3:
            last_record = self.opstack.pop()
            first_record = self.opstack.pop()
            chan = self.opstack.pop()
            self.opstack.push('Unlock ' + chan + ', ' + first_record + ' To ' + last_record)
        elif self.opstack.size() == 2:
            record = self.opstack.pop()
            chan = self.opstack.pop()
            self.opstack.push('Unlock ' + chan + ', ' + record)
        elif self.opstack.size() == 1:
            chan = self.opstack.pop()
            self.opstack.push('Unlock ' + chan)



    # Dim hiz7dgus As String
    # Private Const DefaultBufferSize& = 32768
    # Private CRC_32_Tab(0 To 255) As Long
    # ======================
    # Line #7:
    # 	Dim 
    # 	VarDefn hiz7dgus (As String)
    # Line #8:
    # Line #9:
    # 	Dim (Private Const) 
    # 	LitDI4 0x8000 0x0000 
    # 	VarDefn DefaultBufferSize
    # Line #10:
    # Line #11:
    # 	Dim (Private) 
    # 	LitDI2 0x0000 
    # 	LitDI2 0x00FF 
    # 	VarDefn CRC_32_Tab (As Long)
    def vardefn(self, *args):      
        ending =''
        args = list(args) #quite ugly, but fu...
        if args[0] == '(WithEvents)':
            var = args.pop(0)[1:-1] + ' ' + args.pop(0)
        else:
            var = args.pop(0)

        spaces = 1
        if len(args) > 0:
            if args[-1].startswith('0x'):
                spaces = int(args.pop(-1),16) #TODO: treat spaces there
            ending = args[0]
            for arg in args[1:]:
                ending += ' ' + arg
            ending = ' ' + ending[1:-1]
            

        # first we check if this is only one literal definition
        # in this case, we get Dim definitions and we are all set up
        stacktop = self.opstack.pop()

        if stacktop == 'DimImplicit': #case where dim is implicit, 
            val = var + ending  # we have pushed in this case 'DimImplicit' on stack
            self.opstack.push(val)
            return

        # in this case we have a single variable declaration
        decls = ['Dim', 'Private', 'Public', 'Protected', 'Friend', 'Protected Friend', 'Shared', 'Shadows', 'Static', 'ReadOnly']
        if stacktop in decls:
            val = stacktop + ' ' + var + ending
            self.opstack.push(val)
            return

        else:
            # in this case, our variable is either a table, or there is also some const declarations
            # if so, walk the stack and check for declaration
            self.opstack.push(stacktop)
            values = []

            # gather all stack
            while self.opstack.size() > 0:
                values.append(self.opstack.pop())
            values = values[::-1]

            # if we have multiple vardefn with dim, then we are here
            # because all previous vardef should have been pushed correctly on stack
            if len(values) == 1 :
                for decl in decls:
                    if values[0].startswith(decl):
                        val = values[0] +', ' + var + ending
                        self.opstack.push(val)
                        return
                    
            # if const is used for declaration, then a value is attributed to variable
            # appears somehow not possible to declare a table as const, so far so good, no need to check this case
            if 'Const' in values[0]:
                val = values.pop(0)
                end_val = ' = ' + values.pop(0)
                if len(values) > 0:
                    # how to say what is dimensions to what is attribution
                    #val = 'Undefined variable declaration'
                    raise Pcode2codeException('undefined variable declaration')
                else:
                    val = val + ' ' + var + ending + end_val
                self.opstack.push(val)
                return
            
            #so here we have a table
            val = ''
            if values[0] in decls: #first we check if this is the first definition
                val += values.pop(0) + ' ' + var + '('
            elif values[0] == 'DimImplicit': #not sure about this one
                values.pop(0)
                val += var + '('
            else:
                #next we check for a previous declaration
                prev_decl = False
                for decl in decls:
                    if values[0].startswith(decl):
                        val += values.pop(0) +', ' + var + '('
                        prev_decl = True
                if prev_decl is False: #in this case, nothing before
                    val+= var + '('

            #first occurence
            curr_val1 = values.pop(0)
            curr_val2 = values.pop(0)
            if curr_val1 == 'OptionBase':
                val += curr_val2 
            else:
                val += curr_val1 + ' To ' + curr_val2 

            #other occurences
            while len(values) > 0:
                val += ', '
                curr_val1 = values.pop(0)
                curr_val2 = values.pop(0)
                if curr_val1 == 'OptionBase':
                    val += curr_val2 
                else:
                    val += curr_val1 + ' To ' + curr_val2 

            #closing
            val += ')' + ending
            self.opstack.push(val)

    def wend(self):
        """
        command handling end of while loop "Wend"
        example: Wend
        gives : 
              # Wend
        """
        self.opstack.push('Wend')
        self.indentlevel = self.indentlevel - 1
            
    def while_(self):
        """
        command handling "while" loops definitions
        example: While numero <= 12
        gives:
             # Ld numero
             # LitDI2 0x000C
             # Le
             # While
        """
        self.opstack.push('While ' + self.opstack.pop())
        self.indentincrease_future = True
            
    def with_(self):
        """
        command handling "with" definitions
        example: with theWindow 
        gives:
             # StartWithExpr
             # Ld theWindow
             # With
        """
        self.opstack.push('With ' + self.opstack.pop())
        self.indentincrease_future = True
            
    def writechan(self):
        """
        command defining "write" to a channel
        example: Write #1, MyBool; " is a Boolean value"
        gives:
             # LitDI2 0x0001
             # Sharp
             # WriteChan
             # Ld MyBool
             # PrintItemSemi
             # LitStr 0x0013 " is a Boolean value"
             # PrintItemNL
        """
        self.opstack.push('Write ' +self.opstack.pop() + ',')
            
    def constfuncexpr(self, *args):
        raise Pcode2codeException('not implemented constfuncexpr')
            
    def lbconst(self, var):
        """
        opcode used when #Const is used
        example: #Const x = y
        gives:
             # LbMark
             # Ld B
             # LbConst a
        """
        self.opstack.push('#Const ' + var + ' = ' + self.opstack.pop())
    
    def lbif(self):
        """
        opcode used when #If is used
        example: #If a = b Then
        gives:
             # LbMark
             # Ld a
             # Ld B
             # Eq
             # LbIf
        """
        self.opstack.push('#If ' + self.opstack.pop() + ' Then')
        self.indentincrease_future = True
    
    def lbelse(self):
        """
        opcode used when #Else is used
        example: #Else 
        gives: lbElse
        """
        self.opstack.push('#Else')
        self.indentlevel = self.indentlevel - 1
        self.indentincrease_future = True
            
    def lbelseif(self):
        """
        opcode used when #Elseif is used
        example: #ElseIf a = c Then
        gives:
             # LbMark
             # Ld a
             # Ld c
             # Eq
             # LbElseIf
        """
        self.opstack.push('#ElseIf ' + self.opstack.pop() + ' Then')
        self.indentlevel = self.indentlevel - 1
        self.indentincrease_future = True
            
    def lbendif(self):
        """
        opcode used when "#End If" is used
        example: #End If
        gives: #LbEndIf
        """
        self.opstack.push('#End If')
        self.indentlevel = self.indentlevel - 1
            
    def lbmark(self):
        """
        appears to be used to indicate the start of a lb statement, appears quite useless
        """
        pass #pass on purposes

    def endforvariable(self):
        """
        This command ends out a for loop variable definition. Gives nothing interesting in fact
        example: TODO macaroni
        gives: TODO macaroni
        """
        #pass on purposes
        pass
            
    def startforvariable(self):
        """
        This command starts out a for loop variable definition. Gives nothing interesting in fact
        example: TODO macaroni
        gives: TODO macaroni
        """
        #pass on purposes
        pass
            
    def newredim(self, *args):
        raise Pcode2codeException('not implemented newredim')
            
    def startwithexpr(self):
        """
        used like startforvariable, eg, simply an indicator of when a with variable is declared.
        pretty useless for us.
        example: With theWindow
        gives:
             # StartWithExpr
             # Ld theWindow
             # With
        """
        #pass on purposes
        pass
            
    def setorst(self, *args):
        raise Pcode2codeException('not implemented setorst')
            
    def endenum(self):
        """
        command to end an enum
        example: End Enum
        gives:
             #EndEnum
        """
        self.opstack.push('End Enum')
        self.indentlevel = self.indentlevel - 1
            
    def illegal(self, *args):
        raise Pcode2codeException('not implemented illegal')

    def newline(self):
        """
        defines a blank line. Used for internal processing, for blank streams and lines
        """
        self.opstack.push('')
    
    def clearstack(self):
        self.opstack.clearstack()

    def getstacktop(self):
        return self.opstack.top()

    def getstackpop(self):
        return self.opstack.pop()

    def getstacksize(self):
        return self.opstack.size()

    def increaseindentlevel_future(self):
        """
        when we increase the indent level, we need to first print out the line, and then to increase the indent level. 
        to do so, when a line has been printed, this function checks if the indent level need to be increased and do so.
        """
        if self.unindented > 0:
            self.unindented -= 1
        elif self.indentincrease_future:
            self.indentlevel = self.indentlevel + 1
        self.indentincrease_future = False
    
    def getindentlevel(self):
        """
         function retrieving the class indentlevel parameter, used to print out code with correct indent
        """
        return self.indentlevel

    def hasbos(self):
        return self.has_bos

    def resethasbos(self):
        self.has_bos = False
    
class Parser:

    def __init__(self, myinput):
        self.myinput = myinput  # input to be processed, is always a dump of pcodedmp module there
        self.opstack = Stack()  # vba bytecode is somewhat stack based, so we declare a new one 
        self.operations = Operations(self.opstack) # all operations that can be found in vba bytecode
        self.output = ''        # the output of global processing
        self.output_queue = []
        self.unindented = 0

    def queueLineOutput(self, line, linenum, print_linenum=False, has_end=True):
        self.output_queue.append((line, linenum, print_linenum, has_end))

    def addlineOutput(self, line, linenum, print_linenum=False, has_end=True, _checking_queue=False):
        """
            Because we can choose what is the output for our module, this function somehow bufferize the
            output before it's printed in the latter.
        """
        if not line.strip():
            return
        while not _checking_queue and self.output_queue:
            self.addlineOutput(*self.output_queue.pop(), True)
        if print_linenum:
            self.output += str(linenum) + ': '           
        if not has_end:
            self.output += line
            return
        self.output += line + '\n' 

    def getOutput(self):
        """
        simply a getter to output, used in the end of global processing
        """
        return self.output

    def parseInput(self):
        """
            Function parsing pcodedmp dump to create a dictionary of all lines of the input with the operation lines associated.
            Basically, to explain, a pcodedmp dump would look like so:
               ' Line #7:
               '   Dim 
               '   VarDefn hiz7dgus (As String)
            Here the first line gives out the line number, and the rest are operation lines.
        """
        splittedInput = self.myinput.splitlines()
        lines = {}
        i = 0
        started = False
        streams = {}
        laststream = None
        opelinesblock = []
        # we parse each lines, and cut them by line blocks, to put them in "lines"
        #TODO: simplify
        for inputLine in splittedInput:
            inputLine = inputLine.strip()

            if 'VBA/' in inputLine and inputLine.endswith('bytes'): # here we have a new stream in the document
                if laststream is None: #eg first occurence
                    laststream = inputLine
                else:
                    if opelinesblock == []:
                        opelinesblock = ['NewLine']
                    lines[i] = opelinesblock
                    streams[laststream] = lines
                    opelinesblock = []
                    i = 0
                    lines = {}
                    started = False
                    laststream = inputLine
            if inputLine.startswith('Line #'): # here is our new line block
                started = True
                if not inputLine.startswith('Line #0'):
                    
                    if opelinesblock == []:		# when line is blank, it still appears in dump
                        opelinesblock = ['NewLine']     # so we treat it with a special new operation
                    	                                # saying line is blank
                    lines[i] = opelinesblock
                    i+=1
                opelinesblock = []
            else:
                if started:
                    opelinesblock.append(inputLine)

        if opelinesblock == []:
            opelinesblock = ['NewLine']
            
        lines[i] = opelinesblock
        streams[laststream] = lines

        self.myinput = streams


    def parseOpLine(self, inputLine):
        """
            function to parse an operation line.
            to avoid using costly regexp, we split each operation line. The first element is always the operation
            to do, and the rest is potential args. In case there are args, they will be reconstructed by the underlying operation.
        """
        linelist = inputLine.split()
        ope = linelist[0]
        args = linelist[1:]
        func = self.operations.ops[ope]
        func(*args)

    def processInput(self, print_linenum):
        """
            When the input has been <<parsed>>, this function process it to disassemble the input, by calling parseOpLine for each line. 
            It is basically only a printing function.
            args: 
              - print_linenum: boolean indicating if line numbers should be printed in the output or not. Please refer to function named "process"
        """
        for stream in self.myinput.keys():
            if stream:
                self.queueLineOutput('# DECOMPILED STREAM : ' + stream, 0)
            unindented = 0
            for linenum, oplines in self.myinput[stream].items():
                for line in oplines:
                    if line.startswith('FuncDefn'):
                        unindented += 1
                    if line.startswith('EndFunc') or line.startswith('EndSub'):
                        unindented -= 1
            self.operations.unindented = unindented
            for linenum in self.myinput[stream]:
                try:
                    self.operations.clearstack()
                    for opline in self.myinput[stream][linenum]:
                        self.parseOpLine(opline)
                    if self.operations.hasbos():
                        output_parts = []
                        while self.operations.getstacksize() > 0:
                            output_parts.append(self.operations.getstackpop())
                        output_parts = output_parts[::-1]
                        self.addlineOutput(self.operations.getindentlevel() * '  ', linenum, print_linenum, False)
                        for part in output_parts[:-1]:
                            self.addlineOutput(part + ' ', linenum, has_end=False)
                        self.addlineOutput(output_parts[-1], linenum)
                        self.operations.resethasbos()
                    else:
                        self.addlineOutput(self.operations.getindentlevel() * '  ' + self.operations.getstacktop(), linenum, print_linenum)
                except Pcode2codeException as e:
                    self.addlineOutput("' pcode2code, cannot process line "+ str(linenum) + ' : ' + str(e), linenum, print_linenum)
                    for opline in self.myinput[stream][linenum]:
                        self.addlineOutput("'\t# " + opline, linenum)
                except Exception as e:
                    self.addlineOutput("' a generic exception occured at line " + str(linenum) + ": " + str(e), linenum, print_linenum)
                    for opline in self.myinput[stream][linenum]:
                        self.addlineOutput("'\t# " + opline, linenum)
                self.operations.increaseindentlevel_future()
            self.output_queue.clear()