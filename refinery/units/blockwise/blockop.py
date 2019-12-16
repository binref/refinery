#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ...lib.argformats import PythonExpression, number
from . import ArithmeticUnit, NoNumpy


_BLOCK_OPERATION_PARSER = PythonExpression('B', 'A', 'S', 'V')


def blockop_expression(definition):
    """
    An argparse type which uses the `refinery.lib.argformats.PythonExpression` parser to
    parse the expressions that can be passed to `refinery.blockop`. Essentially, these
    are Python expressions which can contain variables `B`, `A`, `S`, and `V`.
    """
    def wrapper(B, S, *V):
        return wrapper.parsed(B=B, A=V[0], S=S, V=V) if V else wrapper.parsed(B=B, S=S)
    wrapper.parsed = _BLOCK_OPERATION_PARSER(definition)
    return wrapper


class blockop(ArithmeticUnit):
    """
    This unit allows you to specify a custom Python expression where the following variables are allowed.

    - the variable `B`: current block
    - the variable `S`: an optional seed value for an internal state
    - the variable `V`: the vector of arguments
    - the variable `A`: same as `V[0]`

    Each block of the input is replaced by the value of this expression. Additionally, it is possible to
    specify prologue and epilogue expressions which are used to update the state variable `S` before and
    after the update of each block, respectively.
    """

    def interface(self, argp):
        argp.add_argument('operation', type=blockop_expression, help='A Python expression defining the operation.')
        argp.prologue = argp.add_mutually_exclusive_group()
        argp.prologue.add_argument('-P', '--prologue', type=blockop_expression, metavar='E', default=None, help=(
            'Optional expression with which the state variable S is updated before a block is operated on.'))
        argp.epilogue = argp.add_mutually_exclusive_group()
        argp.epilogue.add_argument('-E', '--epilogue', type=blockop_expression, metavar='E', default=None, help=(
            'Optional expression with which the state variable S is updated after a block was operated on.'))
        argp.epilogue.add_argument('--ctr', action='store_const', dest='epilogue', const=blockop_expression('S+1'),
            help='equivalent to --epilogue=S+1')
        argp.epilogue.add_argument('--cbc', action='store_const', dest='epilogue', const=blockop_expression('B'),
            help='equivalent to --epilogue=B')
        argp.add_argument('-s', '--seed', type=number, default=0,
            help='Optional seed value for the state variable S. The default is zero.')
        return super().interface(argp)

    @property
    def ecb(self):
        return not self.args.epilogue and not self.args.prologue

    def process_ecb_fast(self, data):
        if not self.ecb:
            raise NoNumpy
        return super().process_ecb_fast(data)

    def process(self, data):
        self._state = self.args.seed
        return super().process(data)

    def operate(self, block, *args):
        if self.args.prologue:
            self._state = self.args.prologue(block, self._state, *args)
        block = self.args.operation(block, self._state, *args) & self.fmask
        if self.args.epilogue:
            self._state = self.args.epilogue(block, self._state, *args)
        return block
