#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from ...lib.meta import metavars
from ...lib.argformats import PythonExpression
from . import arg, ArithmeticUnit, NoNumpy


class IndexCounter:
    mask: int
    index: int

    def init(self, mask):
        self.mask = mask
        self.index = -1

    def __iter__(self):
        return self

    def __next__(self):
        self.index = index = self.index + 1 & self.mask
        return index


class blockop(ArithmeticUnit):
    """
    This unit allows you to specify a custom Python expression where the following variables are allowed.

    - the variable `A`: same as `V[0]`
    - the variable `B`: current block
    - the variable `N`: number of bytes in the input
    - the variable `I`: current index in the input
    - the variable `S`: an optional seed value for an internal state
    - the variable `V`: the vector of arguments

    Each block of the input is replaced by the value of this expression. Additionally, it is possible to
    specify prologue and epilogue expressions which are used to update the state variable `S` before and
    after the update of each block, respectively.
    """

    @staticmethod
    def _parse_op(definition):
        """
        An argparse type which uses the `refinery.lib.argformats.PythonExpression` parser to
        parse the expressions that can be passed to `refinery.blockop`. Essentially, these
        are Python expressions which can contain variables `B`, `A`, `S`, and `V`.
        """
        parsed = PythonExpression(definition, *'IBASNV', all_variables_allowed=True)

        def wrapper(index, block, state, argvector, total, meta):
            args = {'I': index, 'B': block, 'S': state, 'N': total}
            if argvector:
                args.update(A=argvector[0], V=argvector)
            return parsed(meta, **args)

        return wrapper

    def __init__(
        self, operation: arg(type=str, help='A Python expression defining the operation.'), *argument,
        seed: arg('-s', type=str, help=(
            'Optional seed value for the state variable S. The default is zero. This can be an expression '
            'involving the variable N.')) = 0,
        prologue: arg('-p', type=str, metavar='E', help=(
            'Optional expression with which the state variable S is updated before a block is operated on.')) = None,
        epilogue: arg('-e', type=str, metavar='E', group='EPI', help=(
            'Optional expression with which the state variable S is updated after a block was operated on.')) = None,
        inc: arg('-I', group='EPI', help='equivalent to --epilogue=S+1') = False,
        dec: arg('-D', group='EPI', help='equivalent to --epilogue=S-1') = False,
        cbc: arg('-X', group='EPI', help='equivalent to --epilogue=(B)') = False,
        bigendian=False, blocksize=1, precision=None
    ):
        for flag, flag_is_set, expression in [
            ('--cbc', cbc, '(B)'),
            ('--inc', inc, 'S+1'),
            ('--dec', dec, 'S-1'),
        ]:
            if flag_is_set:
                if epilogue is not None:
                    raise ValueError(
                        F'Ambiguous specification; epilogue was already set to {epilogue} '
                        F'when {flag} was parsed.'
                    )
                epilogue = expression

        self._index = IndexCounter()

        super().__init__(
            self._index,
            *argument,
            bigendian=bigendian,
            blocksize=blocksize,
            precision=precision,
            operation=self._parse_op(operation),
            seed=seed,
            prologue=prologue and self._parse_op(prologue),
            epilogue=epilogue and self._parse_op(epilogue),
        )

    @property
    def _is_ecb(self):
        return not self.args.epilogue and not self.args.prologue

    def process_ecb_fast(self, data):
        if not self._is_ecb:
            raise NoNumpy
        return super().process_ecb_fast(data)

    def process(self, data):
        seed = self.args.seed
        meta = metavars(data)
        if isinstance(seed, str):
            seed = PythonExpression(seed, 'N', constants=metavars(data))
        self._index.init(self.fmask)
        self._state = seed
        self._evaluation_arguments = [0, 0, 0, (), len(data), meta]
        if callable(self._state):
            self._state = self._state(meta, N=len(data))
        return super().process(data)

    def operate(self, block, index, *args):
        arguments = self._evaluation_arguments
        arguments[:4] = index, block, self._state, args
        if self.args.prologue:
            arguments[2] = self._state = self.args.prologue(*arguments)
        block = self.args.operation(*arguments) & self.fmask
        if self.args.epilogue:
            arguments[1] = block
            self._state = self.args.epilogue(*arguments)
        return block

    def inplace(self, block, *args) -> None:
        super().inplace(block, *args)
