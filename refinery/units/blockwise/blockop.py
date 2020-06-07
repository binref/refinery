#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from ...lib.argformats import PythonExpression
from . import ArithmeticUnit, NoNumpy


class blockop(ArithmeticUnit):
    """
    This unit allows you to specify a custom Python expression where the following variables are allowed.

    - the variable `A`: same as `V[0]`
    - the variable `B`: current block
    - the variable `N`: number of bytes in the input
    - the variable `S`: an optional seed value for an internal state
    - the variable `V`: the vector of arguments

    Each block of the input is replaced by the value of this expression. Additionally, it is possible to
    specify prologue and epilogue expressions which are used to update the state variable `S` before and
    after the update of each block, respectively.
    """

    _PARSER_OPERATION = PythonExpression('B', 'A', 'S', 'N', 'V')
    _PARSER_SEEDVALUE = PythonExpression('N')

    @staticmethod
    def _parse_op(definition):
        """
        An argparse type which uses the `refinery.lib.argformats.PythonExpression` parser to
        parse the expressions that can be passed to `refinery.blockop`. Essentially, these
        are Python expressions which can contain variables `B`, `A`, `S`, and `V`.
        """
        def wrapper(B, S, N, *V):
            return wrapper.parsed(B=B, A=V[0], N=N, S=S, V=V) if V else wrapper.parsed(B=B, S=S)
        wrapper.parsed = blockop._PARSER_OPERATION(definition)
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
        bigendian=False, blocksize=1
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

        if isinstance(seed, str):
            seed = self._PARSER_SEEDVALUE(seed)

        super().__init__(
            *argument,
            bigendian=bigendian,
            blocksize=blocksize,
            operation=self._parse_op(operation),
            seed=seed,
            prologue=prologue and self._parse_op(prologue),
            epilogue=epilogue and self._parse_op(epilogue),
        )

    @property
    def ecb(self):
        return not self.args.epilogue and not self.args.prologue

    def process_ecb_fast(self, data):
        if not self.ecb:
            raise NoNumpy
        return super().process_ecb_fast(data)

    def process(self, data):
        self._total = len(data)
        self._state = self.args.seed
        if callable(self._state):
            self._state = self._state(N=self._total)
        return super().process(data)

    def operate(self, block, *args):
        if self.args.prologue:
            self._state = self.args.prologue(block, self._state, self._total, *args)
        block = self.args.operation(block, self._state, self._total, *args) & self.fmask
        if self.args.epilogue:
            self._state = self.args.epilogue(block, self._state, self._total, *args)
        return block
