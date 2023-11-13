#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from refinery.units.blockwise import Arg, ArithmeticUnit, FastBlockError
from refinery.lib.meta import metavars
from refinery.lib.argformats import PythonExpression


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


class alu(ArithmeticUnit):
    """
    The arithmetic-logical unit. It allows you to specify a custom Python expression where the following
    variables are allowed:

    - the variable `A`: same as `V[0]`
    - the variable `B`: current block
    - the variable `N`: number of bytes in the input
    - the variable `K`: current index in the input
    - the variable `S`: the internal state value
    - the variable `V`: the vector of arguments
    - the variable `I`: function that casts to a signed int in current precision
    - the variable `U`: function that casts to unsigned int in current precision
    - the variable `R`: function that rotates right
    - the variable `L`: function that rotates left
    - the variable `X`: function that negates the bits of the input

    Each block of the input is replaced by the value of this expression. Additionally, it is possible to
    specify prologue and epilogue expressions which are used to update the state variable `S` before and
    after the update of each block, respectively.
    """

    @staticmethod
    def _parse_op(definition, default=None):
        """
        An argparse type which uses the `refinery.lib.argformats.PythonExpression` parser to parse the
        expressions that can be passed to `refinery.alu`. Essentially, these are Python expressions which can
        contain variables `B`, `A`, `S`, and `V`.
        """
        if not definition:
            if default is None:
                raise ValueError('No definition given')
            definition = default
        return PythonExpression(definition, *'IBASNVRLX', all_variables_allowed=True)

    def __init__(
        self, operator: Arg(type=str, help='A Python expression defining the operation.'), *argument,
        seed: Arg('-s', type=str, help=(
            'Optional seed value for the state variable S. The default is zero. This can be an expression '
            'involving the variable N.')) = 0,
        prologue: Arg('-p', type=str, metavar='E', help=(
            'Optional expression with which the state variable S is updated before a block is operated on.')) = None,
        epilogue: Arg('-e', type=str, metavar='E', group='EPI', help=(
            'Optional expression with which the state variable S is updated after a block was operated on.')) = None,
        inc: Arg('-I', group='EPI', help='equivalent to --epilogue=S+1') = False,
        dec: Arg('-D', group='EPI', help='equivalent to --epilogue=S-1') = False,
        cbc: Arg('-X', group='EPI', help='equivalent to --epilogue=(B)') = False,
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
            seed=seed,
            operator=self._parse_op(operator),
            prologue=self._parse_op(prologue, 'S'),
            epilogue=self._parse_op(epilogue, 'S'),
        )

    @property
    def _is_ecb(self):
        return not self.args.epilogue and not self.args.prologue

    def _fastblock(self, _):
        raise FastBlockError

    def process(self, data):
        context = dict(metavars(data))
        seed = self.args.seed
        if isinstance(seed, str):
            seed = PythonExpression(seed, 'N', constants=metavars(data))
        if callable(seed):
            seed = seed(context, N=len(data))
        self._index.init(self.fmask)
        prologue = self.args.prologue.expression
        epilogue = self.args.epilogue.expression
        operator = self.args.operator.expression
        fbits = self.fbits
        fmask = self.fmask

        def cast_unsigned(n) -> int:
            return int(n) & fmask

        def cast_signed(n) -> int:
            n = int(n) & fmask
            if n >> (fbits - 1):
                return -((~n + 1) & fmask)
            else:
                return n

        def rotate_right(n, k):
            return (n >> k) | (n << (fbits - k)) & fmask

        def rotate_left(n, k):
            return (n << k) | (n >> (fbits - k)) & fmask

        def negate_bits(n):
            return n ^ fmask

        context.update(
            N=len(data),
            S=seed,
            I=cast_signed,
            U=cast_unsigned,
            R=rotate_right,
            L=rotate_left,
            X=negate_bits
        )

        def operate(block, index, *args):
            context.update(K=index, B=block, V=args)
            if args:
                context['A'] = args[0]
            context['S'] = eval(prologue, None, context)
            context['B'] = eval(operator, None, context)
            context['S'] = eval(epilogue, None, context)
            return context['B']

        placeholder = self.operate
        self.operate = operate
        result = super().process(data)
        self.operate = placeholder
        return result

    @staticmethod
    def operate(block, index, *args):
        raise RuntimeError('This operate method cannot be called.')

    def inplace(self, block, *args) -> None:
        super().inplace(block, *args)
