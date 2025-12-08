from __future__ import annotations

from refinery.lib.argformats import PythonExpression
from refinery.lib.meta import metavars
from refinery.lib.types import INF, Param
from refinery.units.blockwise import Arg, ArithmeticUnit, FastBlockError


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
    - the variable `E`: block value of encoded input (not changed after update)
    - the variable `N`: number of bytes in the input
    - the variable `K`: current index in the input
    - the variable `S`: the internal state value
    - the variable `V`: the vector of arguments
    - the variable `I`: function that casts to a signed int in current precision
    - the variable `U`: function that casts to unsigned int in current precision
    - the variable `R`: function; `R(x,4)` rotates x by 4 to the right
    - the variable `L`: function; `L(x,4)` rotates x by 4 to the left
    - the variable `M`: function; `M(x,8)` picks the lower 8 bits of x
    - the variable `X`: function that negates the bits of the input

    (The rotation operations are interpreted as shifts when arbitrary precision is used.)

    Each block of the input is replaced by the value of this expression. Additionally, it is possible to
    specify prologue and epilogue expressions which are used to update the state variable `S` before and
    after the update of each block, respectively.
    """

    @staticmethod
    def _parse_op(definition, default=None):
        if definition:
            return definition
        elif not default:
            raise ValueError('No definition given')
        else:
            return default

    def __init__(
        self,
        operator: Param[str, Arg.String(help='A Python expression defining the operation.')],
        *argument,
        seed: Param[int | str, Arg.String('-s', help=(
            'Optional seed value for the state variable S. The default is zero. This can be an expression '
            'involving the variable N.'))] = 0,
        prologue: Param[str, Arg.String('-p', metavar='E', help=(
            'Optional expression with which the state variable S is updated before a block is operated on.'))] = '',
        epilogue: Param[str, Arg.String('-e', metavar='E', group='EPI', help=(
            'Optional expression with which the state variable S is updated after a block was operated on.'))] = '',
        inc: Param[bool, Arg.Switch('-I', group='EPI', help='equivalent to --epilogue=S+1')] = False,
        dec: Param[bool, Arg.Switch('-D', group='EPI', help='equivalent to --epilogue=S-1')] = False,
        cbc: Param[bool, Arg.Switch('-X', group='EPI', help='equivalent to --epilogue=(B)')] = False,
        ctr: Param[bool, Arg.Switch('-T', group='EPI', help='equivalent to --epilogue=S+B')] = False,
        bigendian=False, blocksize=1, precision=-1
    ):
        for flag, flag_is_set, expression in [
            ('--cbc', cbc, '(B)'),
            ('--inc', inc, 'S+1'),
            ('--dec', dec, 'S-1'),
            ('--ctr', ctr, 'S+B'),
        ]:
            if flag_is_set:
                if epilogue:
                    raise ValueError(
                        F'Ambiguous specification; epilogue was already set to {epilogue} '
                        F'when {flag} was parsed.')
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

    def _fastblock(self, data):
        raise FastBlockError

    def process(self, data):
        context = dict(metavars(data))
        seed = self.args.seed
        fbits = self.fbits
        fmask = self.fmask

        self._index.init(self.fmask)

        def _expression(definition: str):
            return PythonExpression(definition, *'IBEASMNVRLX', all_variables_allowed=True, mask=fmask)

        prologue = _expression(self.args.prologue).expression
        epilogue = _expression(self.args.epilogue).expression
        operator = _expression(self.args.operator).expression

        def cast_unsigned(n) -> int:
            return int(n) & fmask

        def cast_signed(n) -> int:
            n = int(n) & fmask
            if n >> (fbits - 1):
                return -((~n + 1) & fmask)
            else:
                return n

        if fbits is INF:
            def rotate_r(n, k):
                return n >> k

            def rotate_l(n, k):
                return n << k
        else:
            def rotate_r(n, k):
                return (n >> k) | (n << (fbits - k)) & fmask

            def rotate_l(n, k):
                return (n << k) | (n >> (fbits - k)) & fmask

        def negate_bits(n):
            return n ^ fmask

        def mask_to_bits(x, b):
            return x & ((1 << b) - 1)

        context.update(
            N=len(data),
            I=cast_signed,
            U=cast_unsigned,
            R=rotate_r,
            L=rotate_l,
            X=negate_bits,
            M=mask_to_bits,
        )
        args = [
            self._infinitize_argument(len(data), *self._argument_parse_hook(a))
            for a in self.args.argument]
        if args:
            args = [next(iter(a)) for a in args]
            context['A'] = args[0]
            context['V'] = args

        if isinstance(seed, str):
            seed = PythonExpression(seed, 'IAMNVRLX', constants=context, mask=fmask)
        if callable(seed):
            seed = seed(context, N=len(data))

        self._index.init(self.fmask)
        context.update(S=seed)

        def operate(block, index, *args):
            context.update(K=index, B=block, E=block, V=args)
            if args:
                context['A'] = args[0]
            context['S'] = eval(prologue, None, context)
            context['B'] = eval(operator, None, context)
            context['S'] = eval(epilogue, None, context)
            return context['B']

        placeholder = self.operate
        self.operate = operate

        try:
            result = super().process(data)
        finally:
            self.operate = placeholder

        return result

    @staticmethod
    def operate(block, index, *args):
        raise RuntimeError('This operate method cannot be called.')

    def inplace(self, block, *args) -> None:
        super().inplace(block, *args)
