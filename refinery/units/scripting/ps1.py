from __future__ import annotations

from refinery.lib.scripts.ps1.deobfuscation import deobfuscate
from refinery.lib.scripts.ps1.model import Ps1Script
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer
from refinery.lib.types import Param
from refinery.units import Arg
from refinery.units.scripting import IterativeDeobfuscator


class ps1(IterativeDeobfuscator):
    """
    AST-based PowerShell deobfuscator.

    Parses the script into an abstract syntax tree, applies simplifying transformations (constant
    folding, format string evaluation, bracket removal, type cast simplification, string
    operations, case normalization, invoke simplification, uncurly variables), and synthesizes
    clean output. Iterates until stable; running this twice does not change the output.
    """

    def __init__(
        self,
        timeout=500,
        stdout: Param[bool, Arg.Switch('-o', help=(
            'Keep every statement that writes a value to the success output stream, including bare '
            'literals an obfuscator may have injected as noise. Use this when the input is a module '
            'or a fragment of a larger script, where such a value can reach a caller rather than '
            'only the console.'))] = False,
        env: Param[bool, Arg.Switch('-e', '--env', help=(
            'Keep every assignment to an environment variable, including ones an obfuscator may '
            'have injected as noise and no statement in the file reads.'))] = False,
        strict: Param[bool, Arg.Switch('-s', help=(
            'Assume that unknown reflectively executed code (iex, a call through a variable) can '
            'change or read anything the rest of the script does. This cleans less junk code but '
            'without the flag, the deobfuscation behavior is formally unsound.'))] = False,
    ):
        super().__init__(timeout=timeout, stdout=stdout, strict=strict, env=env)

    def parse(self, data: str) -> Ps1Script:
        return Ps1Parser(data).parse()

    def transform(self, ast: Ps1Script) -> int:
        return deobfuscate(
            ast,
            preserve_bare_output=self.args.stdout,
            trust_eval=not self.args.strict,
            preserve_env_stores=self.args.env,
        )

    def synthesize(self, ast: Ps1Script) -> str:
        return Ps1Synthesizer().convert(ast)
