from __future__ import annotations

from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.deobfuscation import deobfuscate
from refinery.lib.scripts.js.model import JsScript
from refinery.lib.scripts.js.options import ExecutionModel
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer
from refinery.lib.types import Param
from refinery.units import Arg
from refinery.units.scripting import IterativeDeobfuscator


class djs(IterativeDeobfuscator):
    """
    AST-based JavaScript deobfuscator and pretty-printer.

    Parses the script into an abstract syntax tree, applies simplifying transformations, and
    synthesizes clean output. This deobfuscator iterates until stable; running it twice does
    not change the output. By default the input is assumed to run as a classic global script; pass
    the module switch when it runs as an ES or CommonJS module instead, or the CommonJS switch when
    it is known to run as the latter. Name any entrypoint a host calls into, or dead-code removal
    will discard it as unreachable.
    """

    def __init__(
        self,
        *entrypoints: Param[str, Arg.String(metavar='pattern', nargs='*', help=(
            'A wildcard pattern naming top-level functions that a host invokes by name, such as the '
            'run handler of a JXA script or a Windows Script Host event handler. Such a function has '
            'no caller inside the file, so it is otherwise removed as unreachable along with '
            'everything only it reached. Give a single asterisk to keep every top-level function.'))],
        timeout=500,
        module: Param[bool, Arg.Switch('-m', help=(
            'Assume the input runs as a module, where a top-level declaration is scoped to the '
            'module and does not attach to the global object, rather than as a classic global '
            'script (a browser script tag, Windows Script Host). The module may be an ES module or '
            'a CommonJS file; use -c when it is known to be the latter.'))] = False,
        commonjs: Param[bool, Arg.Switch('-c', help=(
            'Assume the input runs as a CommonJS module, as node file.js runs it when no package '
            'says otherwise. This implies -m. Unlike an ES module, a CommonJS file is not strict '
            'code unless it says so, so code the input runs from a string can be unpacked into '
            'it.'))] = False,
        environment: Param[str | HostEnvironment, Arg.Option('-e', metavar='E', choices=HostEnvironment, help=(
            'Pin the host the input runs in, so that the global names that host defines are assumed '
            'present and the reads that rely on them are resolved. The default is {default}, which '
            'assumes only the globals every host shares, so a host-conditional read such as window '
            'or global is kept. Options are: {choices}.'))] = HostEnvironment.universal,
        loaded: Param[bool, Arg.Switch('-l', help=(
            'Assume code may load the input and read what it exports: another file that requires it, '
            'as with the main file of a package, or the file itself through the module registry. '
            'Without this switch, a CommonJS file that never reads module back has the store that '
            'replaces module.exports removed.'))] = False,
        strict: Param[bool, Arg.Switch('-s', help=(
            'Assume that unknown reflectively executed code (a direct eval, a Function construction, '
            'a string timer) can change or read anything the rest of the script does. This cleans '
            'less junk code but without the flag, the deobfuscation behavior is formally unsound.'))] = False,
    ):
        super().__init__(
            timeout=timeout,
            module=module,
            commonjs=commonjs,
            entrypoints=entrypoints,
            environment=Arg.AsOption(environment, HostEnvironment),
            loaded=loaded,
            strict=strict,
        )

    def parse(self, data: str) -> JsScript:
        return JsParser(data).parse()

    def transform(self, ast: JsScript) -> int:
        if self.args.commonjs:
            execution = ExecutionModel.commonjs
        elif self.args.module:
            execution = ExecutionModel.module
        else:
            execution = ExecutionModel.script
        return deobfuscate(
            ast,
            execution=execution,
            entrypoints=tuple(self.args.entrypoints),
            environment=self.args.environment,
            trust_eval=not self.args.strict,
            loaded_by_other_files=self.args.loaded,
        )

    def synthesize(self, ast: JsScript) -> str:
        return JsSynthesizer().convert(ast)
