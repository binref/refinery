"""
The model of `test.lib.scripts.ps1.dispatch` held to what Windows PowerShell 5.1 wrote, and the
analysis held to the model over generated programs.
"""
from __future__ import annotations

import functools
import re

from dataclasses import dataclass
from typing import NamedTuple

from test import TestBase
from test.lib.scripts.ps1 import corpus, dispatch
from test.lib.scripts.ps1.dispatch import (
    BodyGenerator,
    Break,
    Call,
    Catch,
    Continue,
    Def,
    Event,
    Exit,
    Fail,
    Generator,
    If,
    Invoke,
    Loop,
    Mark,
    Outcome,
    Prefer,
    Preference,
    Return,
    Set,
    Show,
    Statement,
    Store,
    Sub,
    Throw,
    Trap,
    Try,
)

from refinery.lib.scripts import Block, Node
from refinery.lib.scripts.analysis.cfg import CfgNode, ControlFlowGraph
from refinery.lib.scripts.ps1.analysis.cache import Ps1ModelCache
from refinery.lib.scripts.ps1.analysis.cfg import Ps1ControlFlowModel, Ps1ReportNode
from refinery.lib.scripts.ps1.analysis.dispatch import Ps1Dispatch, Ps1ErrorKind, member_of
from refinery.lib.scripts.ps1.analysis.effects import deletion_is_observable
from refinery.lib.scripts.ps1.analysis.handlers import handler_acts
from refinery.lib.scripts.ps1.deobfuscation import deobfuscate
from refinery.lib.scripts.ps1.model import (
    Ps1AssignmentExpression,
    Ps1BreakStatement,
    Ps1CatchClause,
    Ps1CommandInvocation,
    Ps1ContinueStatement,
    Ps1ExitStatement,
    Ps1ExpressionStatement,
    Ps1ForEachLoop,
    Ps1FunctionDefinition,
    Ps1IfStatement,
    Ps1ReturnStatement,
    Ps1ScriptBlock,
    Ps1SubExpression,
    Ps1ThrowStatement,
    Ps1TrapStatement,
    Ps1TryCatchFinally,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer


def shown(trace: dispatch.Trace) -> str:
    """
    A trace as the transcripts below record it: each mark, `ERROR` for an error 5.1 reported and
    stepped over, and `THROW` where the run ended on one.
    """
    return ' '.join(
        event.value if isinstance(event, Event) else event for event in trace if event is not Event.ENDED)


#: What Windows PowerShell 5.1 wrote for each anchor of `test.lib.scripts.ps1.dispatch.ANCHORS`,
#: measured on 2026-10-29 by running each one as `test.lib.scripts.ps1.corpus.DISPATCH` renders it,
#: in the form `shown` gives. An anchor added or changed has no entry until it is measured with
#: `test.lib.scripts.ps1.oracle.behaviours`.
DISPATCH_TRANSCRIPTS: dict[str, str] = {
    'top / cast / Continue'                                                                   : 'ERROR rest',
    'if / cast / Continue'                                                                    : 'ERROR rest after',
    'loop / cast / Continue'                                                                  : 'ERROR rest ERROR rest after',
    'try body, finally / cast / Continue'                                                     : 'fin ERROR after',
    'catch body / cast / Continue'                                                            : 'ERROR after',
    'finally body / cast / Continue'                                                          : 't ERROR rest after',
    'finally body, error / cast / Continue'                                                   : 'c after',
    'trap body / cast / Continue'                                                             : 'THROW',
    'subexpression / cast / Continue'                                                         : 'ERROR rest after',
    'if in a catch body / cast / Continue'                                                    : 'ERROR after',
    'try in a try body / cast / Continue'                                                     : 'ERROR after',
    'loop in a try body / cast / Continue'                                                    : 'c after',
    'finally body, error, in a catch body / cast / Continue'                                  : 'ERROR after',
    'trap body, run from a try / cast / Continue'                                             : 't t THROW',
    'try body, catch [RuntimeException] or [InvalidCastException] / cast / Continue'          : 'i after',
    'try body, catch [RuntimeException] or [Exception] / cast / Continue'                     : 'e after',
    'try body, catch [untyped] / cast / Continue'                                             : 'c after',
    'trapped block, continue [untyped] / cast / Continue'                                     : 't rest after',
    'under a trapped block, continue [untyped] / cast / Continue'                             : 't after',
    'trapped block, break [untyped] / cast / Continue'                                        : 't THROW',
    'under a trapped block, break [untyped] / cast / Continue'                                : 't THROW',
    'trapped block, runs off [untyped] / cast / Continue'                                     : 't ERROR rest after',
    'under a trapped block, runs off [untyped] / cast / Continue'                             : 't ERROR after',
    'try body, catch [RuntimeException] / cast / Continue'                                    : 'c after',
    'trapped block, continue [RuntimeException] / cast / Continue'                            : 't rest after',
    'under a trapped block, continue [RuntimeException] / cast / Continue'                    : 't after',
    'trapped block, break [RuntimeException] / cast / Continue'                               : 't THROW',
    'under a trapped block, break [RuntimeException] / cast / Continue'                       : 't THROW',
    'trapped block, runs off [RuntimeException] / cast / Continue'                            : 't ERROR rest after',
    'under a trapped block, runs off [RuntimeException] / cast / Continue'                    : 't ERROR after',
    'try body, catch [InvalidCastException] / cast / Continue'                                : 'c after',
    'trapped block, continue [InvalidCastException] / cast / Continue'                        : 't rest after',
    'under a trapped block, continue [InvalidCastException] / cast / Continue'                : 't after',
    'trapped block, break [InvalidCastException] / cast / Continue'                           : 't THROW',
    'under a trapped block, break [InvalidCastException] / cast / Continue'                   : 't THROW',
    'trapped block, runs off [InvalidCastException] / cast / Continue'                        : 't ERROR rest after',
    'under a trapped block, runs off [InvalidCastException] / cast / Continue'                : 't ERROR after',
    'try body, catch [IOException] / cast / Continue'                                         : 'ERROR after',
    'trapped block, continue [IOException] / cast / Continue'                                 : 'THROW',
    'under a trapped block, continue [IOException] / cast / Continue'                         : 'THROW',
    'trapped block, break [IOException] / cast / Continue'                                    : 'THROW',
    'under a trapped block, break [IOException] / cast / Continue'                            : 'THROW',
    'trapped block, runs off [IOException] / cast / Continue'                                 : 'THROW',
    'under a trapped block, runs off [IOException] / cast / Continue'                         : 'THROW',
    'function at script scope / cast / Continue'                                              : 'ERROR rest after',
    'function in a try body / cast / Continue'                                                : 'c after',
    'function in a catch body / cast / Continue'                                              : 'ERROR after',
    'function under a trap / cast / Continue'                                                 : 't after',
    'script block in a catch body / cast / Continue'                                          : 'ERROR after',
    'return through a finally / cast / Continue'                                              : 'f after',
    'continue through a finally / cast / Continue'                                            : 'f m f m after',
    'exit through a finally / cast / Continue'                                                : 'f after',
    'return through a finally, function / cast / Continue'                                    : 'f tail after',
    'preference written to Stop / cast / Continue'                                            : 'THROW',
    'top / cast / SilentlyContinue'                                                           : 'rest',
    'if / cast / SilentlyContinue'                                                            : 'rest after',
    'loop / cast / SilentlyContinue'                                                          : 'rest rest after',
    'try body, finally / cast / SilentlyContinue'                                             : 'fin after',
    'catch body / cast / SilentlyContinue'                                                    : 'after',
    'finally body / cast / SilentlyContinue'                                                  : 't rest after',
    'finally body, error / cast / SilentlyContinue'                                           : 'c after',
    'subexpression / cast / SilentlyContinue'                                                 : 'rest after',
    'if in a catch body / cast / SilentlyContinue'                                            : 'after',
    'try in a try body / cast / SilentlyContinue'                                             : 'after',
    'loop in a try body / cast / SilentlyContinue'                                            : 'c after',
    'finally body, error, in a catch body / cast / SilentlyContinue'                          : 'after',
    'try body, catch [RuntimeException] or [InvalidCastException] / cast / SilentlyContinue'  : 'i after',
    'try body, catch [RuntimeException] or [Exception] / cast / SilentlyContinue'             : 'e after',
    'try body, catch [untyped] / cast / SilentlyContinue'                                     : 'c after',
    'trapped block, continue [untyped] / cast / SilentlyContinue'                             : 't rest after',
    'under a trapped block, continue [untyped] / cast / SilentlyContinue'                     : 't after',
    'trapped block, break [untyped] / cast / SilentlyContinue'                                : 't THROW',
    'under a trapped block, break [untyped] / cast / SilentlyContinue'                        : 't THROW',
    'trapped block, runs off [untyped] / cast / SilentlyContinue'                             : 't rest after',
    'under a trapped block, runs off [untyped] / cast / SilentlyContinue'                     : 't after',
    'try body, catch [RuntimeException] / cast / SilentlyContinue'                            : 'c after',
    'trapped block, continue [RuntimeException] / cast / SilentlyContinue'                    : 't rest after',
    'under a trapped block, continue [RuntimeException] / cast / SilentlyContinue'            : 't after',
    'trapped block, break [RuntimeException] / cast / SilentlyContinue'                       : 't THROW',
    'under a trapped block, break [RuntimeException] / cast / SilentlyContinue'               : 't THROW',
    'trapped block, runs off [RuntimeException] / cast / SilentlyContinue'                    : 't rest after',
    'under a trapped block, runs off [RuntimeException] / cast / SilentlyContinue'            : 't after',
    'try body, catch [InvalidCastException] / cast / SilentlyContinue'                        : 'c after',
    'trapped block, continue [InvalidCastException] / cast / SilentlyContinue'                : 't rest after',
    'under a trapped block, continue [InvalidCastException] / cast / SilentlyContinue'        : 't after',
    'trapped block, break [InvalidCastException] / cast / SilentlyContinue'                   : 't THROW',
    'under a trapped block, break [InvalidCastException] / cast / SilentlyContinue'           : 't THROW',
    'trapped block, runs off [InvalidCastException] / cast / SilentlyContinue'                : 't rest after',
    'under a trapped block, runs off [InvalidCastException] / cast / SilentlyContinue'        : 't after',
    'try body, catch [IOException] / cast / SilentlyContinue'                                 : 'after',
    'trapped block, continue [IOException] / cast / SilentlyContinue'                         : 'THROW',
    'under a trapped block, continue [IOException] / cast / SilentlyContinue'                 : 'THROW',
    'trapped block, break [IOException] / cast / SilentlyContinue'                            : 'THROW',
    'under a trapped block, break [IOException] / cast / SilentlyContinue'                    : 'THROW',
    'trapped block, runs off [IOException] / cast / SilentlyContinue'                         : 'THROW',
    'under a trapped block, runs off [IOException] / cast / SilentlyContinue'                 : 'THROW',
    'function at script scope / cast / SilentlyContinue'                                      : 'rest after',
    'function in a try body / cast / SilentlyContinue'                                        : 'c after',
    'function in a catch body / cast / SilentlyContinue'                                      : 'after',
    'function under a trap / cast / SilentlyContinue'                                         : 't after',
    'script block in a catch body / cast / SilentlyContinue'                                  : 'after',
    'return through a finally / cast / SilentlyContinue'                                      : 'f after',
    'continue through a finally / cast / SilentlyContinue'                                    : 'f m f m after',
    'exit through a finally / cast / SilentlyContinue'                                        : 'f after',
    'return through a finally, function / cast / SilentlyContinue'                            : 'f tail after',
    'preference written to Stop / cast / SilentlyContinue'                                    : 'THROW',
    'top / cast / Stop'                                                                       : 'THROW',
    'if / cast / Stop'                                                                        : 'THROW',
    'loop / cast / Stop'                                                                      : 'THROW',
    'try body, finally / cast / Stop'                                                         : 'fin THROW',
    'catch body / cast / Stop'                                                                : 'THROW',
    'finally body / cast / Stop'                                                              : 't THROW',
    'finally body, error / cast / Stop'                                                       : 'c after',
    'trap body / cast / Stop'                                                                 : 'THROW',
    'subexpression / cast / Stop'                                                             : 'THROW',
    'if in a catch body / cast / Stop'                                                        : 'THROW',
    'try in a try body / cast / Stop'                                                         : 'THROW',
    'loop in a try body / cast / Stop'                                                        : 'c after',
    'finally body, error, in a catch body / cast / Stop'                                      : 'THROW',
    'trap body, run from a try / cast / Stop'                                                 : 't t THROW',
    'try body, catch [RuntimeException] or [InvalidCastException] / cast / Stop'              : 'i after',
    'try body, catch [RuntimeException] or [Exception] / cast / Stop'                         : 'e after',
    'try body, catch [untyped] / cast / Stop'                                                 : 'c after',
    'trapped block, continue [untyped] / cast / Stop'                                         : 't rest after',
    'under a trapped block, continue [untyped] / cast / Stop'                                 : 't after',
    'trapped block, break [untyped] / cast / Stop'                                            : 't THROW',
    'under a trapped block, break [untyped] / cast / Stop'                                    : 't THROW',
    'trapped block, runs off [untyped] / cast / Stop'                                         : 't THROW',
    'under a trapped block, runs off [untyped] / cast / Stop'                                 : 't THROW',
    'try body, catch [RuntimeException] / cast / Stop'                                        : 'c after',
    'trapped block, continue [RuntimeException] / cast / Stop'                                : 't rest after',
    'under a trapped block, continue [RuntimeException] / cast / Stop'                        : 't after',
    'trapped block, break [RuntimeException] / cast / Stop'                                   : 't THROW',
    'under a trapped block, break [RuntimeException] / cast / Stop'                           : 't THROW',
    'trapped block, runs off [RuntimeException] / cast / Stop'                                : 't THROW',
    'under a trapped block, runs off [RuntimeException] / cast / Stop'                        : 't THROW',
    'try body, catch [InvalidCastException] / cast / Stop'                                    : 'c after',
    'trapped block, continue [InvalidCastException] / cast / Stop'                            : 't rest after',
    'under a trapped block, continue [InvalidCastException] / cast / Stop'                    : 't after',
    'trapped block, break [InvalidCastException] / cast / Stop'                               : 't THROW',
    'under a trapped block, break [InvalidCastException] / cast / Stop'                       : 't THROW',
    'trapped block, runs off [InvalidCastException] / cast / Stop'                            : 't THROW',
    'under a trapped block, runs off [InvalidCastException] / cast / Stop'                    : 't THROW',
    'try body, catch [IOException] / cast / Stop'                                             : 'THROW',
    'trapped block, continue [IOException] / cast / Stop'                                     : 'THROW',
    'under a trapped block, continue [IOException] / cast / Stop'                             : 'THROW',
    'trapped block, break [IOException] / cast / Stop'                                        : 'THROW',
    'under a trapped block, break [IOException] / cast / Stop'                                : 'THROW',
    'trapped block, runs off [IOException] / cast / Stop'                                     : 'THROW',
    'under a trapped block, runs off [IOException] / cast / Stop'                             : 'THROW',
    'function at script scope / cast / Stop'                                                  : 'THROW',
    'function in a try body / cast / Stop'                                                    : 'c after',
    'function in a catch body / cast / Stop'                                                  : 'THROW',
    'function under a trap / cast / Stop'                                                     : 't after',
    'script block in a catch body / cast / Stop'                                              : 'THROW',
    'return through a finally / cast / Stop'                                                  : 'f after',
    'continue through a finally / cast / Stop'                                                : 'f m f m after',
    'exit through a finally / cast / Stop'                                                    : 'f after',
    'return through a finally, function / cast / Stop'                                        : 'f tail after',
    'preference written to Stop / cast / Stop'                                                : 'THROW',
    'top / throw / Continue'                                                                  : 'THROW',
    'if / throw / Continue'                                                                   : 'THROW',
    'loop / throw / Continue'                                                                 : 'THROW',
    'try body, finally / throw / Continue'                                                    : 'fin THROW',
    'catch body / throw / Continue'                                                           : 'THROW',
    'finally body / throw / Continue'                                                         : 't THROW',
    'finally body, error / throw / Continue'                                                  : 'c after',
    'trap body / throw / Continue'                                                            : 'THROW',
    'subexpression / throw / Continue'                                                        : 'THROW',
    'if in a catch body / throw / Continue'                                                   : 'THROW',
    'try in a try body / throw / Continue'                                                    : 'THROW',
    'loop in a try body / throw / Continue'                                                   : 'c after',
    'finally body, error, in a catch body / throw / Continue'                                 : 'THROW',
    'trap body, run from a try / throw / Continue'                                            : 't t THROW',
    'try body, catch [RuntimeException] or [InvalidCastException] / throw / Continue'         : 'r after',
    'try body, catch [RuntimeException] or [Exception] / throw / Continue'                    : 'r after',
    'try body, catch [untyped] / throw / Continue'                                            : 'c after',
    'trapped block, continue [untyped] / throw / Continue'                                    : 't rest after',
    'under a trapped block, continue [untyped] / throw / Continue'                            : 't after',
    'trapped block, break [untyped] / throw / Continue'                                       : 't THROW',
    'under a trapped block, break [untyped] / throw / Continue'                               : 't THROW',
    'trapped block, runs off [untyped] / throw / Continue'                                    : 't ERROR rest after',
    'under a trapped block, runs off [untyped] / throw / Continue'                            : 't ERROR after',
    'try body, catch [RuntimeException] / throw / Continue'                                   : 'c after',
    'trapped block, continue [RuntimeException] / throw / Continue'                           : 't rest after',
    'under a trapped block, continue [RuntimeException] / throw / Continue'                   : 't after',
    'trapped block, break [RuntimeException] / throw / Continue'                              : 't THROW',
    'under a trapped block, break [RuntimeException] / throw / Continue'                      : 't THROW',
    'trapped block, runs off [RuntimeException] / throw / Continue'                           : 't ERROR rest after',
    'under a trapped block, runs off [RuntimeException] / throw / Continue'                   : 't ERROR after',
    'try body, catch [InvalidCastException] / throw / Continue'                               : 'THROW',
    'trapped block, continue [InvalidCastException] / throw / Continue'                       : 'THROW',
    'under a trapped block, continue [InvalidCastException] / throw / Continue'               : 'THROW',
    'trapped block, break [InvalidCastException] / throw / Continue'                          : 'THROW',
    'under a trapped block, break [InvalidCastException] / throw / Continue'                  : 'THROW',
    'trapped block, runs off [InvalidCastException] / throw / Continue'                       : 'THROW',
    'under a trapped block, runs off [InvalidCastException] / throw / Continue'               : 'THROW',
    'try body, catch [IOException] / throw / Continue'                                        : 'THROW',
    'trapped block, continue [IOException] / throw / Continue'                                : 'THROW',
    'under a trapped block, continue [IOException] / throw / Continue'                        : 'THROW',
    'trapped block, break [IOException] / throw / Continue'                                   : 'THROW',
    'under a trapped block, break [IOException] / throw / Continue'                           : 'THROW',
    'trapped block, runs off [IOException] / throw / Continue'                                : 'THROW',
    'under a trapped block, runs off [IOException] / throw / Continue'                        : 'THROW',
    'function at script scope / throw / Continue'                                             : 'THROW',
    'function in a try body / throw / Continue'                                               : 'c after',
    'function in a catch body / throw / Continue'                                             : 'THROW',
    'function under a trap / throw / Continue'                                                : 't after',
    'script block in a catch body / throw / Continue'                                         : 'THROW',
    'return through a finally / throw / Continue'                                             : 'f after',
    'continue through a finally / throw / Continue'                                           : 'f m f m after',
    'exit through a finally / throw / Continue'                                               : 'f after',
    'return through a finally, function / throw / Continue'                                   : 'f tail after',
    'preference written to Stop / throw / Continue'                                           : 'THROW',
    'top / throw / SilentlyContinue'                                                          : 'rest',
    'if / throw / SilentlyContinue'                                                           : 'rest after',
    'loop / throw / SilentlyContinue'                                                         : 'rest rest after',
    'try body, finally / throw / SilentlyContinue'                                            : 'fin after',
    'catch body / throw / SilentlyContinue'                                                   : 'after',
    'finally body / throw / SilentlyContinue'                                                 : 't rest after',
    'finally body, error / throw / SilentlyContinue'                                          : 'c after',
    'subexpression / throw / SilentlyContinue'                                                : 'rest after',
    'if in a catch body / throw / SilentlyContinue'                                           : 'after',
    'try in a try body / throw / SilentlyContinue'                                            : 'after',
    'loop in a try body / throw / SilentlyContinue'                                           : 'c after',
    'finally body, error, in a catch body / throw / SilentlyContinue'                         : 'after',
    'try body, catch [RuntimeException] or [InvalidCastException] / throw / SilentlyContinue' : 'r after',
    'try body, catch [RuntimeException] or [Exception] / throw / SilentlyContinue'            : 'r after',
    'try body, catch [untyped] / throw / SilentlyContinue'                                    : 'c after',
    'trapped block, continue [untyped] / throw / SilentlyContinue'                            : 't rest after',
    'under a trapped block, continue [untyped] / throw / SilentlyContinue'                    : 't after',
    'trapped block, break [untyped] / throw / SilentlyContinue'                               : 't THROW',
    'under a trapped block, break [untyped] / throw / SilentlyContinue'                       : 't THROW',
    'trapped block, runs off [untyped] / throw / SilentlyContinue'                            : 't rest after',
    'under a trapped block, runs off [untyped] / throw / SilentlyContinue'                    : 't after',
    'try body, catch [RuntimeException] / throw / SilentlyContinue'                           : 'c after',
    'trapped block, continue [RuntimeException] / throw / SilentlyContinue'                   : 't rest after',
    'under a trapped block, continue [RuntimeException] / throw / SilentlyContinue'           : 't after',
    'trapped block, break [RuntimeException] / throw / SilentlyContinue'                      : 't THROW',
    'under a trapped block, break [RuntimeException] / throw / SilentlyContinue'              : 't THROW',
    'trapped block, runs off [RuntimeException] / throw / SilentlyContinue'                   : 't rest after',
    'under a trapped block, runs off [RuntimeException] / throw / SilentlyContinue'           : 't after',
    'try body, catch [InvalidCastException] / throw / SilentlyContinue'                       : 'after',
    'trapped block, continue [InvalidCastException] / throw / SilentlyContinue'               : 'THROW',
    'under a trapped block, continue [InvalidCastException] / throw / SilentlyContinue'       : 'THROW',
    'trapped block, break [InvalidCastException] / throw / SilentlyContinue'                  : 'THROW',
    'under a trapped block, break [InvalidCastException] / throw / SilentlyContinue'          : 'THROW',
    'trapped block, runs off [InvalidCastException] / throw / SilentlyContinue'               : 'THROW',
    'under a trapped block, runs off [InvalidCastException] / throw / SilentlyContinue'       : 'THROW',
    'try body, catch [IOException] / throw / SilentlyContinue'                                : 'after',
    'trapped block, continue [IOException] / throw / SilentlyContinue'                        : 'THROW',
    'under a trapped block, continue [IOException] / throw / SilentlyContinue'                : 'THROW',
    'trapped block, break [IOException] / throw / SilentlyContinue'                           : 'THROW',
    'under a trapped block, break [IOException] / throw / SilentlyContinue'                   : 'THROW',
    'trapped block, runs off [IOException] / throw / SilentlyContinue'                        : 'THROW',
    'under a trapped block, runs off [IOException] / throw / SilentlyContinue'                : 'THROW',
    'function at script scope / throw / SilentlyContinue'                                     : 'rest after',
    'function in a try body / throw / SilentlyContinue'                                       : 'c after',
    'function in a catch body / throw / SilentlyContinue'                                     : 'after',
    'function under a trap / throw / SilentlyContinue'                                        : 't after',
    'script block in a catch body / throw / SilentlyContinue'                                 : 'after',
    'return through a finally / throw / SilentlyContinue'                                     : 'f after',
    'continue through a finally / throw / SilentlyContinue'                                   : 'f m f m after',
    'exit through a finally / throw / SilentlyContinue'                                       : 'f after',
    'return through a finally, function / throw / SilentlyContinue'                           : 'f tail after',
    'preference written to Stop / throw / SilentlyContinue'                                   : 'THROW',
    'top / throw / Stop'                                                                      : 'THROW',
    'if / throw / Stop'                                                                       : 'THROW',
    'loop / throw / Stop'                                                                     : 'THROW',
    'try body, finally / throw / Stop'                                                        : 'fin THROW',
    'catch body / throw / Stop'                                                               : 'THROW',
    'finally body / throw / Stop'                                                             : 't THROW',
    'finally body, error / throw / Stop'                                                      : 'c after',
    'trap body / throw / Stop'                                                                : 'THROW',
    'subexpression / throw / Stop'                                                            : 'THROW',
    'if in a catch body / throw / Stop'                                                       : 'THROW',
    'try in a try body / throw / Stop'                                                        : 'THROW',
    'loop in a try body / throw / Stop'                                                       : 'c after',
    'finally body, error, in a catch body / throw / Stop'                                     : 'THROW',
    'trap body, run from a try / throw / Stop'                                                : 't t THROW',
    'try body, catch [RuntimeException] or [InvalidCastException] / throw / Stop'             : 'r after',
    'try body, catch [RuntimeException] or [Exception] / throw / Stop'                        : 'r after',
    'try body, catch [untyped] / throw / Stop'                                                : 'c after',
    'trapped block, continue [untyped] / throw / Stop'                                        : 't rest after',
    'under a trapped block, continue [untyped] / throw / Stop'                                : 't after',
    'trapped block, break [untyped] / throw / Stop'                                           : 't THROW',
    'under a trapped block, break [untyped] / throw / Stop'                                   : 't THROW',
    'trapped block, runs off [untyped] / throw / Stop'                                        : 't THROW',
    'under a trapped block, runs off [untyped] / throw / Stop'                                : 't THROW',
    'try body, catch [RuntimeException] / throw / Stop'                                       : 'c after',
    'trapped block, continue [RuntimeException] / throw / Stop'                               : 't rest after',
    'under a trapped block, continue [RuntimeException] / throw / Stop'                       : 't after',
    'trapped block, break [RuntimeException] / throw / Stop'                                  : 't THROW',
    'under a trapped block, break [RuntimeException] / throw / Stop'                          : 't THROW',
    'trapped block, runs off [RuntimeException] / throw / Stop'                               : 't THROW',
    'under a trapped block, runs off [RuntimeException] / throw / Stop'                       : 't THROW',
    'try body, catch [InvalidCastException] / throw / Stop'                                   : 'THROW',
    'trapped block, continue [InvalidCastException] / throw / Stop'                           : 'THROW',
    'under a trapped block, continue [InvalidCastException] / throw / Stop'                   : 'THROW',
    'trapped block, break [InvalidCastException] / throw / Stop'                              : 'THROW',
    'under a trapped block, break [InvalidCastException] / throw / Stop'                      : 'THROW',
    'trapped block, runs off [InvalidCastException] / throw / Stop'                           : 'THROW',
    'under a trapped block, runs off [InvalidCastException] / throw / Stop'                   : 'THROW',
    'try body, catch [IOException] / throw / Stop'                                            : 'THROW',
    'trapped block, continue [IOException] / throw / Stop'                                    : 'THROW',
    'under a trapped block, continue [IOException] / throw / Stop'                            : 'THROW',
    'trapped block, break [IOException] / throw / Stop'                                       : 'THROW',
    'under a trapped block, break [IOException] / throw / Stop'                               : 'THROW',
    'trapped block, runs off [IOException] / throw / Stop'                                    : 'THROW',
    'under a trapped block, runs off [IOException] / throw / Stop'                            : 'THROW',
    'function at script scope / throw / Stop'                                                 : 'THROW',
    'function in a try body / throw / Stop'                                                   : 'c after',
    'function in a catch body / throw / Stop'                                                 : 'THROW',
    'function under a trap / throw / Stop'                                                    : 't after',
    'script block in a catch body / throw / Stop'                                             : 'THROW',
    'return through a finally / throw / Stop'                                                 : 'f after',
    'continue through a finally / throw / Stop'                                               : 'f m f m after',
    'exit through a finally / throw / Stop'                                                   : 'f after',
    'return through a finally, function / throw / Stop'                                       : 'f tail after',
    'preference written to Stop / throw / Stop'                                               : 'THROW',
    'failing store / Continue'                                                                : 'ERROR one',
    'failing store under a resuming trap / Continue'                                          : 'one',
    'failing store in a function / Continue'                                                  : 'ERROR one ',
    'failing store / SilentlyContinue'                                                        : 'one',
    'failing store under a resuming trap / SilentlyContinue'                                  : 'one',
    'failing store in a function / SilentlyContinue'                                          : 'one ',
    'failing store / Stop'                                                                    : 'THROW',
    'failing store under a resuming trap / Stop'                                              : 'one',
    'failing store in a function / Stop'                                                      : 'THROW',
}


class Unreadable(Exception):
    pass


_SYNTH = Ps1Synthesizer()
_FAIL = re.compile(r'^\$null = \[int\]\$(?:args|p)\[(\d+)\]$', re.IGNORECASE)
_STORE = re.compile(r'^\$(v\d+) = \[int\]\$(?:args|p)\[(\d+)\]$', re.IGNORECASE)
_SET = re.compile(r"^\$(v\d+) = '(\w*)'$", re.IGNORECASE)
_SHOW = re.compile(r'^Write-Host \$(v\d+)$', re.IGNORECASE)
_MARK = re.compile(r"^Write-Host '(\w*)'$", re.IGNORECASE)
_SHOWN = re.compile(r'^Write-Host(?: (\d+|\$null))?$', re.IGNORECASE)
_CALL = re.compile(r'^(f\d+)$', re.IGNORECASE)
_COPY = re.compile(r'^\$p = \$args$', re.IGNORECASE)
_TEST = re.compile(r'^\$(?:args|p)\[(\d+)\]$', re.IGNORECASE)
_PREFERENCE = re.compile(r"^\$ErrorActionPreference = '(\w+)'$", re.IGNORECASE)


class _Reader:
    """
    Reads a script `test.lib.scripts.ps1.dispatch.render` wrote, or the deobfuscator made of one,
    back into the grammar, and keeps which node each statement was read from. The lines `render`
    writes ahead of the program — the preference it runs under, and the copy of its inputs — are
    read past where they open the script.
    """

    def __init__(self):
        self.nodes: dict[int, Node] = {}

    def script(self, body, rewritten: bool = False) -> tuple[Statement, ...]:
        """
        The program *body* holds. In a *rewritten* script a preference line is read as the
        statement it is: deleting what stood before it can move a line of the program to the top,
        and one the header left there sets the preference the run already starts with.
        """
        body = list(body)
        if rewritten:
            for index, node in enumerate(body[:2]):
                if isinstance(node, Ps1ExpressionStatement) and _COPY.match(_SYNTH.convert(node).strip()):
                    del body[index]
                    break
            return self.program(body)
        for line in (_PREFERENCE, _COPY):
            if body and isinstance(body[0], Ps1ExpressionStatement) and line.match(_SYNTH.convert(body[0]).strip()):
                body.pop(0)
        return self.program(body)

    def program(self, body) -> tuple[Statement, ...]:
        read: list[Statement] = []
        for node in body:
            statement = self._statement(node)
            if statement is not None:
                self.nodes[id(statement)] = node
                read.append(statement)
        return tuple(read)

    def _block(self, block) -> tuple[Statement, ...]:
        return () if block is None else self.program(block.body)

    def _statement(self, node) -> Statement | None:
        if isinstance(node, Ps1FunctionDefinition):
            if node.body is None or node.is_filter:
                raise Unreadable(_SYNTH.convert(node))
            return Def(node.name, self.program(node.body.body))
        if isinstance(node, Ps1ReturnStatement) and node.pipeline is None:
            return Return()
        if isinstance(node, Ps1ExitStatement) and node.pipeline is None:
            return Exit()
        if isinstance(node, Ps1ExpressionStatement):
            text = _SYNTH.convert(node).strip()
            if (match := _PREFERENCE.match(text)):
                return Prefer(Preference(next(p.value for p in Preference if p.value.lower() == match.group(1).lower())))
            if (match := _FAIL.match(text)):
                return Fail(int(match.group(1)))
            if (match := _STORE.match(text)):
                return Store(match.group(1).lower(), int(match.group(2)))
            if (match := _SET.match(text)):
                return Set(match.group(1).lower(), match.group(2))
            if (match := _SHOW.match(text)):
                return Show(match.group(1).lower())
            if (match := _MARK.match(text)):
                return Mark(match.group(1))
            if (match := _SHOWN.match(text)):
                shown = match.group(1)
                return Mark('' if shown is None or shown.lower() == '$null' else shown)
            if (match := _CALL.match(text)):
                return Call(match.group(1).lower())
            expression = node.expression
            if (
                isinstance(expression, Ps1CommandInvocation)
                and expression.invocation_operator == '&'
                and isinstance(expression.name, Ps1ScriptBlock)
                and not expression.arguments
            ):
                return Invoke(self.program(expression.name.body))
            if (
                isinstance(expression, Ps1AssignmentExpression)
                and isinstance(expression.value, Ps1SubExpression)
                and expression.target is not None
                and _SYNTH.convert(expression.target).strip().lower() == '$null'
            ):
                return Sub(self.program(expression.value.body))
            raise Unreadable(text)
        if isinstance(node, Ps1ThrowStatement):
            return Throw()
        if isinstance(node, Ps1IfStatement):
            if len(node.clauses) != 1:
                raise Unreadable(_SYNTH.convert(node))
            condition, block = node.clauses[0]
            if not (match := _TEST.match(_SYNTH.convert(condition).strip())):
                raise Unreadable(_SYNTH.convert(node))
            return If(int(match.group(1)), self._block(block), self._block(node.else_block))
        if isinstance(node, Ps1ForEachLoop):
            return Loop(self._block(node.body))
        if isinstance(node, Ps1TryCatchFinally):
            catches = []
            for clause in node.catch_clauses:
                if len(clause.types) > 1:
                    raise Unreadable(_SYNTH.convert(node))
                catches.append(Catch(clause.types[0] if clause.types else None, self._block(clause.body)))
            final = None if node.finally_block is None else self._block(node.finally_block)
            return Try(self._block(node.try_block), tuple(catches), final)
        if isinstance(node, Ps1TrapStatement):
            return Trap(node.type_name.strip() or None, self._block(node.body))
        if isinstance(node, Ps1ContinueStatement) and node.label is None:
            return Continue()
        if isinstance(node, Ps1BreakStatement) and node.label is None:
            return Break()
        raise Unreadable(_SYNTH.convert(node))


def _observable(program: tuple[Statement, ...], removed: Statement, preference: Preference) -> bool:
    smaller = dispatch.without(program, removed)
    return any(
        dispatch.visible(dispatch.run(program, preference, on))
        != dispatch.visible(dispatch.run(smaller, preference, on))
        for on in dispatch.vectors(program)
    )


#: Where the evaluator may say an error ends up besides a statement, a clause or a `trap`.
_ENDS = 'the end of the run'
_CALLER = 'the caller of the body'


def _places_of(fate) -> set:
    """
    Every place *fate* says an error may end up: a statement the run carries on after, a `catch`
    clause or `trap` that takes it, the end of the run, the caller of the body.
    """
    places: set = {*fate.carried, *fate.caught, *fate.trapped}
    if fate.ends_run:
        places.add(_ENDS)
    if fate.to_caller:
        places.add(_CALLER)
    return places


class _Witnessed(NamedTuple):
    """
    What the model showed of one failing point or `throw`: the node it was read from, the kind of
    error it raises, the places the model sent its error to, and whether a handler that acts ran.
    """
    node: Node
    kind: Ps1ErrorKind
    places: set
    acted: bool


def _witnessed(
    read: tuple[Statement, ...],
    preference: Preference,
    vectors: list[frozenset[int]],
    nodes: dict[int, Node],
) -> list[_Witnessed]:
    """
    For every failing point and `throw` of *read*, what the model shows of its error run under each
    of *vectors*, in the evaluator's terms: an error the model carries on after, takes or ends the
    run with outside the body of a function or script block the point stands in is one that body
    hands to its caller. *nodes* maps every statement of *read* to the node it was read from.
    """
    seen: dict[int, list[tuple[Outcome, Statement | Catch | None]]] = {}

    def witness(site: Statement, outcome: Outcome, target: Statement | Catch | None) -> None:
        seen.setdefault(id(site), []).append((outcome, target))

    for on in vectors:
        dispatch.run(read, preference, on, witness)
    clauses: dict[int, Node] = {}
    for statement in dispatch.statements(read):
        node = nodes.get(id(statement))
        if isinstance(statement, Try) and isinstance(node, Ps1TryCatchFinally):
            for clause, written in zip(statement.catches, node.catch_clauses):
                clauses[id(clause)] = written
    bodies = _bodies(read)
    found: list[_Witnessed] = []
    for site in dispatch.statements(read):
        if not isinstance(site, (Fail, Throw, Store)) or (node := nodes.get(id(site))) is None:
            continue
        kind = Ps1ErrorKind.THROWN if isinstance(site, Throw) else Ps1ErrorKind.STATEMENT
        body = bodies.get(id(site))
        places: set = set()
        acted = False
        for outcome, target in seen.get(id(site), ()):
            if outcome is Outcome.LEAVES:
                places.add(_CALLER if body is not None else _ENDS)
                continue
            if body is not None and id(target) not in body:
                places.add(_CALLER)
                continue
            written = clauses.get(id(target)) if outcome is Outcome.CAUGHT else nodes.get(id(target))
            places.add(written)
            acted = acted or isinstance(written, (Ps1TrapStatement, Ps1CatchClause)) and handler_acts(written)
        found.append(_Witnessed(node, kind, places, acted))
    return found


def unlisted(
    read: tuple[Statement, ...],
    preference: Preference,
    vectors: list[frozenset[int]],
    nodes: dict[int, Node],
    analysis: Ps1Dispatch,
) -> bool:
    """
    Whether the model, run on *read* under each of *vectors*, sends an error a failing point or a
    `throw` raised somewhere the evaluator does not list for that point, or runs a handler that acts
    where the evaluator says none does.
    """
    for site in _witnessed(read, preference, vectors, nodes):
        if not site.places:
            continue
        fate = analysis.fate(site.node, site.kind)
        if fate is None or not site.places <= _places_of(fate) or site.acted and not fate.acts:
            return True
    return False


def overlisted(
    read: tuple[Statement, ...],
    preference: Preference,
    vectors: list[frozenset[int]],
    nodes: dict[int, Node],
    analysis: Ps1Dispatch,
) -> int:
    """
    How many places the evaluator lists for the failing points and `throw` statements of *read*
    that the model, run under each of *vectors*, sends no error to: the measure of how much more the
    evaluator claims than a run does, which `unlisted` cannot see.
    """
    count = 0
    for site in _witnessed(read, preference, vectors, nodes):
        fate = analysis.fate(site.node, site.kind)
        if fate is not None:
            count += len(_places_of(fate) - site.places)
    return count


def _own_statements(body: tuple[Statement, ...]) -> list[Statement]:
    """
    The statements of *body* and of every list nested in it, a `trap` body among them, short of the
    bodies of the functions and script blocks it holds.
    """
    found: list[Statement] = []
    stack = list(body)
    while stack:
        statement = stack.pop()
        found.append(statement)
        if isinstance(statement, If):
            stack.extend((*statement.then, *statement.otherwise))
        elif isinstance(statement, (Loop, Sub, Trap)):
            stack.extend(statement.body)
        elif isinstance(statement, Try):
            stack.extend(statement.body)
            for clause in statement.catches:
                stack.extend(clause.body)
            stack.extend(statement.final or ())
    return found


def _bodies(program: tuple[Statement, ...]) -> dict[int, frozenset[int]]:
    """
    For every statement of *program* standing in the body of a function or a script block, the
    identities of every statement and `catch` clause of that innermost body.
    """
    found: dict[int, frozenset[int]] = {}

    def enter(body: tuple[Statement, ...], called: bool) -> None:
        members = _own_statements(body)
        clauses = [clause for statement in members if isinstance(statement, Try) for clause in statement.catches]
        identities = frozenset(id(member) for member in (*members, *clauses))
        for statement in members:
            if called:
                found[id(statement)] = identities
            if isinstance(statement, (Def, Invoke)):
                enter(statement.body, True)

    enter(program, False)
    return found


@dataclass(frozen=True)
class Disagreement:
    """
    One answer of the analysis the model contradicts, for the generated program `number`: deleting
    a failing point or a `trap` the model says changes what the program shows was called
    unobservable, the model sends an error somewhere the evaluator does not list, or the output
    shows something else for some inputs.
    """
    law: str
    number: int


def disagreements(program: tuple[Statement, ...], preference: Preference, number: int) -> list[Disagreement]:
    """
    Every answer of the analysis about generated program `number` the model contradicts.
    """
    source = dispatch.render(program, preference)
    tree = Ps1Parser(source).parse()
    reader = _Reader()
    read = reader.script(tree.body)
    cache = Ps1ModelCache(tree)
    faults = cache.faults
    handlers = cache.handlers
    found: set[Disagreement] = set()
    if unlisted(read, preference, list(dispatch.vectors(read)), reader.nodes, faults.dispatch):
        found.add(Disagreement('fate', number))
    for statement in dispatch.statements(read):
        node = reader.nodes.get(id(statement))
        if not isinstance(statement, (Fail, Trap)) or node is None:
            continue
        if not _observable(read, statement, preference):
            continue
        if isinstance(statement, Fail):
            if not deletion_is_observable(node, faults, cache.world_reach, cache.error_state, handlers.raises(True)):
                found.add(Disagreement('deletion veto', number))
        elif isinstance(node, Ps1TrapStatement):
            if faults.removable_traps([node], handlers.raises(True), handlers.skips):
                found.add(Disagreement('trap removal', number))
    output = Ps1Parser(source).parse()
    deobfuscate(output, trust_eval=False)
    try:
        rewritten = _Reader().script(output.body, rewritten=True)
    except Unreadable:
        found.add(Disagreement('output unreadable', number))
        return sorted(found, key=str)
    if any(
        dispatch.visible(dispatch.run(read, preference, on))
        != dispatch.visible(dispatch.run(rewritten, preference, on))
        for on in dispatch.vectors(read)
    ):
        found.add(Disagreement('output', number))
    return sorted(found, key=str)


#: How many generated programs the analysis is held to, and the seed that names them. Over these
#: 400 the analysis the error roadmap started from disagrees with the model 37 times, and a reader
#: that forgets either landing of plan (1) 8 and 23 times.
PROGRAMS = 400
SEED = 7


@functools.cache
def _all_disagreements() -> tuple[Disagreement, ...]:
    found: list[Disagreement] = []
    for number, (program, preference) in enumerate(Generator(SEED).programs(PROGRAMS)):
        found.extend(disagreements(program, preference, number))
    return tuple(found)


#: The disagreements the analysis has today over the generated programs, each with the defect it
#: is an instance of. A program is rendered with `test.lib.scripts.ps1.dispatch.render` from its
#: place in `Generator(SEED).programs(PROGRAMS)`.
DISPATCH_DEFECTS: dict[Disagreement, str] = {}

#: How many programs of `test.lib.scripts.ps1.dispatch.BodyGenerator` the analysis is held to, and
#: the seed that names them: functions and script blocks, stores read back, jumps through a
#: `finally` and preference writes. Each of the three fixes these programs were drawn to reach is
#: undone by a planted breakage some of them notice.
BODY_PROGRAMS = 400
BODY_SEED = 7


@functools.cache
def _all_body_disagreements() -> tuple[Disagreement, ...]:
    found: list[Disagreement] = []
    for number, (program, preference) in enumerate(BodyGenerator(BODY_SEED).programs(BODY_PROGRAMS)):
        found.extend(disagreements(program, preference, number))
    return tuple(found)


#: The disagreements the analysis has today over the body programs, each with the defect it is an
#: instance of, rendered from its place in `BodyGenerator(BODY_SEED).programs(BODY_PROGRAMS)`.
BODY_DEFECTS: dict[Disagreement, str] = {}


class TestPs1TheDispatchModelWritesWhat51Writes(TestBase):
    """
    The model is held to what 5.1 wrote for every anchor, reported errors included.
    """

    def test_every_anchor_runs_as_51_ran_it(self):
        for name, (program, preference, on) in dispatch.ANCHORS.items():
            if name not in DISPATCH_TRANSCRIPTS:
                continue
            with self.subTest(name):
                self.assertEqual(shown(dispatch.run(program, preference, on)), DISPATCH_TRANSCRIPTS[name])

    def test_every_anchor_was_measured(self):
        self.assertEqual(sorted(set(dispatch.ANCHORS) - set(DISPATCH_TRANSCRIPTS)), [])

    def test_every_measurement_is_an_anchor(self):
        self.assertEqual(sorted(set(DISPATCH_TRANSCRIPTS) - set(dispatch.ANCHORS)), [])

    def test_the_corpus_runs_the_anchors_as_the_model_renders_them(self):
        self.assertEqual(corpus.DISPATCH, tuple(
            dispatch.render(program, preference, on) for program, preference, on in dispatch.ANCHORS.values()))

    def test_every_generated_program_reads_back_as_it_was_generated(self):
        for number, (program, preference) in enumerate(Generator(SEED).programs(PROGRAMS)):
            source = dispatch.render(program, preference)
            with self.subTest(number=number):
                self.assertEqual(
                    dispatch.render(_Reader().script(Ps1Parser(source).parse().body), preference), source)


#: How many places the evaluator lists, over every anchor, that the model sends no error to there.
#: The evaluator reads every filter as one that may or may not match and every value of the flag a
#: call site of a body may set, so it lists more than any one run reaches; a change that lists more
#: still has `unlisted` pass, and this is what it moves.
OVERLISTED_OVER_THE_ANCHORS = 216


class TestPs1TheEvaluatorListsWhereEveryAnchorSendsAnError(TestBase):
    """
    For every anchor 5.1 was measured on, each place the model sends the error of a failing point
    or a `throw` is among the places `refinery.lib.scripts.ps1.analysis.dispatch` lists for it, and
    the places it lists besides are as many as they were.
    """

    def test_the_evaluator_lists_as_many_places_no_anchor_reaches_as_it_did(self):
        count = 0
        for program, preference, on in dispatch.ANCHORS.values():
            tree = Ps1Parser(dispatch.render(program, preference)).parse()
            reader = _Reader()
            read = reader.script(tree.body)
            count += overlisted(read, preference, [on], reader.nodes, Ps1ModelCache(tree).faults.dispatch)
        self.assertEqual(count, OVERLISTED_OVER_THE_ANCHORS)

    def test_every_place_an_anchor_sends_an_error_is_listed(self):
        for name, (program, preference, on) in dispatch.ANCHORS.items():
            with self.subTest(name):
                tree = Ps1Parser(dispatch.render(program, preference)).parse()
                reader = _Reader()
                read = reader.script(tree.body)
                analysis = Ps1ModelCache(tree).faults.dispatch
                self.assertFalse(unlisted(read, preference, [on], reader.nodes, analysis))


class TestPs1TheAnalysisAgreesWithTheDispatchModel(TestBase):
    """
    Over generated programs, the deletion veto and the `trap` removal answer never call a deletion
    unobservable that the model says changes what the program shows, the evaluator lists every place
    the model sends an error, and the deobfuscated output shows what the program shows for every
    input.
    """

    def test_every_disagreement_is_a_recorded_defect(self):
        self.assertEqual(sorted(_all_disagreements(), key=str), sorted(DISPATCH_DEFECTS, key=str))

    def test_every_disagreement_over_the_body_programs_is_a_recorded_defect(self):
        self.assertEqual(sorted(_all_body_disagreements(), key=str), sorted(BODY_DEFECTS, key=str))

    def test_every_body_program_reads_back_as_it_was_generated(self):
        for number, (program, preference) in enumerate(BodyGenerator(BODY_SEED).programs(BODY_PROGRAMS)):
            source = dispatch.render(program, preference)
            with self.subTest(number=number):
                self.assertEqual(
                    dispatch.render(_Reader().script(Ps1Parser(source).parse().body), preference), source)


class TestPs1TheTailOfALineEndsWhereItsListHandsControlOn(TestBase):

    @staticmethod
    def _tail(source: str) -> tuple[Ps1IfStatement, frozenset[Node]]:
        tree = Ps1Parser(source).parse()
        statement, = (node for node in tree.walk() if isinstance(node, Ps1IfStatement))
        line, = (
            node for node in tree.walk()
            if isinstance(node, Ps1ExpressionStatement) and isinstance(node.expression, Ps1AssignmentExpression)
        )
        return statement, Ps1ModelCache(tree).faults.dispatch.tail_of(line)

    def test_the_last_line_of_an_if_body_goes_on_after_the_if(self):
        statement, tail = self._tail("if ($c) { $null = [int]$s }; Write-Host 'after'")
        self.assertIn(statement, tail)

    def test_the_last_line_of_a_subexpression_tested_by_an_if_goes_on_to_the_test(self):
        statement, tail = self._tail("if ($( 1; $null = [int]$s )) { Write-Host 'then' }; Write-Host 'after'")
        self.assertNotIn(statement, tail)


#: Body programs of `test.lib.scripts.ps1.dispatch.BodyGenerator`, by seed and number, the analysis
#: once contradicted the model on: one per seed and law of the census the error roadmap was measured
#: against, and the five whose defects were named: a `trap` deletion and a `catch` lift landing in
#: one batch (11, 33), a store read by a called function (11, 1980), a store before a `break` (11,
#: 1606; 24, 1917), and a typed `trap` declining a `throw` under `SilentlyContinue` (12, 1110).
ONCE_CONTRADICTED: dict[int, tuple[int, ...]] = {
    1: (380, 618),
    2: (60, 244, 1380),
    3: (601, 857, 1958),
    8: (80, 1468),
    9: (131, 477),
    10: (69, 419, 1163),
    11: (32, 33, 64, 1606, 1980),
    12: (223, 285, 1110),
    13: (143, 585),
    14: (1104, 1319, 1547),
    15: (363, 456, 1339),
    16: (269, 912),
    17: (198, 203, 1416),
    18: (78, 1156),
    19: (158, 242),
    20: (44, 381),
    21: (141, 408, 473),
    22: (200, 495),
    23: (410, 950),
    24: (110, 455, 1917),
    25: (84, 346),
    26: (149, 1631),
    27: (531, 725, 1052),
}


class TestPs1TheBodyProgramsOnceContradictedAgreeWithTheModel(TestBase):

    def test_every_body_program_once_contradicted_agrees_with_the_model(self):
        for seed, numbers in ONCE_CONTRADICTED.items():
            programs = list(BodyGenerator(seed).programs(max(numbers) + 1))
            for number in numbers:
                program, preference = programs[number]
                with self.subTest(seed=seed, number=number):
                    self.assertEqual(disagreements(program, preference, number), [])


def _reached_by_raising(graph: ControlFlowGraph, point: CfgNode) -> set[int]:
    seen: set[int] = set()
    pending = [successor for successor in point.successors if graph.raise_taken(point, successor)]
    while pending:
        node = pending.pop()
        if id(node) not in seen:
            seen.add(id(node))
            pending.extend(node.successors)
    return seen


def _carrying_on_after(graph: ControlFlowGraph, model: Ps1ControlFlowModel, statement: Node) -> set[int]:
    """
    The nodes standing where a run carries on after *statement*: its completion and what follows
    it, the report node carrying on after it, and the place a `trap` set resumes after it.
    """
    places: set[int] = set()
    for node in graph.completion_of(statement) or ():
        places.add(id(node))
        places.update(id(successor) for successor in node.successors)
    places.update(
        id(node) for node in graph.nodes
        if isinstance(node, Ps1ReportNode) and node.carries_on_after is statement
    )
    for trap_set in model.trap_sets_in(graph):
        slot = trap_set.slots.get(id(statement))
        if slot is not None:
            places.add(id(slot))
        for node in trap_set.completions.get(id(statement), ()):
            places.add(id(node))
            places.update(id(successor) for successor in node.successors)
    return places


def unreached(source: str) -> list[str]:
    """
    Every place the evaluator sends the error of a point of *source* to, under one value of the
    error preference, that the graphs do not reach from the point along a path starting with an
    edge taken only when the point raised: a `catch` clause, a `trap`, or a statement the run
    carries on after. Where the run carries on after the statement the point stands in, the point
    falling through to the next one is that path.
    """
    tree = Ps1Parser(source).parse()
    cache = Ps1ModelCache(tree)
    faults = cache.faults
    model = faults.control_flow
    raises = cache.raises_alone
    found: list[str] = []
    for graph in model.graphs.values():
        for point in graph.nodes:
            element = point.element
            if element is None or isinstance(element, (Ps1CatchClause, Ps1TrapStatement, Block)):
                continue
            kinds = raises.kinds(element)
            if not kinds:
                continue
            reached = _reached_by_raising(graph, point)
            statement = member_of(element)
            falls_through = any(graph.completes_into(point, successor) for successor in point.successors)
            for reading in faults.dispatch.readings():
                fate = reading.fate(element, kinds)
                if fate is None:
                    continue
                for handler in (*fate.caught, *fate.trapped):
                    entry = graph.node_of(handler)
                    if entry is not None and id(entry) not in reached:
                        found.append(F'{_SYNTH.convert(element)} -> {_SYNTH.convert(handler)}')
                for carried in fate.carried:
                    if carried is statement and falls_through:
                        continue
                    if not _carrying_on_after(graph, model, carried) & reached:
                        found.append(F'{_SYNTH.convert(element)} -> after {_SYNTH.convert(carried)}')
    return found


class TestPs1TheGraphsReachWhereTheEvaluatorSendsAnError(TestBase):
    """
    The graphs draw where an error goes from the evaluator, so over generated programs each place
    the evaluator sends the error of a point to is reached from that point in the graphs.
    """

    def test_every_place_the_evaluator_names_is_reached_over_the_generated_programs(self):
        for number, (program, preference) in enumerate(Generator(SEED).programs(PROGRAMS)):
            with self.subTest(number=number):
                self.assertEqual(unreached(dispatch.render(program, preference)), [])

    def test_every_place_the_evaluator_names_is_reached_over_the_body_programs(self):
        for number, (program, preference) in enumerate(BodyGenerator(BODY_SEED).programs(BODY_PROGRAMS)):
            with self.subTest(number=number):
                self.assertEqual(unreached(dispatch.render(program, preference)), [])
