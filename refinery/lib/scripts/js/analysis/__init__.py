"""
Static-analysis substrate for JavaScript deobfuscation. Transforms query a shared, computed model of
the program here instead of each re-deriving scope, binding, and dataflow facts on their own.

The foundation is `model`, a flow-insensitive lexical model of scopes
and resolved bindings. Later layers (control-flow graphs, effect summaries) attach behind the same
representation-agnostic surface.
"""
from __future__ import annotations

from refinery.lib.scripts.js.analysis.cfg import (
    CfgNode,
    ControlFlowGraph,
    ControlFlowModel,
    build_cfg,
    build_control_flow,
    build_control_flow_model,
)
from refinery.lib.scripts.js.analysis.effects import (
    EffectModel,
    EffectSummary,
    build_effects,
)
from refinery.lib.scripts.js.analysis.liveness import (
    LivenessModel,
    build_liveness,
)
from refinery.lib.scripts.js.analysis.model import (
    Binding,
    BindingKind,
    Role,
    Scope,
    ScopeKind,
    SemanticModel,
    build_semantic_model,
    is_use_position,
    pattern_identifiers,
    reference_role,
)

__all__ = [
    'Binding',
    'BindingKind',
    'CfgNode',
    'ControlFlowGraph',
    'ControlFlowModel',
    'EffectModel',
    'EffectSummary',
    'LivenessModel',
    'Role',
    'Scope',
    'ScopeKind',
    'SemanticModel',
    'build_cfg',
    'build_control_flow',
    'build_effects',
    'build_liveness',
    'build_semantic_model',
    'is_use_position',
    'pattern_identifiers',
    'reference_role',
]
