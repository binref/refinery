"""
Static-analysis substrate for AutoIt3 deobfuscation. Transforms query a shared, computed model of
the program here instead of each re-deriving scope, binding, and constant-value facts on their own.

`values` owns the value domain and every operator's semantics over it, `builtins` the emulation
table for the pure builtin functions, `scopes` the documented scoping rules that decide which
storage a write targets, `existence` the census of the names a global may take, `aliases` the
per-scope map of variables that provably name one function, and `propagation` the
constant-binding walk with the may-write summaries it rests on. `cache` binds them into the
per-run model cache the pipeline shares across transforms.
"""
from refinery.lib.scripts.au3.analysis.cache import Au3ModelCache, model_cache
from refinery.lib.scripts.au3.analysis.existence import (
    Au3ExistenceModel,
    build_existence_model,
)
from refinery.lib.scripts.au3.analysis.propagation import (
    Au3PropagationModel,
    build_propagation_model,
)
from refinery.lib.scripts.au3.analysis.scopes import Au3ScopeModel, Binding, build_scope_model
from refinery.lib.scripts.au3.analysis.values import Au3Value

__all__ = [
    'Au3ExistenceModel',
    'Au3ModelCache',
    'Au3PropagationModel',
    'Au3ScopeModel',
    'Au3Value',
    'Binding',
    'build_existence_model',
    'build_propagation_model',
    'build_scope_model',
    'model_cache',
]
