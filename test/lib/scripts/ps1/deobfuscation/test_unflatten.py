from __future__ import annotations

import unittest
import unittest.mock

from inspect import cleandoc

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.analysis import cache
from refinery.lib.scripts.ps1.deobfuscation import Ps1ControlFlowDeflattening
from refinery.lib.scripts.ps1.parser import Ps1Parser


class TestPs1ControlFlowDeflattening(TestPs1):

    def test_linear_chain_shuffled(self):
        code = '\n'.join([
            '$s = 0',
            'while ($s -NE -1) {',
            '  switch ($s) {',
            '    3 { Write-Host $script:c; $s = -1 }',
            '    1 { Write-Host $script:a; $s = 2 }',
            '    0 { $s = 1 }',
            '    2 { Write-Host $script:b; $s = 3 }',
            '    default { break }',
            '  }',
            '}',
        ])
        result = self._deobfuscate(code)
        self.assertNotIn('switch', result)
        self.assertNotIn('while', result)
        lines = [ln.strip() for ln in result.strip().splitlines() if ln.strip()]
        a_idx = next(i for i, ln in enumerate(lines) if '$script:a' in ln)
        b_idx = next(i for i, ln in enumerate(lines) if '$script:b' in ln)
        c_idx = next(i for i, ln in enumerate(lines) if '$script:c' in ln)
        self.assertLess(a_idx, b_idx)
        self.assertLess(b_idx, c_idx)

    def test_statements_between_init_and_loop_preserved(self):
        code = cleandoc("""
            $s = 0
            $keep = Get-Stuff
            while ($s -NE -1) {
              switch ($s) {
                0 { $s = 1 }
                1 { Write-Host $keep; $s = -1 }
                default { break }
              }
            }
        """)
        result = self._apply(code, Ps1ControlFlowDeflattening)
        self.assertEqual(result, cleandoc("""
            $keep = Get-Stuff
            Write-Host $keep
        """))

    def test_data_variable_not_dropped_as_internal(self):
        code = cleandoc("""
            $s = 0
            while ($s -NE -1) {
              switch ($s) {
                0 { $key = 42; $s = 1 }
                1 { Write-Host $key; $s = -1 }
                default { break }
              }
            }
        """)
        result = self._apply(code, Ps1ControlFlowDeflattening)
        self.assertEqual(result, cleandoc("""
            $key = 42
            Write-Host $key
        """))

    def test_conditional_branch_with_join(self):
        code = '\n'.join([
            '$s = 0',
            'while ($s -NE -1) {',
            '  switch ($s) {',
            '    0 { if ($env:OS -Eq $script:val) { $s = 1 } else { $s = 2 } }',
            '    1 { $path = $script:win; $s = 3 }',
            '    2 { $path = $script:nix; $s = 3 }',
            '    3 { Write-Host $path; $s = -1 }',
            '    default { break }',
            '  }',
            '}',
        ])
        result = self._deobfuscate(code)
        self.assertNotIn('switch', result)
        self.assertNotIn('while', result)
        self.assertIn('if', result)
        self.assertIn('Write-Host', result)
        self.assertIn('$script:win', result)
        self.assertIn('$script:nix', result)

    def test_conditional_one_exit_arm(self):
        code = '\n'.join([
            '$s = 0',
            'while ($s -NE -1) {',
            '  switch ($s) {',
            '    0 { if ($script:cond) { $s = 1 } else { $s = -1 } }',
            '    1 { Write-Host $script:msg; $s = -1 }',
            '    default { break }',
            '  }',
            '}',
        ])
        result = self._deobfuscate(code)
        self.assertNotIn('switch', result)
        self.assertIn('if', result)
        self.assertIn('$script:msg', result)

    def test_conditional_with_side_effects_in_branches(self):
        code = '\n'.join([
            '$s = 0',
            'while ($s -NE -1) {',
            '  switch ($s) {',
            '    0 {',
            '      if ($script:cond) { $script:a = $script:x; $s = 1 }',
            '      else { $script:b = $script:y; $s = 1 }',
            '    }',
            '    1 { Write-Host $script:result; $s = -1 }',
            '    default { break }',
            '  }',
            '}',
        ])
        result = self._deobfuscate(code)
        self.assertNotIn('switch', result)
        self.assertIn('$script:a = $script:x', result)
        self.assertIn('$script:b = $script:y', result)
        self.assertIn('Write-Host', result)

    def test_loop_with_back_edge(self):
        code = '\n'.join([
            '$s = 0',
            'while ($s -NE -1) {',
            '  switch ($s) {',
            '    0 { $script:i = $script:start; $s = 1 }',
            '    1 { if ($script:i -LT $script:limit) { $s = 2 } else { $s = -1 } }',
            '    2 { Write-Host $script:i; $script:i = $script:i + 1; $s = 1 }',
            '    default { break }',
            '  }',
            '}',
        ])
        result = self._deobfuscate(code)
        self.assertNotIn('switch', result)
        self.assertIn('while', result)
        self.assertIn('$script:i -LT $script:limit', result)

    def test_bailout_nonconstant_state(self):
        code = '\n'.join([
            '$s = 0',
            'while ($s -NE -1) {',
            '  switch ($s) {',
            '    0 { $s = $script:dynamic }',
            '    1 { Write-Host $script:msg; $s = -1 }',
            '    default { break }',
            '  }',
            '}',
        ])
        result = self._deobfuscate(code)
        self.assertIn('switch', result)
        self.assertIn('while', result)

    def test_nested_conditional_chain(self):
        code = '\n'.join([
            '$s = 0',
            'while ($s -NE -1) {',
            '  switch ($s) {',
            '    0 { if ($script:c1) { $s = 1 } else { $s = 2 } }',
            '    1 { $script:r = $script:a; $s = 3 }',
            '    2 { if ($script:c2) { $s = 4 } else { $s = 5 } }',
            '    4 { $script:r = $script:b; $s = 3 }',
            '    5 { $script:r = $script:c; $s = 3 }',
            '    3 { Write-Host $script:r; $s = -1 }',
            '    default { break }',
            '  }',
            '}',
        ])
        result = self._deobfuscate(code)
        self.assertNotIn('switch', result)
        self.assertIn('$script:c1', result)
        self.assertIn('$script:c2', result)
        self.assertIn('Write-Host', result)

    def test_string_state_ids_ne(self):
        code = '\n'.join([
            '$s = "a"',
            'while ($s -NE "done") {',
            '  switch ($s) {',
            '    "a" { Write-Host $script:x; $s = "b" }',
            '    "b" { Write-Host $script:y; $s = "done" }',
            '    default { break }',
            '  }',
            '}',
        ])
        result = self._deobfuscate(code)
        self.assertNotIn('switch', result)
        self.assertNotIn('while', result)
        lines = [ln.strip() for ln in result.strip().splitlines() if ln.strip()]
        x_idx = next(i for i, ln in enumerate(lines) if '$script:x' in ln)
        y_idx = next(i for i, ln in enumerate(lines) if '$script:y' in ln)
        self.assertLess(x_idx, y_idx)

    def test_string_state_ids_like(self):
        code = '\n'.join([
            '$s = "goTo1"',
            'while ($s -like "goTo*") {',
            '  switch -wildcard ($s) {',
            '    "goTo1" { Write-Host $script:a; $s = "goTo2" }',
            '    "goTo2" { Write-Host $script:b; $s = "halt" }',
            '    default { break }',
            '  }',
            '}',
        ])
        result = self._deobfuscate(code)
        self.assertNotIn('switch', result)
        self.assertNotIn('while', result)
        lines = [ln.strip() for ln in result.strip().splitlines() if ln.strip()]
        a_idx = next(i for i, ln in enumerate(lines) if '$script:a' in ln)
        b_idx = next(i for i, ln in enumerate(lines) if '$script:b' in ln)
        self.assertLess(a_idx, b_idx)

    def test_float_state_ids(self):
        code = '\n'.join([
            '$s = 1.5',
            'while ($s -NE 0.0) {',
            '  switch ($s) {',
            '    1.5 { Write-Host $script:first; $s = 2.5 }',
            '    2.5 { Write-Host $script:second; $s = 0.0 }',
            '    default { break }',
            '  }',
            '}',
        ])
        result = self._deobfuscate(code)
        self.assertNotIn('switch', result)
        self.assertNotIn('while', result)
        lines = [ln.strip() for ln in result.strip().splitlines() if ln.strip()]
        f_idx = next(i for i, ln in enumerate(lines) if '$script:first' in ln)
        s_idx = next(i for i, ln in enumerate(lines) if '$script:second' in ln)
        self.assertLess(f_idx, s_idx)

    def test_a_hexadecimal_state_constant_is_the_value_powershell_gives_it(self):
        """
        Measured on 5.1: `0xFFFFFFFF` is the Int32 -1, not the magnitude 4294967295. So state 0 ends
        the machine, and the `4294967295` case is a state the host never enters. Reading the numeral
        as its magnitude routes the machine into that case and emits code that never runs.
        """
        code = cleandoc("""
            $s = 0
            while ($s -ne -1) {
              switch ($s) {
                0 { Write-Host $script:reached; $s = 0xFFFFFFFF }
                4294967295 { Write-Host $script:unreachable; $s = -1 }
                default { break }
              }
            }
        """)
        result = self._apply(code, Ps1ControlFlowDeflattening)
        self.assertEqual(result, 'Write-Host $script:reached')

    def test_a_state_id_too_wide_for_an_integer_is_left_flattened(self):
        """
        A decimal literal past Int64 is a Decimal, not an integer, so the machine reader names no
        value for it rather than reading its magnitude as an int it is not. Recovering the machine
        would key it on a value the host never assigns, so the dispatcher is left in place instead.
        """
        code = cleandoc("""
            $s = 0
            while ($s -ne -1) {
              switch ($s) {
                0 { Write-Host $script:reached; $s = 99999999999999999999 }
                99999999999999999999 { Write-Host $script:x; $s = -1 }
                default { break }
              }
            }
        """)
        self.assertEqual(
            self._apply(code, Ps1ControlFlowDeflattening),
            self._apply(code))

    def test_a_loop_whose_exit_condition_is_unevaluable_is_left_flattened(self):
        """
        Which state ends this loop depends on what `Get-Random` returns, so no state can be shown to
        end it and none can be shown not to. Recovering the machine as `while ($True)` turns that
        refusal into the answer that no state exits, and runs a body forever that the host may not
        run at all.
        """
        self._assertUnchanged(cleandoc("""
            $s = 0
            while ($s -ne (Get-Random)) {
              switch ($s) {
                0 {
                  Write-Host $script:first
                  $s = 1
                }
                1 {
                  Write-Host $script:second
                  $s = 0
                }
                default {
                  break
                }
              }
            }
        """), Ps1ControlFlowDeflattening)

    def test_string_state_ids_match(self):
        code = '\n'.join([
            '$s = "state_1"',
            'while ($s -match "^state_") {',
            '  switch -regex ($s) {',
            '    "state_1" { Write-Host $script:msg; $s = "exit" }',
            '    default { break }',
            '  }',
            '}',
        ])
        result = self._deobfuscate(code)
        self.assertNotIn('switch', result)
        self.assertNotIn('while', result)
        self.assertIn('$script:msg', result)


class TestPs1DeflatteningDoesNotRebuildTheModelPerMachine(TestPs1):
    """
    Every removal plan the pass opens reads the fault model, and that model is layered on the
    control-flow graph of every block in the script. A commit advances the tree version those
    graphs are cached against, so re-reading the model through the cache once per machine would
    rebuild all of them: a body holding several independent machines would pay for the whole script
    once per machine it dissolves. What a walk over a script costs is a property of the script, not
    of how many of its statements turn out to be removable.

    The machines in a body are siblings, and dissolving one leaves the handlers around another where
    they were, so the pass reads the fault model once per body and reuses it for every machine there.
    The count is then a property of the script and does not carry the machine count.

    The build is `refinery.lib.scripts.ps1.analysis.cache.build_control_flow_model`, which is what
    the cache calls, counted here rather than timed so the measurement is the same on every
    machine. It is compared between two machine counts rather than against a number of its own: a
    count that answers the same for two machines as for eight is the only one that does not carry
    the machine count in it.
    """

    _FEW = 2
    _MANY = 8

    _MACHINE = """
        $s{index} = 0
        while ($s{index} -NE -1) {{
          switch ($s{index}) {{
            0 {{ Write-Host 'a{index}'; $s{index} = 1 }}
            1 {{ Write-Host 'b{index}'; $s{index} = -1 }}
            default {{ break }}
          }}
        }}
    """

    @classmethod
    def _machines(cls, count: int) -> str:
        machine = cleandoc(cls._MACHINE)
        return '\n'.join(machine.format(index=index) for index in range(count))

    @staticmethod
    def _dissolved(count: int) -> str:
        lines = []
        for index in range(count):
            lines.append(F"Write-Host 'a{index}'")
            lines.append(F"Write-Host 'b{index}'")
        return '\n'.join(lines)

    def _models_built(self, count: int) -> int:
        built = 0
        build = cache.build_control_flow_model

        def counted(root):
            nonlocal built
            built += 1
            return build(root)

        script = Ps1Parser(self._machines(count)).parse()
        with unittest.mock.patch.object(cache, 'build_control_flow_model', counted):
            Ps1ControlFlowDeflattening().visit(script)
        return built

    def test_every_machine_in_the_body_is_dissolved(self):
        for count in (self._FEW, self._MANY):
            with self.subTest(machines=count):
                self.assertEqual(
                    self._apply(self._machines(count), Ps1ControlFlowDeflattening),
                    self._dissolved(count),
                )

    def test_the_models_built_are_the_same_for_two_machines_and_for_eight(self):
        self.assertEqual(self._models_built(self._MANY), self._models_built(self._FEW))
