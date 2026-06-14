from __future__ import annotations

from inspect import cleandoc

from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts.ps1.deobfuscation import Ps1ControlFlowDeflattening


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
        # `$keep = Get-Stuff` sits between the state init and the dispatcher loop and must survive
        # deflattening.
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
        # `$key = 42` is read by emitted code, so it is real data, not a dispatch artifact, and
        # must not be suppressed.
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
