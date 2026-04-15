from refinery.lib.nsis.decompiler import (
    NSDecompiler,
    NSScriptWriter,
    _decode_flag_value,
    _is_bare_identifier,
    _is_numeric,
    build_labels,
    nsis_escape,
    format_section_begin,
    format_section_end,
    CMD_REF_Goto,
    decode_messagebox,
    decode_button_id,
    decode_showwindow,
    decode_reg_root,
    decode_exec_flags,
    decode_sect_op,
    decode_file_attributes,
    decode_setoverwrite,
    decode_shortcut_hotkey,
)
from .. import TestBase


class TestNSISConstantDecoders(TestBase):

    def test_decode_messagebox_ok(self):
        self.assertEqual(decode_messagebox(0), 'MB_OK')

    def test_decode_messagebox_yesno_iconquestion(self):
        self.assertEqual(decode_messagebox(0x24), 'MB_YESNO|MB_ICONQUESTION')

    def test_decode_messagebox_okcancel_iconexclamation_defbutton2_topmost(self):
        self.assertEqual(
            decode_messagebox(0x40131),
            'MB_OKCANCEL|MB_ICONEXCLAMATION|MB_DEFBUTTON2|MB_TOPMOST',
        )

    def test_decode_messagebox_retrycancel(self):
        self.assertEqual(decode_messagebox(5), 'MB_RETRYCANCEL')

    def test_decode_messagebox_usericon(self):
        self.assertEqual(decode_messagebox(0x80), 'MB_OK|MB_USERICON')

    def test_decode_messagebox_systemmodal(self):
        self.assertEqual(decode_messagebox(0x1000), 'MB_OK|MB_SYSTEMMODAL')

    def test_decode_messagebox_taskmodal(self):
        self.assertEqual(decode_messagebox(0x2000), 'MB_OK|MB_TASKMODAL')

    def test_decode_button_id_known(self):
        self.assertEqual(decode_button_id(0), '0')
        self.assertEqual(decode_button_id(1), 'IDOK')
        self.assertEqual(decode_button_id(2), 'IDCANCEL')
        self.assertEqual(decode_button_id(6), 'IDYES')
        self.assertEqual(decode_button_id(11), 'IDCONTINUE')

    def test_decode_button_id_unknown(self):
        self.assertEqual(decode_button_id(99), 'Button_99')

    def test_decode_showwindow_hide(self):
        self.assertEqual(decode_showwindow(0), 'SW_HIDE')

    def test_decode_showwindow_shownormal(self):
        self.assertEqual(decode_showwindow(1), 'SW_SHOWNORMAL')

    def test_decode_showwindow_forceminimize(self):
        self.assertEqual(decode_showwindow(11), 'SW_FORCEMINIMIZE')

    def test_decode_showwindow_unknown(self):
        self.assertEqual(decode_showwindow(99), '99')

    def test_decode_reg_root_shctx(self):
        self.assertEqual(decode_reg_root(0), 'SHCTX')

    def test_decode_reg_root_hklm(self):
        self.assertEqual(decode_reg_root(0x80000002), 'HKLM')

    def test_decode_reg_root_hkcu(self):
        self.assertEqual(decode_reg_root(0x80000001), 'HKCU')

    def test_decode_reg_root_unknown(self):
        self.assertEqual(decode_reg_root(0xDEADBEEF), '0xDEADBEEF')

    def test_decode_exec_flags_autoclose(self):
        self.assertEqual(decode_exec_flags(0), 'AutoClose')

    def test_decode_exec_flags_errors(self):
        self.assertEqual(decode_exec_flags(2), 'Errors')

    def test_decode_exec_flags_detailsprint(self):
        self.assertEqual(decode_exec_flags(13), 'DetailsPrint')

    def test_decode_exec_flags_unknown(self):
        self.assertEqual(decode_exec_flags(99), '_99')

    def test_decode_sect_op_text(self):
        self.assertEqual(decode_sect_op(0), 'Text')

    def test_decode_sect_op_size(self):
        self.assertEqual(decode_sect_op(5), 'Size')

    def test_decode_sect_op_unknown(self):
        self.assertEqual(decode_sect_op(99), '_99')

    def test_decode_file_attributes_single(self):
        self.assertEqual(decode_file_attributes(0x01), 'READONLY')

    def test_decode_file_attributes_combined(self):
        self.assertEqual(decode_file_attributes(0x23), 'READONLY|HIDDEN|ARCHIVE')

    def test_decode_file_attributes_with_unknown_bit(self):
        result = decode_file_attributes(0x08)
        self.assertEqual(result, '0x8')

    def test_decode_file_attributes_mixed_known_unknown(self):
        result = decode_file_attributes(0x09)
        self.assertEqual(result, 'READONLY|0x8')

    def test_decode_setoverwrite_on(self):
        self.assertEqual(decode_setoverwrite(0), 'on')

    def test_decode_setoverwrite_ifnewer(self):
        self.assertEqual(decode_setoverwrite(3), 'ifnewer')

    def test_decode_setoverwrite_ifdiff(self):
        self.assertEqual(decode_setoverwrite(4), 'ifdiff')

    def test_decode_setoverwrite_unknown(self):
        self.assertEqual(decode_setoverwrite(99), '99')

    def test_decode_shortcut_hotkey_empty(self):
        self.assertEqual(decode_shortcut_hotkey(0), '')

    def test_decode_shortcut_hotkey_ctrl_s(self):
        spec = (2 << 24) | (ord('S') << 16)
        self.assertEqual(decode_shortcut_hotkey(spec), 'CONTROL|S')

    def test_decode_shortcut_hotkey_f1(self):
        spec = 0x70 << 16
        self.assertEqual(decode_shortcut_hotkey(spec), 'F1')

    def test_decode_shortcut_hotkey_shift_alt_f12(self):
        spec = (5 << 24) | (0x7B << 16)
        self.assertEqual(decode_shortcut_hotkey(spec), 'SHIFT|ALT|F12')

    def test_decode_shortcut_hotkey_unknown_key(self):
        spec = 1 << 16
        self.assertEqual(decode_shortcut_hotkey(spec), 'Char_1')


class TestNSScriptWriter(TestBase):

    def test_comment(self):
        w = NSScriptWriter()
        w.comment('hello')
        self.assertEqual(w.getvalue(), '; hello')

    def test_separator_contains_dashes(self):
        w = NSScriptWriter()
        w.separator()
        self.assertIn('----', w.getvalue())

    def test_newline(self):
        w = NSScriptWriter()
        w.write('a')
        w.newline()
        w.write('b')
        self.assertEqual(w.getvalue(), 'a\nb')

    def test_tab_normal(self):
        w = NSScriptWriter()
        w.tab()
        self.assertEqual(w.getvalue(), '  ')

    def test_tab_commented(self):
        w = NSScriptWriter()
        w.tab(commented=True)
        self.assertEqual(w.getvalue(), '    ; ')

    def test_comment_open_close(self):
        w = NSScriptWriter()
        w.comment_open()
        w.write('block')
        w.newline()
        w.write('next')
        w.newline()
        w.comment_close()
        w.write('after')
        output = w.getvalue()
        self.assertEqual(output, '; block\n; next\nafter')

    def test_add_uint(self):
        w = NSScriptWriter()
        w.add_uint(42)
        self.assertEqual(w.getvalue(), '42')

    def test_add_hex(self):
        w = NSScriptWriter()
        w.add_hex(255)
        self.assertEqual(w.getvalue(), '0x000000FF')

    def test_add_color_bgr_to_rgb(self):
        w = NSScriptWriter()
        w.add_color(0x00FF00)
        self.assertEqual(w.getvalue(), '0x00FF00')

    def test_add_color_swap(self):
        w = NSScriptWriter()
        w.add_color(0xFF0000)
        self.assertEqual(w.getvalue(), '0x0000FF')

    def test_add_quoted(self):
        w = NSScriptWriter()
        w.add_quoted('hello world')
        self.assertEqual(w.getvalue(), '"hello world"')

    def test_add_quoted_bare_identifier(self):
        w = NSScriptWriter()
        w.add_quoted('$INSTDIR')
        self.assertEqual(w.getvalue(), '$INSTDIR')

    def test_add_quoted_dollar_identifier(self):
        w = NSScriptWriter()
        w.add_quoted('$R0')
        self.assertEqual(w.getvalue(), '$R0')

    def test_add_quoted_non_variable(self):
        w = NSScriptWriter()
        w.add_quoted('hello')
        self.assertEqual(w.getvalue(), '"hello"')

    def test_add_quoted_single_letter(self):
        w = NSScriptWriter()
        w.add_quoted('A')
        self.assertEqual(w.getvalue(), '"A"')

    def test_add_quoted_number(self):
        w = NSScriptWriter()
        w.add_quoted('42')
        self.assertEqual(w.getvalue(), '42')

    def test_add_quoted_hex(self):
        w = NSScriptWriter()
        w.add_quoted('0xFF')
        self.assertEqual(w.getvalue(), '0xFF')

    def test_space_quoted(self):
        w = NSScriptWriter()
        w.space_quoted('hello world')
        self.assertEqual(w.getvalue(), ' "hello world"')

    def test_space_quoted_bare(self):
        w = NSScriptWriter()
        w.space_quoted('$OUTDIR')
        self.assertEqual(w.getvalue(), ' $OUTDIR')

    def test_is_bare_identifier(self):
        self.assertTrue(_is_bare_identifier('$INSTDIR'))
        self.assertTrue(_is_bare_identifier('$R0'))
        self.assertTrue(_is_bare_identifier('$_var'))
        self.assertTrue(_is_bare_identifier('$var38'))
        self.assertFalse(_is_bare_identifier(''))
        self.assertFalse(_is_bare_identifier('$'))
        self.assertFalse(_is_bare_identifier('hello'))
        self.assertFalse(_is_bare_identifier('A'))
        self.assertFalse(_is_bare_identifier('_private'))
        self.assertFalse(_is_bare_identifier('$INSTDIR\\file'))
        self.assertFalse(_is_bare_identifier('$\\r$\\n'))
        self.assertFalse(_is_bare_identifier('中文'))

    def test_is_numeric(self):
        self.assertTrue(_is_numeric('0'))
        self.assertTrue(_is_numeric('123'))
        self.assertTrue(_is_numeric('-1'))
        self.assertTrue(_is_numeric('+42'))
        self.assertTrue(_is_numeric('0xFF'))
        self.assertTrue(_is_numeric('0X1A'))
        self.assertTrue(_is_numeric('0x80000000'))
        self.assertFalse(_is_numeric(''))
        self.assertFalse(_is_numeric('+'))
        self.assertFalse(_is_numeric('-'))
        self.assertFalse(_is_numeric('abc'))
        self.assertFalse(_is_numeric('12a'))
        self.assertFalse(_is_numeric('0x'))

    def test_decode_flag_value(self):
        self.assertEqual(_decode_flag_value(0, '0'), 'false')
        self.assertEqual(_decode_flag_value(0, '1'), 'true')
        self.assertEqual(_decode_flag_value(1, '0'), 'current')
        self.assertEqual(_decode_flag_value(1, '1'), 'all')
        self.assertEqual(_decode_flag_value(4, '0'), 'false')
        self.assertEqual(_decode_flag_value(4, '1'), 'true')
        self.assertEqual(_decode_flag_value(8, '0'), 'normal')
        self.assertEqual(_decode_flag_value(8, '1'), 'silent')
        self.assertEqual(_decode_flag_value(12, '0'), '32')
        self.assertEqual(_decode_flag_value(12, '256'), '64')
        self.assertEqual(_decode_flag_value(13, '0'), 'both')
        self.assertEqual(_decode_flag_value(13, '2'), 'textonly')
        self.assertEqual(_decode_flag_value(13, '4'), 'listonly')
        self.assertEqual(_decode_flag_value(13, '6'), 'none')
        self.assertIsNone(_decode_flag_value(2, '0'))
        self.assertIsNone(_decode_flag_value(0, 'abc'))
        self.assertIsNone(_decode_flag_value(12, '128'))

    def test_add_string_lf(self):
        w = NSScriptWriter()
        w.add_string_lf('Section')
        self.assertEqual(w.getvalue(), 'Section\n')

    def test_tab_string(self):
        w = NSScriptWriter()
        w.tab_string('File')
        self.assertEqual(w.getvalue(), '  File')

    def test_add_quotes(self):
        w = NSScriptWriter()
        w.add_quotes()
        self.assertEqual(w.getvalue(), '""')


class TestNSISEscape(TestBase):

    def test_escape_tab(self):
        self.assertEqual(nsis_escape('hello\tworld'), 'hello$\\tworld')

    def test_escape_newline(self):
        self.assertEqual(nsis_escape('line1\nline2'), 'line1$\\nline2')

    def test_escape_carriage_return(self):
        self.assertEqual(nsis_escape('a\rb'), 'a$\\rb')

    def test_escape_dollar(self):
        self.assertEqual(nsis_escape('costs $5'), 'costs $5')

    def test_escape_quote(self):
        self.assertEqual(nsis_escape('say "hi"'), 'say $\\"hi$\\"')

    def test_no_escape_needed(self):
        self.assertEqual(nsis_escape('hello'), 'hello')

    def test_escape_mixed(self):
        self.assertEqual(nsis_escape('$\t"'), '$$\\t$\\"')


class TestNSISControlFlowGraph(TestBase):

    SAMPLE_1 = '4caa12766e4e16f5d275d2aaadc01484f1875b80819234e5bf49506dedcc5330'
    SAMPLE_2 = 'e58d7a6fe9d80d757458a5ebc7c8bddd345b355c2bce06fd86d083b5d0ee8384'

    def _parse_nsis(self, sha256):
        from refinery.lib.nsis.archive import NSArchive
        from refinery.units.formats.archive.xtnsis import xtnsis
        data = self.download_sample(sha256)
        offset = xtnsis._find_archive_offset(bytearray(data))
        self.assertIsNotNone(offset)
        return NSArchive.Parse(memoryview(data)[offset:])

    def _function_ranges(self, arc):
        from refinery.lib.nsis.archive import Op
        from refinery.lib.nsis.decompiler import is_func, is_probably_end_of_func
        header = arc.header
        info = build_labels(header, header.sections)
        labels = info.labels
        ranges = []
        k = 0
        while k < len(header.instructions):
            if not is_func(labels[k]):
                k += 1
                continue
            func_start = k
            k += 1
            while k < len(header.instructions):
                insn = header.instructions[k]
                if header.opcode(insn) is Op.Ret:
                    if k + 1 >= len(header.instructions) or is_probably_end_of_func(labels[k + 1]):
                        k += 1
                        break
                k += 1
            ranges.append((func_start, k))
        return ranges

    def test_every_instruction_in_exactly_one_block(self):
        from refinery.lib.nsis.controlflow import build_cfg
        arc = self._parse_nsis(self.SAMPLE_1)
        header = arc.header
        for sect in header.sections:
            start = sect.start_cmd_index
            end = start + sect.num_commands
            if start >= len(header.instructions) or end > len(header.instructions):
                continue
            cfg = build_cfg(header, start, end)
            covered = set()
            for block in cfg.values():
                for addr in range(block.start, block.end):
                    self.assertNotIn(addr, covered, F'instruction {addr} in multiple blocks')
                    covered.add(addr)
            for addr in range(start, end):
                self.assertIn(addr, covered, F'instruction {addr} not in any block')

    def test_branch_targets_are_block_starts(self):
        from refinery.lib.nsis.controlflow import build_cfg
        arc = self._parse_nsis(self.SAMPLE_1)
        header = arc.header
        for sect in header.sections:
            start = sect.start_cmd_index
            end = start + sect.num_commands
            if start >= len(header.instructions) or end > len(header.instructions):
                continue
            cfg = build_cfg(header, start, end)
            for block in cfg.values():
                for succ in block.successors:
                    self.assertIn(
                        succ, cfg,
                        F'successor {succ} of block {block.start} is not a block start',
                    )

    def test_edges_are_bidirectional(self):
        from refinery.lib.nsis.controlflow import build_cfg
        arc = self._parse_nsis(self.SAMPLE_1)
        header = arc.header
        for sect in header.sections:
            start = sect.start_cmd_index
            end = start + sect.num_commands
            if start >= len(header.instructions) or end > len(header.instructions):
                continue
            cfg = build_cfg(header, start, end)
            for addr, block in cfg.items():
                for succ in block.successors:
                    self.assertIn(
                        addr, cfg[succ].predecessors,
                        F'block {addr} -> {succ} successor not reflected in predecessors',
                    )
                for pred in block.predecessors:
                    self.assertIn(
                        addr, cfg[pred].successors,
                        F'block {addr} <- {pred} predecessor not reflected in successors',
                    )

    def test_cfg_sample_2_coverage(self):
        from refinery.lib.nsis.controlflow import build_cfg
        arc = self._parse_nsis(self.SAMPLE_2)
        header = arc.header
        for sect in header.sections:
            start = sect.start_cmd_index
            end = start + sect.num_commands
            if start >= len(header.instructions) or end > len(header.instructions):
                continue
            cfg = build_cfg(header, start, end)
            covered = set()
            for block in cfg.values():
                for addr in range(block.start, block.end):
                    covered.add(addr)
            for addr in range(start, end):
                self.assertIn(addr, covered)

    def test_return_blocks_have_no_successors(self):
        from refinery.lib.nsis.controlflow import build_cfg, BranchKind
        arc = self._parse_nsis(self.SAMPLE_1)
        header = arc.header
        for sect in header.sections:
            start = sect.start_cmd_index
            end = start + sect.num_commands
            if start >= len(header.instructions) or end > len(header.instructions):
                continue
            cfg = build_cfg(header, start, end)
            for block in cfg.values():
                if block.kind is BranchKind.RETURN:
                    self.assertEqual(
                        block.successors, [],
                        F'return block at {block.start} has successors: {block.successors}',
                    )

    def test_conditional_blocks_have_multiple_successors(self):
        from refinery.lib.nsis.controlflow import build_cfg, BranchKind
        arc = self._parse_nsis(self.SAMPLE_1)
        header = arc.header
        found_conditional = False
        for start, end in self._function_ranges(arc):
            cfg = build_cfg(header, start, end)
            for block in cfg.values():
                if block.kind is BranchKind.CONDITIONAL:
                    found_conditional = True
                    self.assertGreaterEqual(
                        len(block.successors), 1,
                        F'conditional block at {block.start} has no successors',
                    )
        self.assertTrue(found_conditional, 'no conditional blocks found in sample')

    def test_cfg_nonempty_for_sections(self):
        from refinery.lib.nsis.controlflow import build_cfg
        arc = self._parse_nsis(self.SAMPLE_1)
        header = arc.header
        ranges = self._function_ranges(arc)
        self.assertGreater(len(ranges), 0, 'no functions found')
        for start, end in ranges:
            if end <= start:
                continue
            cfg = build_cfg(header, start, end)
            self.assertGreater(len(cfg), 0)

    def test_linearize_preserves_all_addresses(self):
        from refinery.lib.nsis.controlflow import build_cfg, linearize, walk_addresses
        arc = self._parse_nsis(self.SAMPLE_1)
        header = arc.header
        info = build_labels(header, header.sections)
        for start, end in self._function_ranges(arc):
            cfg = build_cfg(header, start, end)
            root = linearize(header, cfg, info.labels, start, end)
            addresses = walk_addresses(root)
            expected = list(range(start, end))
            self.assertEqual(addresses, expected, F'function [{start}, {end})')

    def test_linearize_preserves_all_addresses_sample_2(self):
        from refinery.lib.nsis.controlflow import build_cfg, linearize, walk_addresses
        arc = self._parse_nsis(self.SAMPLE_2)
        header = arc.header
        info = build_labels(header, header.sections)
        for start, end in self._function_ranges(arc):
            cfg = build_cfg(header, start, end)
            root = linearize(header, cfg, info.labels, start, end)
            addresses = walk_addresses(root)
            expected = list(range(start, end))
            self.assertEqual(addresses, expected, F'function [{start}, {end})')

    def test_linearize_has_return_nodes_for_ret_instructions(self):
        from refinery.lib.nsis.archive import Op
        from refinery.lib.nsis.controlflow import (
            build_cfg, linearize, ReturnNode, BlockNode,
        )
        arc = self._parse_nsis(self.SAMPLE_1)
        header = arc.header
        info = build_labels(header, header.sections)
        found_ret = False
        for start, end in self._function_ranges(arc):
            cfg = build_cfg(header, start, end)
            root = linearize(header, cfg, info.labels, start, end)
            self.assertIsInstance(root, BlockNode)
            for node in root.body:
                if isinstance(node, ReturnNode):
                    found_ret = True
                    insn = header.instructions[node.address]
                    self.assertIs(header.opcode(insn), Op.Ret)
        self.assertTrue(found_ret, 'no ReturnNode found in sample')

    def test_linearize_has_label_nodes_for_goto_targets(self):
        from refinery.lib.nsis.controlflow import (
            build_cfg, linearize, LabelNode,
        )
        arc = self._parse_nsis(self.SAMPLE_1)
        header = arc.header
        info = build_labels(header, header.sections)
        label_addresses: set[int] = set()
        for start, end in self._function_ranges(arc):
            cfg = build_cfg(header, start, end)
            root = linearize(header, cfg, info.labels, start, end)
            for node in root.body:
                if isinstance(node, LabelNode):
                    label_addresses.add(node.address)
        self.assertGreater(len(label_addresses), 0, 'no labels found')
        for addr in label_addresses:
            self.assertTrue(
                info.labels[addr] & CMD_REF_Goto,
                F'LabelNode at {addr} does not have CMD_REF_Goto flag',
            )

    def test_reduce_if_else_preserves_addresses(self):
        from refinery.lib.nsis.archive import Op
        from refinery.lib.nsis.controlflow import (
            build_cfg, linearize, reduce_if_else, walk_addresses,
        )
        arc = self._parse_nsis(self.SAMPLE_1)
        header = arc.header
        info = build_labels(header, header.sections)
        for start, end in self._function_ranges(arc):
            cfg = build_cfg(header, start, end)
            root = linearize(header, cfg, info.labels, start, end)
            flat = walk_addresses(root)
            reduced = reduce_if_else(root, header)
            reduced_addrs = walk_addresses(reduced)
            extra = set(reduced_addrs) - set(flat)
            self.assertEqual(extra, set(), F'extra addresses in [{start}, {end})')
            missing = set(flat) - set(reduced_addrs)
            for addr in missing:
                opcode = header.opcode(header.instructions[addr])
                self.assertIs(
                    opcode, Op.Nop,
                    F'eliminated address {addr} in [{start}, {end}) is {opcode.name}, not Goto',
                )

    def test_reduce_if_else_finds_if_nodes(self):
        from refinery.lib.nsis.controlflow import (
            build_cfg, linearize, reduce_if_else, IfNode, BlockNode,
        )
        arc = self._parse_nsis(self.SAMPLE_1)
        header = arc.header
        info = build_labels(header, header.sections)

        def count_ifs(node):
            c = 0
            if isinstance(node, IfNode):
                c = 1 + count_ifs(node.then_body)
                if node.else_body:
                    c += count_ifs(node.else_body)
            elif isinstance(node, BlockNode):
                for child in node.body:
                    c += count_ifs(child)
            return c

        total = 0
        for start, end in self._function_ranges(arc):
            cfg = build_cfg(header, start, end)
            root = linearize(header, cfg, info.labels, start, end)
            reduced = reduce_if_else(root, header)
            total += count_ifs(reduced)
        self.assertGreater(total, 50, F'expected many IfNodes, got {total}')

    def test_reduce_if_else_sample_2_preserves_addresses(self):
        from refinery.lib.nsis.archive import Op
        from refinery.lib.nsis.controlflow import (
            build_cfg, linearize, reduce_if_else, walk_addresses,
        )
        arc = self._parse_nsis(self.SAMPLE_2)
        header = arc.header
        info = build_labels(header, header.sections)
        for start, end in self._function_ranges(arc):
            cfg = build_cfg(header, start, end)
            root = linearize(header, cfg, info.labels, start, end)
            flat = walk_addresses(root)
            reduced = reduce_if_else(root, header)
            reduced_addrs = walk_addresses(reduced)
            extra = set(reduced_addrs) - set(flat)
            self.assertEqual(extra, set(), F'extra addresses in [{start}, {end})')
            missing = set(flat) - set(reduced_addrs)
            for addr in missing:
                opcode = header.opcode(header.instructions[addr])
                self.assertIs(
                    opcode, Op.Nop,
                    F'eliminated address {addr} in [{start}, {end}) is {opcode.name}, not Goto',
                )

    def test_reduce_loops_preserves_addresses(self):
        from refinery.lib.nsis.archive import Op
        from refinery.lib.nsis.controlflow import (
            build_cfg, linearize, reduce_loops, walk_addresses,
        )
        arc = self._parse_nsis(self.SAMPLE_1)
        header = arc.header
        info = build_labels(header, header.sections)
        for start, end in self._function_ranges(arc):
            body_end = end - 1
            cfg = build_cfg(header, start, body_end)
            root = linearize(header, cfg, info.labels, start, body_end)
            flat = walk_addresses(root)
            reduced = reduce_loops(root, header)
            reduced_addrs = walk_addresses(reduced)
            extra = set(reduced_addrs) - set(flat)
            self.assertEqual(extra, set(), F'extra addresses in [{start}, {end})')
            missing = set(flat) - set(reduced_addrs)
            for addr in missing:
                opcode = header.opcode(header.instructions[addr])
                self.assertIs(
                    opcode, Op.Nop,
                    F'eliminated address {addr} in [{start}, {end}) is {opcode.name}, not Goto',
                )

    def test_reduce_loops_finds_while_nodes(self):
        from refinery.lib.nsis.controlflow import (
            build_cfg, linearize, reduce_loops,
            WhileNode, DoWhileNode, BlockNode,
        )
        arc = self._parse_nsis(self.SAMPLE_1)
        header = arc.header
        info = build_labels(header, header.sections)

        def count_loops(node):
            w = d = 0
            if isinstance(node, WhileNode):
                w = 1
                w2, d2 = count_loops(node.body)
                w += w2
                d += d2
            elif isinstance(node, DoWhileNode):
                d = 1
                w2, d2 = count_loops(node.body)
                w += w2
                d += d2
            elif isinstance(node, BlockNode):
                for child in node.body:
                    w2, d2 = count_loops(child)
                    w += w2
                    d += d2
            return w, d

        total_while = 0
        total_do_while = 0
        for start, end in self._function_ranges(arc):
            body_end = end - 1
            cfg = build_cfg(header, start, body_end)
            root = linearize(header, cfg, info.labels, start, body_end)
            reduced = reduce_loops(root, header)
            w, d = count_loops(reduced)
            total_while += w
            total_do_while += d
        self.assertGreater(total_while, 5, F'expected many WhileNodes, got {total_while}')
        self.assertGreater(total_do_while, 2, F'expected DoWhileNodes, got {total_do_while}')

    def test_reduce_loops_sample_2_preserves_addresses(self):
        from refinery.lib.nsis.archive import Op
        from refinery.lib.nsis.controlflow import (
            build_cfg, linearize, reduce_loops, walk_addresses,
        )
        arc = self._parse_nsis(self.SAMPLE_2)
        header = arc.header
        info = build_labels(header, header.sections)
        for start, end in self._function_ranges(arc):
            body_end = end - 1
            cfg = build_cfg(header, start, body_end)
            root = linearize(header, cfg, info.labels, start, body_end)
            flat = walk_addresses(root)
            reduced = reduce_loops(root, header)
            reduced_addrs = walk_addresses(reduced)
            extra = set(reduced_addrs) - set(flat)
            self.assertEqual(extra, set(), F'extra addresses in [{start}, {end})')
            missing = set(flat) - set(reduced_addrs)
            for addr in missing:
                opcode = header.opcode(header.instructions[addr])
                self.assertIs(
                    opcode, Op.Nop,
                    F'eliminated address {addr} in [{start}, {end}) is {opcode.name}, not Goto',
                )

    def test_reduce_combined_preserves_addresses(self):
        from refinery.lib.nsis.archive import Op
        from refinery.lib.nsis.controlflow import (
            build_cfg, linearize, reduce_loops, reduce_if_else, walk_addresses,
        )
        for sha in (self.SAMPLE_1, self.SAMPLE_2):
            arc = self._parse_nsis(sha)
            header = arc.header
            info = build_labels(header, header.sections)
            for start, end in self._function_ranges(arc):
                body_end = end - 1
                cfg = build_cfg(header, start, body_end)
                root = linearize(header, cfg, info.labels, start, body_end)
                flat = walk_addresses(root)
                reduced = reduce_loops(root, header)
                reduced = reduce_if_else(reduced, header)
                reduced_addrs = walk_addresses(reduced)
                extra = set(reduced_addrs) - set(flat)
                self.assertEqual(extra, set(), F'extra addresses in [{start}, {end})')
                missing = set(flat) - set(reduced_addrs)
                for addr in missing:
                    opcode = header.opcode(header.instructions[addr])
                    self.assertIs(
                        opcode, Op.Nop,
                        F'eliminated addr {addr} in [{start}, {end}) is {opcode.name}, not Goto',
                    )

    def test_eliminate_dead_code_unit(self):
        from refinery.lib.nsis.controlflow import (
            BlockNode, GotoNode, LabelNode, InstructionNode, ReturnNode,
            eliminate_dead_code,
        )
        from refinery.lib.nsis.archive import Op
        body = [
            GotoNode(10, 0x100),
            GotoNode(11, 0x200),
            LabelNode(12),
            InstructionNode(12, Op.AssignVar),
        ]
        result = eliminate_dead_code(BlockNode(body))
        addresses = [(type(n).__name__, getattr(n, 'address', None)) for n in result.body]
        self.assertEqual(addresses, [
            ('GotoNode', 10),
            ('LabelNode', 12),
            ('InstructionNode', 12),
        ])
        body2 = [
            ReturnNode(20),
            InstructionNode(21, Op.AssignVar),
            GotoNode(22, 0x100),
        ]
        result2 = eliminate_dead_code(BlockNode(body2))
        self.assertEqual(len(result2.body), 1)
        self.assertIsInstance(result2.body[0], ReturnNode)


class TestNSISSectionFormat(TestBase):

    def test_section_group_end(self):
        from refinery.lib.nsis.archive import NSSection, NSSectionFlags
        section = NSSection(
            name=0,
            install_types=0,
            flags=NSSectionFlags.SECGRPEND,
            start_cmd_index=0,
            num_commands=0,
            size_kb=0,
        )
        w = NSScriptWriter()
        is_group = format_section_begin(w, section, 0, lambda n: '', True)
        self.assertTrue(is_group)
        self.assertIn('SectionGroupEnd', w.getvalue())

    def test_section_group(self):
        from refinery.lib.nsis.archive import NSSection, NSSectionFlags
        section = NSSection(
            name=1,
            install_types=0,
            flags=NSSectionFlags.SECGRP | NSSectionFlags.EXPAND,
            start_cmd_index=0,
            num_commands=0,
            size_kb=0,
        )
        w = NSScriptWriter()
        is_group = format_section_begin(w, section, 0, lambda n: 'MyGroup', True)
        self.assertTrue(is_group)
        output = w.getvalue()
        self.assertIn('SectionGroup', output)
        self.assertIn('/e', output)
        self.assertIn('MyGroup', output)

    def test_regular_section(self):
        from refinery.lib.nsis.archive import NSSection, NSSectionFlags
        section = NSSection(
            name=1,
            install_types=0,
            flags=NSSectionFlags.SELECTED,
            start_cmd_index=0,
            num_commands=10,
            size_kb=0,
        )
        w = NSScriptWriter()
        is_group = format_section_begin(w, section, 3, lambda n: 'Main', True)
        self.assertFalse(is_group)
        output = w.getvalue()
        self.assertIn('Section', output)
        self.assertNotIn('/o', output)
        self.assertIn('Main', output)
        self.assertIn('Section_3', output)

    def test_unselected_section(self):
        from refinery.lib.nsis.archive import NSSection
        section = NSSection(
            name=1,
            install_types=0,
            flags=0,
            start_cmd_index=0,
            num_commands=5,
            size_kb=0,
        )
        w = NSScriptWriter()
        format_section_begin(w, section, 0, lambda n: 'Optional', True)
        self.assertIn('/o', w.getvalue())

    def test_section_end(self):
        w = NSScriptWriter()
        format_section_end(w)
        self.assertIn('SectionEnd', w.getvalue())


class TestNSISDecompiledOutput(TestBase):

    SAMPLE_1 = '4caa12766e4e16f5d275d2aaadc01484f1875b80819234e5bf49506dedcc5330'
    SAMPLE_2 = 'e58d7a6fe9d80d757458a5ebc7c8bddd345b355c2bce06fd86d083b5d0ee8384'
    SAMPLE_3 = '19ccf1d4389f624fb166c5828c1633ea4234c976e044e5b61e53000f4a098be8'

    def _decompile(self, sha256):
        from refinery.lib.nsis.archive import NSArchive
        from refinery.units.formats.archive.xtnsis import xtnsis
        data = self.download_sample(sha256)
        offset = xtnsis._find_archive_offset(bytearray(data))
        self.assertIsNotNone(offset)
        arc = NSArchive.Parse(memoryview(data)[offset:])
        return NSDecompiler(arc.header, arc).decompile()

    def test_decompiled_output_sample_1(self):
        output = self._decompile(self.SAMPLE_1)
        self.assertIn('; NSIS script (UTF-8) NSIS-3 Unicode', output)
        self.assertIn('SetCompressor /SOLID lzma', output)
        self.assertIn('HEADER SIZE: 51660', output)
        self.assertIn('STRING CHARS: 4701', output)
        self.assertIn('OutFile [NSIS].exe', output)
        self.assertIn('Name "2345\u738B\u724C\u8F93\u5165\u6CD5 v6.6"', output)
        self.assertIn('BrandingText "Nullsoft Install System v25-May-2017.cvs"', output)
        self.assertIn('UninstPage custom func_36 "" /ENABLECANCEL', output)
        self.assertIn('Section "Uninstall" ; Section_0', output)
        self.assertIn('SectionEnd', output)
        self.assertIn('Function .onInit', output)
        self.assertIn('FunctionEnd', output)
        self.assertIn('File "$PLUGINSDIR\\FileInfo.dll"', output)
        self.assertIn('File "$PLUGINSDIR\\RCWidgetPlugin.dll"', output)
        self.assertIn('File "$PLUGINSDIR\\System.dll"', output)
        self.assertIn('CallInstDLL "$PLUGINSDIR\\FileInfo.dll" "CheckInstallerInstance"', output)
        self.assertIn('CreateDirectory "$TEMP\\2345Pinyin"', output)
        self.assertIn('DeleteRegKey HKLM "Software\\2345Pinyin"', output)
        self.assertIn('ExecWait "$\\"$INSTDIR\\2345PinyinUpdate.exe$\\" -statistics -uninstall"', output)
        self.assertIn('; While: $R9 <= 99', output)
        self.assertIn('; If: $R0 == 1', output)
        self.assertIn('; EndIf', output)
        self.assertIn('; EndWhile', output)
        self.assertNotIn('$$PLUGINSDIR', output)
        self.assertNotIn('$$TEMP', output)
        self.assertIn('$PLUGINSDIR', output)

    def test_decompiled_output_sample_2(self):
        output = self._decompile(self.SAMPLE_2)
        self.assertIn('; NSIS script NSIS-3', output)
        self.assertIn('SetCompressor zlib', output)
        self.assertIn('HEADER SIZE: 119521', output)
        self.assertIn('STRING CHARS: 10855', output)
        self.assertIn('OutFile [NSIS].exe', output)
        self.assertIn('SilentInstall silent', output)
        self.assertIn('Name "Name"', output)
        self.assertIn('BrandingText "Nullsoft Install System v3.01"', output)
        self.assertIn('Function func_0', output)
        self.assertIn('FunctionEnd', output)
        self.assertIn('Section ; Section_0', output)
        self.assertIn('SectionEnd', output)
        self.assertIn('SetOutPath $TEMP', output)
        self.assertIn('File "$PLUGINSDIR\\System.dll"', output)
        self.assertIn('File "$PLUGINSDIR\\nsExec.dll"', output)
        self.assertIn('File "$PLUGINSDIR\\VPatch.dll"', output)
        self.assertIn('File "$PLUGINSDIR\\UserMgr.dll"', output)
        self.assertIn('CallInstDLL "$PLUGINSDIR\\System.dll" "Call"', output)
        self.assertIn('Delete "$WINDIR\\ServicePackFiles\\i386\\termsrv.dll"', output)
        self.assertIn('RMDir /r "$APPDATA\\Foundation1"', output)
        self.assertIn('Function .onInit', output)
        self.assertIn('Function .onInstSuccess', output)

    def test_decompiled_output_sample_3(self):
        output = self._decompile(self.SAMPLE_3)
        self.assertIn('; NSIS script NSIS-2', output)
        self.assertIn('SetCompressor /SOLID lzma', output)
        self.assertIn('HEADER SIZE: 19848', output)
        self.assertIn('STRING CHARS: 1850', output)
        self.assertIn('OutFile [NSIS].exe', output)
        self.assertIn('Name "quick_part"', output)
        self.assertIn('InstallDir $SYSDIR', output)
        self.assertIn('Page instfiles', output)
        self.assertIn('Function .onInit', output)
        self.assertIn('FunctionEnd', output)
        self.assertIn('Section ; Section_0', output)
        self.assertIn('SectionEnd', output)
        self.assertIn('File "$PLUGINSDIR\\System.dll"', output)
        self.assertIn('File "$PLUGINSDIR\\SelfDel.dll"', output)
        self.assertIn('ExecWait "$WINDIR\\regedit.exe /s $\\"$TEMP\\UCtmp.reg$\\""', output)
        self.assertIn('CallInstDLL "$PLUGINSDIR\\SelfDel.dll" "Del"', output)
