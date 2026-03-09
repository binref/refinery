from .. import TestBase

from refinery.lib.executable import (
    align,
    Range,
    BoxedOffset,
    Location,
    Arch,
    LT,
    ET,
    BO,
    Section,
    Segment,
    Symbol,
    CompartmentNotFound,
    ParsingFailure,
    Executable,
)


class TestAlign(TestBase):

    def test_align_up_basic(self):
        self.assertEqual(align(4, 5), 8)

    def test_align_up_already_aligned(self):
        self.assertEqual(align(4, 8), 8)

    def test_align_up_zero(self):
        self.assertEqual(align(4, 0), 0)

    def test_align_down_basic(self):
        self.assertEqual(align(4, 5, down=True), 4)

    def test_align_down_already_aligned(self):
        self.assertEqual(align(4, 8, down=True), 8)

    def test_align_down_zero(self):
        self.assertEqual(align(4, 0, down=True), 0)

    def test_alignment_less_than_two_returns_value(self):
        self.assertEqual(align(1, 7), 7)
        self.assertEqual(align(0, 7), 7)
        self.assertEqual(align(-1, 7), 7)

    def test_align_up_large_alignment(self):
        self.assertEqual(align(0x1000, 0x1001), 0x2000)

    def test_align_down_large_alignment(self):
        self.assertEqual(align(0x1000, 0x1001, down=True), 0x1000)

    def test_align_up_power_of_two(self):
        self.assertEqual(align(16, 1), 16)
        self.assertEqual(align(16, 15), 16)
        self.assertEqual(align(16, 16), 16)
        self.assertEqual(align(16, 17), 32)

    def test_align_non_power_of_two(self):
        self.assertEqual(align(3, 1), 3)
        self.assertEqual(align(3, 4), 6)
        self.assertEqual(align(3, 6), 6)


class TestRange(TestBase):

    def test_range_method(self):
        r = Range(2, 5)
        self.assertEqual(list(r.range()), [2, 3, 4])

    def test_slice_method(self):
        r = Range(2, 5)
        s = r.slice()
        self.assertEqual(s.start, 2)
        self.assertEqual(s.stop, 5)

    def test_eq_same(self):
        self.assertEqual(Range(0, 10), Range(0, 10))

    def test_eq_different(self):
        self.assertNotEqual(Range(0, 10), Range(0, 11))

    def test_eq_non_range(self):
        r = Range(0, 10)
        self.assertFalse(r.__eq__(42))
        self.assertFalse(r.__eq__((0, 10)))
        self.assertFalse(r.__eq__('hello'))

    def test_len(self):
        self.assertEqual(len(Range(0, 10)), 10)
        self.assertEqual(len(Range(5, 5)), 0)

    def test_contains_int(self):
        r = Range(5, 10)
        self.assertIn(5, r)
        self.assertIn(9, r)
        self.assertNotIn(10, r)
        self.assertNotIn(4, r)

    def test_contains_non_int_raises(self):
        r = Range(0, 10)
        with self.assertRaises(TypeError):
            'hello' in r

    def test_str(self):
        self.assertEqual(str(Range(0, 256)), '0x0:0x100')

    def test_repr(self):
        self.assertEqual(repr(Range(0, 256)), '<Range:0x0:0x100>')

    def test_sub_no_overlap(self):
        result = Range(0, 5) - Range(10, 20)
        self.assertEqual(result, [Range(0, 5)])

    def test_sub_full_containment(self):
        result = Range(0, 10) - Range(0, 10)
        self.assertEqual(result, [])

    def test_sub_partial_overlap_right(self):
        result = Range(0, 10) - Range(5, 15)
        self.assertEqual(result, [Range(0, 5)])

    def test_sub_partial_overlap_left(self):
        result = Range(5, 15) - Range(0, 10)
        self.assertEqual(result, [Range(10, 15)])

    def test_sub_inner_hole(self):
        result = Range(0, 20) - Range(5, 15)
        self.assertEqual(result, [Range(0, 5), Range(15, 20)])

    def test_sub_no_overlap_before(self):
        result = Range(10, 20) - Range(0, 5)
        self.assertEqual(result, [Range(10, 20)])


class TestBoxedOffset(TestBase):

    def test_str(self):
        box = Range(0x1000, 0x2000)
        bo = BoxedOffset(box, 0x1500)
        self.assertEqual(str(bo), '0x1500 in 0x1000:0x2000')

    def test_repr(self):
        box = Range(0x1000, 0x2000)
        bo = BoxedOffset(box, 0x1500)
        self.assertEqual(repr(bo), '<BoxedOffset:0x1500 in 0x1000:0x2000>')


class TestLocation(TestBase):

    def test_str(self):
        phys = BoxedOffset(Range(0, 0x200), 0x100)
        virt = BoxedOffset(Range(0x10000, 0x10200), 0x10100)
        loc = Location(phys, virt)
        self.assertEqual(str(loc), 'V=0x10100 in 0x10000:0x10200; P=0x100 in 0x0:0x200')

    def test_repr(self):
        phys = BoxedOffset(Range(0, 0x200), 0x100)
        virt = BoxedOffset(Range(0x10000, 0x10200), 0x10100)
        loc = Location(phys, virt)
        self.assertIn('Location:', repr(loc))


class TestArch(TestBase):

    def test_pointer_sizes(self):
        self.assertEqual(Arch.X32.pointer_size, 32)
        self.assertEqual(Arch.X64.pointer_size, 64)
        self.assertEqual(Arch.ARM32.pointer_size, 32)
        self.assertEqual(Arch.ARM64.pointer_size, 64)
        self.assertEqual(Arch.MIPS16.pointer_size, 16)
        self.assertEqual(Arch.MIPS32.pointer_size, 32)
        self.assertEqual(Arch.MIPS64.pointer_size, 64)
        self.assertEqual(Arch.PPC32.pointer_size, 32)
        self.assertEqual(Arch.PPC64.pointer_size, 64)
        self.assertEqual(Arch.SPARC32.pointer_size, 32)
        self.assertEqual(Arch.SPARC64.pointer_size, 64)

    def test_id_values(self):
        self.assertEqual(Arch.X32.id, 'X32')
        self.assertEqual(Arch.X64.id, 'X64')
        self.assertEqual(Arch.ARM32.id, 'ARM32')
        self.assertEqual(Arch.ARM64.id, 'ARM64')
        self.assertEqual(Arch.MIPS16.id, 'MIPS16')


class TestEnums(TestBase):

    def test_lt_values(self):
        self.assertEqual(LT.PHYSICAL.value, 'offset')
        self.assertEqual(LT.VIRTUAL.value, 'address')

    def test_et_values(self):
        self.assertEqual(ET.ELF.value, 'ELF')
        self.assertEqual(ET.MachO.value, 'MachO')
        self.assertEqual(ET.PE.value, 'PE')
        self.assertEqual(ET.BLOB.value, 'BLOB')

    def test_bo_values(self):
        self.assertEqual(BO.BE.value, 'big')
        self.assertEqual(BO.LE.value, 'little')

    def test_lt_is_str(self):
        self.assertIsInstance(LT.PHYSICAL, str)

    def test_et_is_str(self):
        self.assertIsInstance(ET.PE, str)

    def test_bo_is_str(self):
        self.assertIsInstance(BO.LE, str)


class TestSection(TestBase):

    def _make_section(self, name='.text'):
        return Section(name, Range(0x200, 0x400), Range(0x10000, 0x10200), False)

    def test_as_segment(self):
        sec = self._make_section()
        seg = sec.as_segment()
        self.assertIsInstance(seg, Segment)
        self.assertEqual(seg.physical, sec.physical)
        self.assertEqual(seg.virtual, sec.virtual)
        self.assertEqual(seg.name, '.text')
        self.assertIsNone(seg.sections)

    def test_as_segment_populate_sections(self):
        sec = self._make_section()
        seg = sec.as_segment(populate_sections=True)
        self.assertEqual(seg.sections, [sec])

    def test_eq_same(self):
        s1 = self._make_section()
        s2 = self._make_section('.data')
        self.assertEqual(s1, s2)

    def test_eq_different(self):
        s1 = self._make_section()
        s2 = Section('.text', Range(0x200, 0x400), Range(0x20000, 0x20200), False)
        self.assertNotEqual(s1, s2)

    def test_eq_non_section(self):
        s = self._make_section()
        self.assertFalse(s.__eq__(42))
        self.assertFalse(s.__eq__((s.name, s.physical, s.virtual, s.synthetic)))

    def test_str(self):
        sec = self._make_section()
        result = str(sec)
        self.assertIn('.text', result)
        self.assertIn('P=', result)
        self.assertIn('V=', result)

    def test_repr(self):
        sec = self._make_section()
        result = repr(sec)
        self.assertIn('Section:', result)


class TestSegment(TestBase):

    def _make_segment(self, name='.text'):
        return Segment(Range(0x200, 0x400), Range(0x10000, 0x10200), None, name)

    def test_as_section(self):
        seg = self._make_segment()
        sec = seg.as_section()
        self.assertIsInstance(sec, Section)
        self.assertEqual(sec.physical, seg.physical)
        self.assertEqual(sec.virtual, seg.virtual)
        self.assertEqual(sec.name, '.text')
        self.assertFalse(sec.synthetic)

    def test_as_section_nameless_raises(self):
        seg = Segment(Range(0, 10), Range(0, 10), None, None)
        with self.assertRaises(ValueError):
            seg.as_section()

    def test_eq_same(self):
        s1 = self._make_segment()
        s2 = self._make_segment('.data')
        self.assertEqual(s1, s2)

    def test_eq_different(self):
        s1 = self._make_segment()
        s2 = Segment(Range(0x200, 0x400), Range(0x20000, 0x20200), None, '.text')
        self.assertNotEqual(s1, s2)

    def test_eq_non_segment(self):
        s = self._make_segment()
        self.assertFalse(s.__eq__(42))

    def test_str_with_name(self):
        seg = self._make_segment('.text')
        result = str(seg)
        self.assertTrue(result.startswith('.text:'))
        self.assertIn('P=', result)
        self.assertIn('V=', result)

    def test_str_without_name(self):
        seg = Segment(Range(0x200, 0x400), Range(0x10000, 0x10200), None, None)
        result = str(seg)
        self.assertNotIn('None', result)
        self.assertIn('P=', result)

    def test_repr(self):
        seg = self._make_segment()
        result = repr(seg)
        self.assertIn('Segment:', result)


class TestSymbol(TestBase):

    def test_get_name_with_name(self):
        sym = Symbol(0x1000, 'my_func', 10, True, True, False)
        self.assertEqual(sym.get_name(), 'my_func')

    def test_get_name_entry(self):
        sym = Symbol(0x1000, None, None, True, True, False, is_entry=True)
        self.assertEqual(sym.get_name(), 'entry')

    def test_get_name_function_no_name(self):
        sym = Symbol(0x1000, None, None, True, False, False)
        self.assertEqual(sym.get_name(), 'sub_00001000')

    def test_get_name_non_function_no_name(self):
        sym = Symbol(0x1000, None, None, False, False, False)
        self.assertEqual(sym.get_name(), 'sym_00001000')

    def test_is_entry_default(self):
        sym = Symbol(0x1000, 'x', 4, True, True, False)
        self.assertFalse(sym.is_entry)

    def test_is_entry_set(self):
        sym = Symbol(0x1000, 'x', 4, True, True, False, is_entry=True)
        self.assertTrue(sym.is_entry)

    def test_function_flag(self):
        sym = Symbol(0x1000, 'f', 4, True, True, False)
        self.assertTrue(sym.function)

    def test_non_function_flag(self):
        sym = Symbol(0x1000, 'd', 4, False, True, False)
        self.assertFalse(sym.function)


class TestExecutableAscii(TestBase):

    def test_str_input(self):
        result = Executable.ascii('hello')
        self.assertEqual(result, 'hello')

    def test_bytes_input(self):
        result = Executable.ascii(b'hello')
        self.assertEqual(result, 'hello')

    def test_bytes_with_null(self):
        result = Executable.ascii(b'hello\x00world')
        self.assertEqual(result, 'hello')

    def test_bytes_latin1(self):
        result = Executable.ascii(b'\xe4\xf6\xfc')
        self.assertEqual(result, '\xe4\xf6\xfc')

    def test_empty_string(self):
        result = Executable.ascii('')
        self.assertEqual(result, '')

    def test_empty_bytes(self):
        result = Executable.ascii(b'')
        self.assertEqual(result, '')

    def test_bytes_null_at_start(self):
        result = Executable.ascii(b'\x00hello')
        self.assertEqual(result, '')

    def test_bytearray_input(self):
        result = Executable.ascii(bytearray(b'test\x00junk'))
        self.assertEqual(result, 'test')
