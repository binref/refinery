import inspect
import random

from refinery.lib import tools, colors


from .. import TestBase


class TestEntropy(TestBase):

    def test_low_entropy(self):
        data = B'2' * 2000
        self.assertLessEqual(tools.entropy_fallback(data), 0.001)

    def test_high_entropy_01(self):
        data = bytes((random.randrange(0, 0x100) for _ in range(2000)))
        self.assertGreaterEqual(tools.entropy_fallback(data), 0.98)

    def test_high_entropy_02(self):
        data = bytes((random.randrange(0, 0x100) for _ in range(2000)))
        self.assertGreaterEqual(tools.entropy(data), 0.98)

    def test_fallback_memoryview(self):
        for data in [
            B'FOO-BAR-BAR' * 200,
            self.generate_random_buffer(1000)
        ]:
            view = memoryview(data)
            self.assertAlmostEqual(tools.entropy(view), tools.entropy_fallback(view))


class TestTools(TestBase):

    def test_coloring(self):
        @inspect.getdoc
        class code:
            """
            async function test() {
                try {
                    const saqotesana = Uint8Array.from(atob(zobefacebi.duvusuvusa), c => c.charCodeAt(0));
                    const iv = Uint8Array.from(atob(zobefacebi.iv), c => c.charCodeAt(0));
                    const keyData = Uint8Array.from(atob(zobefacebi.key), c => c.charCodeAt(0));
                } catch (error) { }
            }
            """
        assert code is not None

        highlighted = code | self.ldu('hlg') | str
        for line1, line2 in zip(
            code.splitlines(), highlighted.splitlines()
        ):
            self.assertEqual(len(line1), colors.colored_text_length(line2))

    def test_terminalfit(self):
        @inspect.getdoc
        class data:
            """
            Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed venenatis ac urna id ultricies. Integer eu semper mauris. Nunc sed
            nunc non ante volutpat egestas. Nam nec risus sed ex dignissim pharetra. Integer vel augue erat. Vivamus hendrerit convallis
            tortor in varius. Morbi sed nulla eget turpis volutpat maximus id vitae nisi:

            1. Aenean ullamcorper egestas lorem ornare ultrices.
            2. Donec quis gravida orci.
            3. Fusce auctor, orci sit amet vehicula varius, elit dolor feugiat nisl, at congue sapien sapien ut felis. Etiam pharetra est
               non turpis facilisis ullamcorper.

            Ut quis ipsum varius, pellentesque mauris nec, rutrum quam. Proin dictum neque ut sem hendrerit, nec lobortis sem scelerisque.
            Nullam eget justo in nunc lacinia porttitor eget nec quam. Morbi volutpat egestas risus, eget malesuada nulla vulputate eu. Cras
            leo ipsum, porttitor et malesuada a, laoreet nec metus:

            - Donec porttitor suscipit dapibus.
            - Phasellus sodales erat id imperdiet rutrum.
            - Vestibulum in augue vel libero tempor vestibulum.
            """

        @inspect.getdoc
        class wish:
            """
            Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed venenatis ac urna id
            ultricies. Integer eu semper mauris. Nunc sed nunc non ante volutpat egestas. Nam nec
            risus sed ex dignissim pharetra. Integer vel augue erat. Vivamus hendrerit convallis
            tortor in varius. Morbi sed nulla eget turpis volutpat maximus id vitae nisi:

            1. Aenean ullamcorper egestas lorem ornare ultrices.
            2. Donec quis gravida orci.
            3. Fusce auctor, orci sit amet vehicula varius, elit dolor feugiat nisl, at congue
               sapien sapien ut felis. Etiam pharetra est non turpis facilisis ullamcorper.

            Ut quis ipsum varius, pellentesque mauris nec, rutrum quam. Proin dictum neque ut sem
            hendrerit, nec lobortis sem scelerisque. Nullam eget justo in nunc lacinia porttitor eget
            nec quam. Morbi volutpat egestas risus, eget malesuada nulla vulputate eu. Cras leo ipsum,
            porttitor et malesuada a, laoreet nec metus:

            - Donec porttitor suscipit dapibus.
            - Phasellus sodales erat id imperdiet rutrum.
            - Vestibulum in augue vel libero tempor vestibulum.
            """

        self.assertEqual(tools.terminalfit(data, width=90), wish)
