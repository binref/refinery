from ... import TestUnitBase


class TestFNV1(TestUnitBase):

    def test_fnv1a(self):
        for name, bits, goal in [
            ('fnv1a', 0x020, 'b5772bec'),
            ('fnv1a', 0x040, '33fb62ed8c29c76c'),
            ('fnv1a', 0x080, 'c1554aaccb9c92213e001d3679bfd5cc'),
            ('fnv1a', 0x100, (
                '4ca8a711a068a687e653c31a183667b80df784171f30687f45f1f633b0afef0c'
            )),
            ('fnv1a', 0x200, (
                '160fefb00021a45b740be7ab388cbc9dc95c1171e46cd7d31331e53ea6a997b4'
                '1c445e31a66ecafe4caa37573d453fd35d899df4e8cd5d56df3473a1d29124f4'
            )),
            ('fnv1a', 0x400, (
                '2cba95fe08e491cf206f2d539d1e2b194db80538c7abb218524325ac9587c061'
                '91ed8b4be0a1954d557a84000000000000000000000000000000000000000000'
                '000000000000000000000000000d7695ccc37057a39892f0ad3620e438ff7624'
                '2e382f46f8626b37c044da017740d9ebde0d16a510213039f50401c0b3b8d258'
            )),
            ('fnv1', 0x020, 'e6a31132'),
            ('fnv1', 0x040, '0ab104d8dc2bda52'),
            ('fnv1', 0x080, '49d0158dc76800c40f445f5eeaf4e3aa'),
            ('fnv1', 0x100, (
                'c60f78b9d27775e173ea321a183667950a53d425a92ccfe8b8105b4fdbca4d62'
            )),
            ('fnv1', 0x200, (
                '160fefb000fc48c47796893579316c57efdca756836cd7d31331e53ea6a997b4'
                '1c445e31a66ecafe4caa37573d453fe6e5bfd37454d3df72e0af2dbbb279ba5e'
            )),
            ('fnv1', 0x400, (
                '2cba95fe08e491cf206f2d539d1e2b194db80538c7abb21852431f14d5d6bd59'
                'a8a6ab1bd81c8d1f87ac2b000000000000000000000000000000000000000000'
                '000000000000000000000000000d7695ccc37057a39892f0ad3620e438ff7624'
                '2e382f46f8626b37c044da017740d93d65b136c82b55656ccaffee48d7610df4'
            )),
        ]:
            if bits == 32:
                unit = self.ldu(name, text=True)
            elif bits < 1024:
                unit = self.ldu(F'{name}x{bits}', text=True)
            else:
                unit = self.ldu(name, bits=bits, text=True)
            test = B'Binary Refinery' | unit | str
            self.assertEqual(test, goal, msg=F'failure for {unit}x{bits}')
