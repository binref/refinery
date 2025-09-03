from ... import TestUnitBase


class TestISAAC(TestUnitBase):

    def test_randseed(self):
        # There are no specific instructions on how the random state would be used as
        # a key stream in the cryptographic application of ISAAC. This implementation
        # opts to use the bytes as given in the only official example:
        #   http://www.burtleburtle.net/bob/rand/isaacafa.html
        #   http://www.burtleburtle.net/bob/rand/randseed.txt
        goal = bytes.fromhex(
            'c9d3bc51 5bc24339 23e22e3a 5659b89a 21c6dcfd 168e10a4 1df755f6 99d3a910'
            'f48f0656 e9431f57 839c384b 238bac78 d3693e2a 96e06a6f 1358bb9e 6872ff7f'
            '75f9a391 9d951a6f 4460a8a1 2818c604 459b44fc e4eeacbf b13edb9c 38f9a0c4'
            '9b6c882d 44ddb798 6a02781b 464d8241 b6e89c5b ee627b94 4b5cf183 030800c9'
            '63e24cba 9582bdaa 8b038c2c 5bcc29d7 ab4e8369 7874b242 1302a96d ec44d5cc'
            '6cc59d03 9abc6857 ea100737 c567708f b25912b4 53899438 b33ba5c0 08d848bc'
            'e32573ca 1190acf5 d015c2e7 be2f137f 2f059bb6 82ca6f0a 39172da5 9bcb3a5b'
            '8288cd54 2f7a6e72 371ac597 3c9c00e1 584ae462 7420bf5e b3e7eeb3 cb1f301d'
            '89f7548d 5c758f6e 5e5689f4 fda0ec6b d080797e c8ce8e0e 08ed5b1a 75f4dca7'
            'c03c8d08 ad11d474 cb4ee33a 6588dd1e e71dd73d 25b36d83 c2a014ee 1f1be022'
            '97748d52 ba47b4b2 b5b0f69f 9092902e 8cc370f9 a65b687f bb8ad147 3c532186'
            '25ff761b f507c27c afb18108 3b8e7ade 3044df96 f5b51be4 b8b3895f 56ad9f82'
            '13cf0045 adbbcd41 ba984c48 ac14915f 4dea8a1c 70240f6e 46e5085b 44995e68'
            'd49a2785 bec21184 33bd3209 28b6c25f 8aaa592c 642844eb b2a8bf4f b62c21b4'
            '1ed94071 5047c204 9966bf98 54d6a1de d3b08718 602cdd1e 27d3b289 f5284ba7'
            'e552480e b4317128 a6a831c7 ef98ba77 082e2387 a60f8187 1bdda376 d11b59d2'
        )
        unit = self.load(B'This is <i>not</i> the right mytext.')
        data = bytearray(len(goal))
        self.assertEqual(data | unit | bytearray, goal)
