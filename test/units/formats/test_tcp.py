import pytest

from .. import TestUnitBase
from .test_pcap import _PCAPNG_SAMPLE


class TestTCP(TestUnitBase):

    @pytest.mark.xdist_group(name='pcap')
    def test_flaron11_challenge7(self):
        goal = [bytes.fromhex(p) for p in [
            '0a 6c 55 90 73 da 49 75  4e 9a d9 84 6a 72 95 47'
            '45 e4 f2 92 12 13 ec cd  a4 b1 42 2e 2f dd 64 6f'
            'c7 e2 83 89 c7 c2 e5 1a  59 1e 01 47 e2 eb e7 ae'
            '26 40 22 da f8 c7 67 6a  1b 27 20 91 7b 82 99 9d'
            '42 cd 18 78 d3 1b c5 7b  6d b1 7b 97 05 c7 ff 24'
            '04 cb bf 13 cb db 8c 09  66 21 63 40 45 29 39 22',
            'a0 d2 eb a8 17 e3 8b 03  cd 06 32 27 bd 32 e3 53'
            '88 08 18 89 3a b0 23 78  d7 db 3c 71 c5 c7 25 c6'
            'bb a0 93 4b 5d 5e 2d 3c  a6 fa 89 ff bb 37 4c 31'
            '96 a3 5e af 2a 5e 0b 43  00 21 de 36 1a a5 8f 80'
            '15 98 1f fd 0d 98 24 b5  0a f2 3b 5c cf 16 fa 4e'
            '32 34 83 60 2d 07 54 53  4d 2e 7a 8a af 81 74 dc'
            'f2 72 d5 4c 31 86 0f',
            '3f bd 43 da 3e e3 25',
            '86 df d7',
            'c5 0c ea 1c 4a a0 64 c3  5a 7f 6e 3a b0 25 84 41'
            'ac 15 85 c3 62 56 de a8  3c ac 93 00 7a 0c 3a 29'
            '86 4f 8e 28 5f fa 79 c8  eb 43 97 6d 5b 58 7f 8f'
            '35 e6 99 54 71 16',
            'fc b1 d2 cd bb a9 79 c9  89 99 8c',
            '61 49 0b',
            'ce 39 da',
            '57 70 11 e0 d7 6e c8 eb  0b 82 59 33 1d ef 13 ee'
            '6d 86 72 3e ac 9f 04 28  92 4e e7 f8 41 1d 4c 70'
            '1b 4d 9e 2b 37 93 f6 11  7d d3 0d ac ba',
            '2c ae 60 0b 5f 32 ce a1  93 e0 de 63 d7 09 83 8b'
            'd6',
            'a7 fd 35',
            'ed f0 fc',
            '80 2b 15 18 6c 7a 1b 1a  47 5d af 94 ae 40 f6 bb'
            '81 af ce dc 4a fb 15 8a  51 28 c2 8c 91 cd 7a 88'
            '57 d1 2a 66 1a ca ec',
            'ae c8 d2 7a 7c f2 6a 17  27 36 85',
            '35 a4 4e',
            '2f 39 17',
            'ed 09 44 7d ed 79 72 19  c9 66 ef 3d d5 70 5a 3c'
            '32 bd b1 71 0a e3 b8 7f  e6 66 69 e0 b4 64 6f c4'
            '16 c3 99 c3 a4 fe 1e dc  0a 3e c5 82 7b 84 db 5a'
            '79 b8 16 34 e7 c3 af e5  28 a4 da 15 45 7b 63 78'
            '15 37 3d 4e dc ac 21 59  d0 56',
            'f5 98 1f 71 c7 ea 1b 5d  8b 1e 5f 06 fc 83 b1 de'
            'f3 8c 6f 4e 69 4e 37 06  41 2e ab f5 4e 3b 6f 4d'
            '19 e8 ef 46 b0 4e 39 9f  2c 8e ce 84 17 fa',
            '40 08 bc',
            '54 e4 1e',
            'f7 01 fe e7 4e 80 e8 df  b5 4b 48 7f 9b 2e 3a 27'
            '7f a2 89 cf 6c b8 df 98  6c dd 38 7e 34 2a c9 f5'
            '28 6d a1 1c a2 78 40 84',
            '5c a6 8d 13 94 be 2a 4d  3d 4d 7c 82 e5',
            '31 b6 da c6 2e f1 ad 8d  c1 f6 0b 79 26 5e d0 de'
            'aa 31 dd d2 d5 3a a9 fd  93 43 46 38 10 f3 e2 23'
            '24 06 36 6b 48 41 53 33  d4 b8 ac 33 6d 40 86 ef'
            'a0 f1 5e 6e 59',
            '0d 1e c0 6f 36',
        ]]
        pipeline = self.load_pipeline('pcap [| tcp ]')
        test = _PCAPNG_SAMPLE | pipeline | [bytes]
        self.assertEqual(test, goal)

    @pytest.mark.xdist_group(name='pcap')
    def test_stream_labels(self):
        pipeline = self.load_pipeline('pcap [| tcp ]')
        chunks = list(_PCAPNG_SAMPLE | pipeline)
        self.assertEqual(chunks[0]['src'], '192.168.56.101:49848')
        self.assertEqual(chunks[0]['dst'], '192.168.56.103:31337')
        self.assertEqual({chunk['stream'] for chunk in chunks}, {0})

    @pytest.mark.xdist_group(name='pcap')
    def test_per_packet_meta_not_inherited(self):
        pipeline = self.load_pipeline('pcap [| tcp ]')
        chunks = list(_PCAPNG_SAMPLE | pipeline)
        for chunk in chunks:
            self.assertNotIn('time', chunk.meta)
            self.assertNotIn('link', chunk.meta)

    @pytest.mark.xdist_group(name='pcap')
    def test_merge_produces_two_directions(self):
        pipeline = self.load_pipeline('pcap [| tcp -m ]')
        chunks = list(_PCAPNG_SAMPLE | pipeline)
        self.assertEqual(len(chunks), 2)
        directions = {(chunk['src'], chunk['dst']) for chunk in chunks}
        self.assertEqual(directions, {
            ('192.168.56.101:49848', '192.168.56.103:31337'),
            ('192.168.56.103:31337', '192.168.56.101:49848'),
        })

    @pytest.mark.xdist_group(name='pcap')
    def test_client_only(self):
        pipeline = self.load_pipeline('pcap [| tcp -mc ]')
        chunks = list(_PCAPNG_SAMPLE | pipeline)
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0]['src'], '192.168.56.101:49848')

    @pytest.mark.xdist_group(name='pcap')
    def test_server_only(self):
        pipeline = self.load_pipeline('pcap [| tcp -ms ]')
        chunks = list(_PCAPNG_SAMPLE | pipeline)
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0]['src'], '192.168.56.103:31337')

    @pytest.mark.xdist_group(name='pcap')
    def test_get_request_summary(self):
        data = self.download_sample('1baf0e669f38b94487b671fab59929129b5b1c2755bc00510812e8a96a53e10e')
        pipeline = self.load_pipeline(R'pcap [| tcp | rex "^GET\s[^\s]+" | sep ]')
        result = str(data | pipeline)
        self.assertEqual(result, '\n'.join((
            'GET /286//update.txt',
            'GET /286/soft/163.exe',
            'GET /286/count/count.asp?mac=00-0E-0C-33-1C-80&ver=2007051922&user=00&md5=258a993832e5f435cc3a7ba4791bc3de&pc=BOBTWO',
            'GET /mh.exe',
            'GET /286/pop.asp?url=http://www.puma164.''com/pu/39685867.htm?2',
            'GET /favicon.ico',
            'GET /12.exe',
            'GET /286/pop.asp?url=http://59.34.197.''164:81/804635/adx352133.asp',
        )))
