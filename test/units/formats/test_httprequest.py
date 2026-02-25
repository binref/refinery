from .. import TestUnitBase


class TestHTTPRequest(TestUnitBase):

    def test_raw_request(self):
        data = B'\r\n'.join([
            B'POST /api/v1/data HTTP/1.1',
            B'Host: example.com',
            B'',
            B'BINARY REFINERY!',
        ])
        self.assertEqual(data | self.load() | bytes, B'BINARY REFINERY!')

    def test_form_urlencoded(self):
        data = B'\r\n'.join([
            B'POST /test HTTP/1.1',
            B'Host: example.com',
            B'Content-Type: application/x-www-form-urlencoded',
            B'Content-Length: 27',
            B'',
            B'one=binary&two=refinery'
        ])
        goal = {'one': 'binary', 'two': 'refinery'}
        test = data | self.load() | {'name': str}
        self.assertDictEqual(test, goal)

    def test_multipart(self):
        data = B'\r\n'.join([
            B'POST /test HTTP/1.1',
            B'Host: example.com',
            B'Content-Type: multipart/form-data;boundary="delimiter12345"',
            B'',
            B'--delimiter12345',
            B'Content-Disposition: form-data; name="foo"',
            B'',
            B'bar',
            B'--delimiter12345',
            B'Content-Disposition: form-data; name="msg"; filename="message.txt"',
            B'',
            B'The Binary Refinery refines the Finest Binaries.',
            B'--delimiter12345--',
        ])

        test = data | self.load() | {'name': str}
        goal = {
            'msg': 'The Binary Refinery refines the Finest Binaries.',
            'foo': 'bar',
        }
        self.assertEqual(test, goal)

        test = data | self.load() | {'file': str}
        self.assertEqual(test['message.txt'], 'The Binary Refinery refines the Finest Binaries.')
