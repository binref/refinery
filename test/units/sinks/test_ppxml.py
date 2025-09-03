from .. import TestUnitBase


class TestXML(TestUnitBase):

    def test_simple(self):
        for k in range(5):
            unit = self.load(indent=k)
            result = unit(b'<foo><bar>baz</bar><bar>bat</bar></foo>')
            self.assertTrue(result.endswith(
                B'<foo>\n%s<bar>baz</bar>\n%s<bar>bat</bar>\n</foo>' % (2 * (k * B' ',))))

    def test_xml_header(self):
        unit = self.load(indent=1, header=True)
        result = unit(B'<?xml version="1.0" encoding="UTF-8"?>\n\n<foo>\n\n\n<bar>baz</bar>\n<bar>bamf</bar></foo>')
        self.assertTrue(result.startswith(B'<?xml'))
        self.assertTrue(result.endswith(B'?>\n<foo>\n <bar>baz</bar>\n <bar>bamf</bar>\n</foo>'))

    def test_unknwon_namespaces_and_entities(self):
        data = (
            B'<ac:structured-macro ac:name="multiexcerpt" ac:schema-version="1">'
            B'<ac:parameter ac:name="MultiExcerptName">Foo</ac:parameter>'
            B'<ac:parameter ac:name="atlassian-macro-output-type">INLINE</ac:parameter>'
            B'<ac:rich-text-body><p><span>Some Atlassian text &ndash; and &ndash; weird entities.</span></p></ac:rich-text-body>'
            B'</ac:structured-macro>'
        )
        pretty = (
            B'<ac:structured-macro ac:name="multiexcerpt" ac:schema-version="1">\n'
            B'    <ac:parameter ac:name="MultiExcerptName">Foo</ac:parameter>\n'
            B'    <ac:parameter ac:name="atlassian-macro-output-type">INLINE</ac:parameter>\n'
            B'    <ac:rich-text-body>\n'
            B'        <p>\n'
            B'            <span>Some Atlassian text &ndash; and &ndash; weird entities.</span>\n'
            B'        </p>\n'
            B'    </ac:rich-text-body>\n'
            B'</ac:structured-macro>'
        )

        unit = self.load()
        result = unit(data)
        self.assertEqual(pretty, result)
