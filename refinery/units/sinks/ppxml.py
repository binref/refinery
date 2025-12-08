from __future__ import annotations

import io

from refinery.lib.id import is_likely_xml
from refinery.lib.types import Param
from refinery.lib.xml import Element, ForgivingParse
from refinery.units import Arg, Unit


class ppxml(Unit):
    """
    Expects XML input data and outputs it in a neatly formatted manner.
    """

    def __init__(self,
        indent: Param[int, Arg.Number('-i', help=(
            'Controls the amount of space characters used for indentation in the output. Default is 4.'))] = 4,
        header: Param[bool, Arg.Switch('-x', help='Add an XML header to the formatted output.')] = False
    ):
        super().__init__(indent=indent, header=header)

    def process(self, data):

        pad = self.args.indent * ' '
        etm = {}

        try:
            dom = ForgivingParse(data, etm)
        except Exception:
            from refinery.lib.meta import metavars
            msg = 'error parsing as XML, returning original content'
            path = metavars(data).get('path')
            if path:
                msg = F'{msg}: {path}'
            self.log_warn(msg)
            return data

        def indent(element: Element, level=0, more_sibs=False):
            """
            The credit for this one goes to:
            https://stackoverflow.com/a/12940014
            """
            indentation = '\n'
            if level:
                indentation += (level - 1) * pad
            childcount = len(element)
            if childcount:
                if not element.text or not element.text.strip():
                    element.text = indentation + pad
                    if level:
                        element.text += pad
                for count, child in enumerate(element):
                    indent(child, level + 1, count < childcount - 1)
                if level and (not element.tail or element.tail.isspace()):
                    element.tail = indentation
                    if more_sibs:
                        element.tail += pad
            elif level and (not element.tail or element.tail.isspace()):
                element.tail = indentation
                if more_sibs:
                    element.tail += pad

        if root := dom.getroot():
            indent(root)

        with io.BytesIO() as output:
            dom.write(output, encoding=self.codec, xml_declaration=self.args.header)
            result = output.getvalue()

        for uid, key in etm.items():
            entity = F'&{key};'.encode(self.codec)
            needle = uid.encode(self.codec)
            result = result.replace(needle, entity)

        return result

    @classmethod
    def handles(cls, data):
        return is_likely_xml(data)
