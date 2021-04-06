#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import io

from .. import arg, Unit
from ...lib.xml import ForgivingParse


class ppxml(Unit):
    """
    Expects XML input data and outputs it in a neatly formatted manner.
    """

    def __init__(self,
        indent: arg.number('-i', help=(
            'Controls the amount of space characters used for indentation in the output. Default is 4.')) = 4,
        header: arg.switch('-x', help='Add an XML header to the formatted output.') = False
    ):
        super().__init__(indent=indent, header=header)

    def process(self, data):

        pad = self.args.indent * ' '
        etm = {}
        dom = ForgivingParse(data, etm)

        def indent(element, level=0, more_sibs=False):
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
                if more_sibs: element.tail += pad

        indent(dom.getroot())

        with io.BytesIO() as output:
            dom.write(output, encoding=self.codec, xml_declaration=self.args.header)
            result = output.getvalue()

        for uid, key in etm.items():
            entity = F'&{key};'.encode(self.codec)
            needle = uid.encode(self.codec)
            result = result.replace(needle, entity)

        return result
