from __future__ import annotations

from enum import Enum
from pathlib import Path

from refinery.lib import xml
from refinery.lib.dt import isodate
from refinery.lib.types import Param
from refinery.units import Arg, Unit
from refinery.units.formats.office.xtdoc import xtdoc
from refinery.units.sinks.ppjson import ppjson


class _Prop(str, Enum):
    app = 'app.xml'
    core = 'core.xml'
    custom = 'custom.xml'


class docmeta(Unit):
    """
    Extract metadata from Word Documents such as custom document properties.
    """

    def __init__(self, tabular: Param[bool, Arg('-t', help='Print information in a table rather than as JSON')] = False):
        super().__init__(tabular=tabular)

    def process(self, data: bytearray):
        def interpret(value: str | dict):
            if isinstance(value, dict):
                return {k: interpret(v) for k, v in value.items()}
            if value.isdigit():
                return int(value)
            casefold = value.lower()
            if casefold == 'false':
                return False
            if casefold == 'true':
                return True
            return isodate(value) or value

        props = data | xtdoc('docProps/*.xml', exact=True, path=b'path') | {'path': bytearray}
        result = {}

        for path, page in props.items():
            name = Path(path).name
            if (dom := xml.parse(page)) is None:
                self.log_info(F'failed to parse as XML: {path}')
                continue
            try:
                prop = _Prop(name)
            except ValueError:
                self.log_info(F'skipped unknown property: {name}')
                continue

            result[prop.name] = contents = {}

            if prop == _Prop.custom:
                while dom.tag.lower() != 'properties':
                    dom = dom.children[0]
                for node in dom:
                    assert node.tag.lower() == 'property'
                    assert len(node.children) == 1
                    content = node.children[0].content
                    if content is None:
                        continue
                    contents[node.attributes['name']] = content.strip()
            elif prop == _Prop.app:
                while dom.tag.lower() != 'properties':
                    dom = dom.children[0]
                for node in dom:
                    if not (content := node.content):
                        continue
                    contents[node.tag] = content
            elif prop == _Prop.core:
                while dom.tag.lower() != 'cp:coreproperties':
                    dom = dom.children[0]
                for node in dom:
                    t, _, name = node.tag.partition(':')
                    if not name:
                        continue
                    if not (content := node.content):
                        continue
                    contents[name] = content
            for name, value in contents.items():
                contents[name] = interpret(value)

        yield from ppjson(tabular=self.args.tabular)._pretty_output(result)
