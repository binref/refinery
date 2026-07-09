from __future__ import annotations

from enum import Enum
from pathlib import Path

from refinery.lib import xml
from refinery.lib.dt import isodate
from refinery.units.formats import JSONTableUnit
from refinery.units.formats.office.xtdoc import xtdoc


class _Prop(str, Enum):
    app = 'app.xml'
    core = 'core.xml'
    custom = 'custom.xml'


class docmeta(JSONTableUnit):
    """
    Extract metadata from Office documents. For Word documents, this includes custom document
    properties; for Microsoft Access databases, this includes the database engine, timestamps, and
    the user profile paths leaked by the compiled VBA project and by the import/export
    specifications.
    """
    @classmethod
    def handles(cls, data) -> bool | None:
        from refinery.lib.id import is_likely_doc
        from refinery.lib.access import is_access_database
        if is_likely_doc(data):
            return True
        if is_access_database(data):
            return True

    def json(self, data: bytearray):
        from refinery.lib.access import is_access_database
        if is_access_database(data):
            return self._json_access(data)
        return self._json_ooxml(data)

    def _json_access(self, data: bytearray):
        from refinery.lib.access import AccessDatabase
        return AccessDatabase(data).metadata()

    def _json_ooxml(self, data: bytearray):
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

        return result
