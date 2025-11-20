from __future__ import annotations

from refinery.lib import json
from refinery.units import Unit


def _is_byte_array(obj) -> bool:
    if not isinstance(obj, list) or not obj:
        return False
    if not all(isinstance(t, int) for t in obj):
        return False
    if all(t in range(-0x80, 0x80) for t in obj):
        return True
    if all(t in range(0x100) for t in obj):
        return True
    return False


def _convert_key(key):
    jvb = dsjava._javaobj.beans
    if isinstance(key, (int, bytes, str, bool)):
        return key
    if isinstance(key, jvb.JavaString):
        return str(key)
    if isinstance(key, jvb.JavaField):
        return key.name
    raise TypeError


def _preprocess(obj):
    if _is_byte_array(obj):
        return bytearray(t & 0xFF for t in obj)
    if isinstance(obj, list):
        for k, v in enumerate(obj):
            obj[k] = _preprocess(v)
    elif isinstance(obj, dict):
        return {
            _convert_key(k): _preprocess(v) for k, v in obj.items()
        }
    return obj


def _tojson(obj):
    jvb = dsjava._javaobj.beans

    if isinstance(obj, jvb.JavaArray) and obj.classdesc.name == '[B' or _is_byte_array(obj):
        return json.bytes_as_string(bytes(t & 0xFF for t in obj))
    if isinstance(obj, jvb.JavaString):
        return str(obj)
    if isinstance(obj, jvb.JavaInstance):
        cd = obj.classdesc
        fd = obj.field_data[cd]
        return dict(
            isException=cd.is_exception,
            isInnerClass=cd.is_inner_class,
            isLocalInnerClass=cd.is_local_inner_class,
            isStaticMemberClass=cd.is_static_member_class,
            name=cd.name,
            fields=_preprocess(fd),
        )
    if isinstance(obj, jvb.JavaField):
        return obj.class_name
    if isinstance(obj, jvb.JavaEnum):
        return obj.value

    return json.bytes_as_string(obj)


class dsjava(Unit):
    """
    Deserialize Java serialized data and re-serialize as JSON.
    """
    @Unit.Requires('javaobj-py3>=0.4.0.1', ['formats'])
    def _javaobj():
        import javaobj.v2
        return javaobj.v2

    def process(self, data):
        ds = _preprocess(self._javaobj.loads(data))
        return json.dumps(ds, tojson=_tojson)
