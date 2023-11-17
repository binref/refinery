#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Unit
from refinery.lib.json import BytesAsArrayEncoder


class JavaEncoder(BytesAsArrayEncoder):

    @classmethod
    def _is_byte_array(cls, obj) -> bool:
        if super()._is_byte_array(obj):
            return True
        elif not isinstance(obj, list) or not obj:
            return False
        if not all(isinstance(t, int) for t in obj):
            return False
        if all(t in range(-0x80, 0x80) for t in obj):
            return True
        if all(t in range(0x100) for t in obj):
            return True
        return False

    def default(self, obj):
        try:
            return super().default(obj)
        except TypeError:
            if isinstance(obj, dsjava._javaobj.beans.JavaString):
                return str(obj)
            if isinstance(obj, dsjava._javaobj.beans.JavaInstance):
                cd = obj.classdesc
                fd = obj.field_data[cd]
                return dict(
                    isException=cd.is_exception,
                    isInnerClass=cd.is_inner_class,
                    isLocalInnerClass=cd.is_local_inner_class,
                    isStaticMemberClass=cd.is_static_member_class,
                    name=cd.name,
                    fields={t.name: v for t, v in fd.items()}
                )
            if isinstance(obj, dsjava._javaobj.beans.JavaField):
                return obj.class_name
            if isinstance(obj, dsjava._javaobj.beans.JavaEnum):
                return obj.value
            if isinstance(obj, dsjava._javaobj.beans.JavaArray):
                if obj.classdesc.name == '[B':
                    return bytearray(t & 0xFF for t in obj)
            raise


class dsjava(Unit):
    """
    Deserialize Java serialized data and re-serialize as JSON.
    """
    @Unit.Requires('javaobj-py3>=0.4.0.1', 'formats')
    def _javaobj():
        import javaobj.v2
        return javaobj.v2

    def process(self, data):
        with JavaEncoder as encoder:
            return encoder.dumps(self._javaobj.loads(data)).encode(self.codec)
