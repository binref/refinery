from __future__ import annotations

from functools import lru_cache

from refinery.lib.dotnet.header import DotNetHeader


class CodePath:
    """
    This class can be used to recover the method to which a certain virtual address
    belongs, including its parent type and namespace.
    """
    def __init__(self, header: DotNetHeader):
        self.header = header
        self.tables = tables = header.meta.Streams.Tables
        memo = [tr.MethodList.Index - 1 for tr in tables.TypeDef]
        memo.append(len(tables.MethodDef))
        self.ranges = [range(*memo[k:k + 2]) for k in range(len(memo) - 1)]

    def method_path(self, offset: int):
        ns, tn, spec = self.method(offset)
        if tn and ns:
            ns = ns.replace('.', '/')
            spec = F'{ns}/{tn}/{spec}'
        return spec

    def method_spec(self, offset: int):
        ns, tn, spec = self.method(offset)
        if tn and ns:
            spec = F'{ns}::{tn}.{spec}'
        return spec

    @lru_cache(maxsize=None)
    def method(self, offset: int):
        def printable(name: str):
            return name.replace('.', '').isidentifier()
        ranges = self.ranges
        tables = self.tables
        header = self.header
        rva = header.pe.offset_to_virtual_address(offset) - header.pe.imagebase
        method = min(tables.MethodDef, key=lambda m: (m.RVA > rva, rva - m.RVA))
        index = tables.MethodDef.index(method)
        method_name = method.Name
        if not printable(method_name):
            method_name = F'method_{method.RVA:08X}'
        for k, (methods, tr) in enumerate(zip(ranges, tables.TypeDef), 1):
            if index in methods:
                namespace = tr.TypeNamespace
                type_name = tr.TypeName
                if not printable(type_name):
                    type_name = F'type{k}'
                if not printable(namespace):
                    namespace = F'ns{k}'
                return namespace, type_name, method_name
        return None, None, method_name
