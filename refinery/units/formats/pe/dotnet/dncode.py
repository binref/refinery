from __future__ import annotations

from refinery.lib.dotnet.header import DotNetHeader, MethodBodyInfo, MethodCodeType, TypeDef
from refinery.lib.patterns import checks
from refinery.units.formats import PathExtractorUnit, UnpackResult


class dncode(PathExtractorUnit):
    """
    Extract .NET IL method bodies from a .NET PE file.

    Each method is emitted as a separate chunk containing the raw CIL bytecode (without the
    method body header). The output can be piped into `refinery.dnopc` for disassembly.
    Methods that are abstract, imported, or use non-IL implementation (native, runtime, OPTIL)
    are silently skipped.
    """
    def unpack(self, data):
        header = DotNetHeader(data, parse_resources=False)
        tables = header.meta.Streams.Tables
        if not tables.MethodDef:
            return

        memo = [tr.MethodList.Index - 1 for tr in tables.TypeDef]
        memo.append(len(tables.MethodDef))
        ranges = [range(*memo[k:k + 2]) for k in range(len(memo) - 1)]

        method_owners: list[TypeDef | None] = [None] * len(tables.MethodDef)
        for methods_range, typedef in zip(ranges, tables.TypeDef):
            for index in methods_range:
                if index < len(method_owners):
                    method_owners[index] = typedef

        def sanitize(name: str) -> str:
            if name.startswith('<') and name.endswith('>'):
                name = F'[{name[1:-1]}]'
            return name

        def printable(name: str) -> bool:
            return bool(name and checks.path_element_nospace.value.str.fullmatch(name))

        view = memoryview(data)

        for index, method in enumerate(tables.MethodDef):
            if method.RVA == 0 or method.CodeType != MethodCodeType.IL:
                continue
            try:
                offset = header.pe.rva_to_offset(method.RVA)
            except Exception:
                self.log_warn(F'failed to convert RVA 0x{method.RVA:08X} for method {method.Name}')
                continue
            try:
                body = MethodBodyInfo.Parse(view[offset:])
            except Exception:
                self.log_warn(F'failed to parse method body at offset 0x{offset:08X} for method {method.Name}')
                continue
            if not printable(method_name := sanitize(method.Name)):
                method_name = F'method_{method.RVA:08X}'
            if owner := method_owners[index]:
                namespace = sanitize(owner.TypeNamespace)
                type_name = sanitize(owner.TypeName)
                if not printable(type_name):
                    type_name = F'type{index}'
                if not printable(namespace):
                    namespace = F'ns{index}'
                namespace = namespace.replace('.', '/')
                path = F'{namespace}/{type_name}/{method_name}'
            else:
                path = method_name
            yield UnpackResult(path, body.code, flags=method.Flags)

    @classmethod
    def handles(cls, data):
        from refinery.lib.id import is_likely_pe_dotnet
        return is_likely_pe_dotnet(data)
