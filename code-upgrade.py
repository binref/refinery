import libcst as cst
import libcst.matchers as m

_Annotated = 'Annotated'
_buf = 'buf'
_nsq = 'nsq'


class ArgToAnnotatedTransformer(cst.CSTTransformer):
    def __init__(self):
        self.imp = False
        super().__init__()

    def leave_Param(self, original_node: cst.Param, updated_node: cst.Param):
        if updated_node.annotation is None:
            return updated_node

        annotation = updated_node.annotation.annotation
        default = updated_node.default

        if isinstance(annotation, cst.Call):
            typename = 'buf'
            must_be_list = False
            if m.matches(annotation, m.Call(func=m.Attribute(value=m.Name('Arg'), attr=m.Name()))):
                assert isinstance(annotation.func, cst.Attribute), str(type(annotation.func))
                assert isinstance(annotation.func.attr, cst.Name), str(type(annotation.func.attr))
                trigger = str(annotation.func.attr.value)
                if trigger == 'Delete':
                    return updated_node
                typename = {
                    'Switch': 'bool',
                    'String': 'str',
                    'Choice': 'str',
                    'Counts': 'int',
                    'Number': 'int',
                    'Bounds': 'slice',
                    'Double': 'float',
                    'Option': 'str',
                    'Binary': _buf,
                    'FsPath': 'str',
                    'NumSeq': _nsq,
                    'RegExp': 'str',
                }[trigger]
            elif m.matches(annotation, m.Call(func=m.Name('Arg'))):
                for kw in annotation.args:
                    if kw.keyword and kw.keyword.value == 'type':
                        typename = str(kw.value)
                        break
                else:
                    if default is not None:
                        if m.matches(default, m.List()):
                            assert isinstance(default, cst.List)
                            default = default.elements[0].value
                            must_be_list = True
                        if m.matches(default, m.Call()):
                            assert isinstance(default, cst.Call)
                            typename = eval(default.func.value).__name__
                            if typename in ('bytes', 'bytearray', 'memoryview'):
                                typename = 'buf'
                        else:
                            try:
                                val = default.evaluated_value
                            except AttributeError:
                                val = eval(default.value)
                            if val is None:
                                typename = 'buf'
                            elif isinstance(val, (bytes, bytearray, memoryview)):
                                typename = 'buf'
                            else:
                                typename = type(val).__name__
            self.imp = True
            typename = cst.Name(typename)
            if must_be_list:
                typename = cst.Subscript(
                    value=cst.Name('list'),
                    slice=[cst.SubscriptElement(cst.Index(typename))]
                )
            return updated_node.with_changes(
                annotation=cst.Annotation(
                    cst.Subscript(
                        value=cst.Name(_Annotated),
                        slice=[
                            cst.SubscriptElement(cst.Index(typename)),
                            cst.SubscriptElement(cst.Index(annotation)),
                        ],
                    )
                )
            )

        return updated_node

    def leave_Module(self, original_node, updated_node):
        if not self.imp:
            return updated_node
        body = list(updated_node.body)
        last_future_idx = -1
        for i, stmt in enumerate(body):
            if m.matches(stmt, m.SimpleStatementLine(body=[m.ImportFrom(module=m.Name("__future__"))])):
                last_future_idx = i
        new_import = cst.SimpleStatementLine(
            body=[cst.ImportFrom(
                module=cst.Attribute(
                    value=cst.Attribute(
                        value=cst.Name("refinery"),
                        attr=cst.Name("lib"),
                    ),
                    attr=cst.Name("types"),
                ),
                names=[
                    cst.ImportAlias(name=cst.Name(_nsq)),
                    cst.ImportAlias(name=cst.Name(_buf)),
                    cst.ImportAlias(name=cst.Name(_Annotated)),
                ],
            )]
        )
        insert_at = last_future_idx + 1
        new_body = body[:insert_at] + [new_import] + body[insert_at:]
        self.seen_typing_import = True
        return updated_node.with_changes(body=new_body)


def transform_file(path: str):
    with open(path, 'r', encoding='utf-8', newline='\n') as f:
        source = f.read()
    tree = cst.parse_module(source)
    updated = tree.visit(ArgToAnnotatedTransformer())
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(updated.code)


if __name__ == '__main__':
    import pathlib
    import sys

    for filename in sys.argv[1:]:
        for path in pathlib.Path.cwd().glob(filename):
            print('processing', path)
            if path.is_file():
                transform_file(str(path))
