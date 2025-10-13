from typing import get_origin, get_args

from refinery.lib.annotations import evaluate, get_type_hints

from .. import TestBase


class TestType:
    ...


class TestTypes(TestBase):

    def test_evaluate_complex_hint(self):
        evaluate('list[list[int] | str | bool | float] | dict[str, int] | list[bool | None] | None')

    def test_evaluate_list(self):
        t = evaluate('list[int]')
        self.assertIs(get_origin(t), list)
        self.assertEqual(get_args(t), (int,))

    def test_get_type_hints_functions(self):
        def f(x: TestType) -> int:
            ...
        hints = get_type_hints(f)
        self.assertIs(hints['x'], TestType)

    def test_get_type_hints_classes(self):
        from refinery.lib.cab import Cabinet

        class Test(Cabinet):
            property: int

        hints = get_type_hints(Test)
        self.assertEqual(get_args(get_args(hints['files'])[1])[0].__name__, 'CabFile')
        self.assertEqual(get_args(get_args(hints['disks'])[1])[0].__name__, 'CabDisk')

        self.assertIs(hints['property'], int)
