from refinery.lib.suffixtree import Node, SuffixTree
from .. import TestBase


def _leaf_paths(tree: SuffixTree) -> dict[int, bytes]:
    paths: dict[int, bytes] = {}
    pending: list[tuple[Node, bytes]] = [(child, bytes(child.label)) for child in tree]
    while pending:
        node, path = pending.pop()
        if not node.children:
            paths[id(node)] = path
        pending.extend((child, path + bytes(child.label)) for child in node)
    return paths


class TestSuffixTree(TestBase):

    def test_string_is_reconstructed_from_suffixes(self):
        data = B'The binary refinery refines binaries and includes fine rhymery.'
        tree = SuffixTree(data)
        paths = _leaf_paths(tree)
        self.assertEqual(
            [paths[id(leaf)] for leaf in tree.leaves],
            [data[k:] for k in range(len(data))]
        )

    def test_every_path_from_the_root_to_a_leaf_is_a_different_suffix(self):
        data = self.download_sample('c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73')[:0x2000]
        paths = list(_leaf_paths(SuffixTree(data)).values())
        self.assertEqual(len(set(paths)), len(paths))
        self.assertTrue(all(data.endswith(path) for path in paths))
        self.assertGreater(len(paths), len(data) // 2)
