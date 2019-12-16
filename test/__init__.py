import unittest
import random
import refinery


__all__ = ['refinery', 'TestBase', 'NameUnknownException']


class NameUnknownException(Exception):
    def __init__(self, name):
        super().__init__('could not resolve: {}'.format(name))


class TestBase(unittest.TestCase):

    def generate_random_buffer(self, size):
        return bytes((random.randrange(0, 0xFF) for _ in range(size)))

    def setUp(self):
        random.seed(0xBAADF00D)  # guarantee deterministic 'random' buffers
