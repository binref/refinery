#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.powershell import get_parent_processes, is_powershell_process

from .. import TestBase


class TestPowerShellDetection(TestBase):

    def test_process_trace(self):
        processes = list(get_parent_processes())
        self.assertTrue(any('python' in p for p in processes))

    def test_not_running_in_powershell(self):
        self.assertFalse(is_powershell_process())
