#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.powershell import NotWindows, get_parent_processes, is_powershell_process

from .. import TestBase


class TestPowerShellDetection(TestBase):

    def test_process_trace(self):
        try:
            processes = list(get_parent_processes())
        except NotWindows:
            pass
        else:
            self.assertTrue(any('python' in p for p in processes))

    def test_not_running_in_powershell(self):
        self.assertFalse(is_powershell_process())
