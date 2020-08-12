#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import inspect

import refinery.lib.tools as tools
from .. import TestBase


class TestTools(TestBase):

    def test_terminalfit(self):
        @inspect.getdoc
        class data:
            """
            Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed venenatis ac urna id ultricies. Integer eu semper mauris. Nunc sed
            nunc non ante volutpat egestas. Nam nec risus sed ex dignissim pharetra. Integer vel augue erat. Vivamus hendrerit convallis
            tortor in varius. Morbi sed nulla eget turpis volutpat maximus id vitae nisi:

            1. Aenean ullamcorper egestas lorem ornare ultrices.
            2. Donec quis gravida orci.
            3. Fusce auctor, orci sit amet vehicula varius, elit dolor feugiat nisl, at congue sapien sapien ut felis. Etiam pharetra est
               non turpis facilisis ullamcorper.

            Ut quis ipsum varius, pellentesque mauris nec, rutrum quam. Proin dictum neque ut sem hendrerit, nec lobortis sem scelerisque.
            Nullam eget justo in nunc lacinia porttitor eget nec quam. Morbi volutpat egestas risus, eget malesuada nulla vulputate eu. Cras
            leo ipsum, porttitor et malesuada a, laoreet nec metus:

            - Donec porttitor suscipit dapibus.
            - Phasellus sodales erat id imperdiet rutrum.
            - Vestibulum in augue vel libero tempor vestibulum.
            """

        @inspect.getdoc
        class wish:
            """
            Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed venenatis ac urna id
            ultricies. Integer eu semper mauris. Nunc sed nunc non ante volutpat egestas. Nam nec
            risus sed ex dignissim pharetra. Integer vel augue erat. Vivamus hendrerit convallis
            tortor in varius. Morbi sed nulla eget turpis volutpat maximus id vitae nisi:

            1. Aenean ullamcorper egestas lorem ornare ultrices.
            2. Donec quis gravida orci.
            3. Fusce auctor, orci sit amet vehicula varius, elit dolor feugiat nisl, at congue
               sapien sapien ut felis. Etiam pharetra est non turpis facilisis ullamcorper.

            Ut quis ipsum varius, pellentesque mauris nec, rutrum quam. Proin dictum neque ut sem
            hendrerit, nec lobortis sem scelerisque. Nullam eget justo in nunc lacinia porttitor eget
            nec quam. Morbi volutpat egestas risus, eget malesuada nulla vulputate eu. Cras leo ipsum,
            porttitor et malesuada a, laoreet nec metus:

            - Donec porttitor suscipit dapibus.
            - Phasellus sodales erat id imperdiet rutrum.
            - Vestibulum in augue vel libero tempor vestibulum.
            """

        self.assertEqual(tools.terminalfit(data, width=90), wish)
