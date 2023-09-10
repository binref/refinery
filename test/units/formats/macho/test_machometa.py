#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
from ... import TestUnitBase


class TestMachoMeta(TestUnitBase):
    def test_x86_64_sample(self):
        data = self.download_sample('6c121f2b2efa6592c2c22b29218157ec9e63f385e7a1d7425857d603ddef8c59')
        unit = self.load()
        result = json.loads(unit(data))

        self.assertEqual(result['FileType'], "THIN")
        self.assertEqual(len(result['Slices']), 1)

        slice_metadata = result['Slices'][0]
        self.assertIn('Header', slice_metadata)
        self.assertIn('Linked Images', slice_metadata)
        self.assertIn('Signatures', slice_metadata)
        self.assertIn('Version', slice_metadata)

        # #define CPU_TYPE_X86  ((cpu_type_t) 7)
        # #define CPU_ARCH_ABI64 0x01000000  /* 64 bit ABI */
        # #define CPU_TYPE_X86_64  (CPU_TYPE_X86 | CPU_ARCH_ABI64)
        self.assertEqual(slice_metadata['Header']['cpu_type'], 0x0100_0007)
        # #define CPU_SUBTYPE_LIB64 0x80000000 /* 64 bit libraries */
        # #define CPU_SUBTYPE_X86_64_ALL  ((cpu_subtype_t)3)
        self.assertEqual(slice_metadata['Header']['cpu_subtype'], 0x8000_0003)

        self.assertEqual(slice_metadata["Base Name"], "")
        self.assertEqual(slice_metadata["Install Name"], "")
        self.assertEqual(slice_metadata["UUID"], "839216049d683075bc3f5a8628778bb8")

    def test_arm64_sample(self):
        data = self.download_sample('3e4bbd21756ae30c24ff7d6942656be024139f8180b7bddd4e5c62a9dfbd8c79')
        unit = self.load()
        result = json.loads(unit(data))

        self.assertEqual(result['FileType'], "THIN")
        self.assertEqual(len(result['Slices']), 1)

        slice_metadata = result['Slices'][0]
        self.assertIn('Header', slice_metadata)
        self.assertIn('Linked Images', slice_metadata)
        self.assertIn('Signatures', slice_metadata)
        self.assertIn('Version', slice_metadata)

        # #define CPU_TYPE_ARM  ((cpu_type_t) 12)
        # #define CPU_ARCH_ABI64 0x01000000  /* 64 bit ABI */
        # #define CPU_TYPE_ARM64          (CPU_TYPE_ARM | CPU_ARCH_ABI64)
        self.assertEqual(slice_metadata['Header']['cpu_type'], 0x0100_000C)
        # #define CPU_SUBTYPE_ARM64_ALL           ((cpu_subtype_t) 0)
        self.assertEqual(slice_metadata['Header']['cpu_subtype'], 0x0000_0000)

        self.assertEqual(slice_metadata["Base Name"], "")
        self.assertEqual(slice_metadata["Install Name"], "")
        self.assertEqual(slice_metadata["UUID"], "f962f18b12a133368aa40779089c2b09")

    def test_universal_binary_sample(self):
        data = self.download_sample('1a9a5c797777f37463b44de2b49a7f95abca786db3977dcdac0f79da739c08ac')
        unit = self.load()
        result = json.loads(unit(data))

        self.assertEqual(result['FileType'], "FAT")
        self.assertEqual(len(result['Slices']), 2)

        for slice_metadata in result['Slices']:
            self.assertIn('Header', slice_metadata)
            self.assertIn('Linked Images', slice_metadata)
            self.assertIn('Signatures', slice_metadata)
            self.assertIn('Version', slice_metadata)

        x86_64_slice_metadata = result['Slices'][0]
        # #define CPU_TYPE_X86  ((cpu_type_t) 7)
        # #define CPU_ARCH_ABI64 0x01000000  /* 64 bit ABI */
        # #define CPU_TYPE_X86_64  (CPU_TYPE_X86 | CPU_ARCH_ABI64)
        self.assertEqual(x86_64_slice_metadata['Header']['cpu_type'], 0x0100_0007)
        # #define CPU_SUBTYPE_X86_64_ALL  ((cpu_subtype_t)3)
        self.assertEqual(x86_64_slice_metadata['Header']['cpu_subtype'], 0x0000_0003)

        arm64_metadata = result['Slices'][1]
        # #define CPU_TYPE_ARM  ((cpu_type_t) 12)
        # #define CPU_ARCH_ABI64 0x01000000  /* 64 bit ABI */
        # #define CPU_TYPE_ARM64          (CPU_TYPE_ARM | CPU_ARCH_ABI64)
        self.assertEqual(arm64_metadata['Header']['cpu_type'], 0x0100_000C)
        # #define CPU_SUBTYPE_ARM64_ALL           ((cpu_subtype_t) 0)
        self.assertEqual(arm64_metadata['Header']['cpu_subtype'], 0)

    def test_adhoc_signature(self):
        data = self.download_sample('6c121f2b2efa6592c2c22b29218157ec9e63f385e7a1d7425857d603ddef8c59')
        unit = self.load()
        result = json.loads(unit(data))

        self.assertEqual(result['FileType'], "THIN")
        self.assertEqual(len(result['Slices']), 1)

        slice_metadata = result['Slices'][0]
        self.assertIn('Signatures', slice_metadata)
        self.assertEqual(slice_metadata['Signatures']['Ad-Hoc Signed'], True)
        self.assertEqual(slice_metadata['Signatures']['Signature Identifier'], "payload2-55554944839216049d683075bc3f5a8628778bb8")

    def test_pkcs7_signature(self):
        data = self.download_sample('a64fa9f1c76457ecc58402142a8728ce34ccba378c17318b3340083eeb7acc67')
        unit = self.load()
        result = json.loads(unit(data))

        self.assertEqual(result['FileType'], "FAT")
        self.assertEqual(len(result['Slices']), 2)

        for slice_index, slice_metadata in enumerate(result['Slices']):
            self.assertIn('Signatures', slice_metadata)
            self.assertIn('Ad-Hoc Signed', slice_metadata['Signatures'])
            self.assertIn('Signature Identifier', slice_metadata['Signatures'])
            self.assertIn('Signature', slice_metadata['Signatures'])

            self.assertEqual(slice_metadata['Signatures']['Signature Identifier'], "libffmpeg")
            self.assertEqual(slice_metadata['Signatures']['Ad-Hoc Signed'], False)

            pkcs7_signature_data = slice_metadata['Signatures']['Signature']

            if slice_index == 0:
                self.assertEqual(pkcs7_signature_data['Timestamp'], "2023-03-13 06:41:00+00:00")
            elif slice_index == 1:
                self.assertEqual(pkcs7_signature_data['Timestamp'], "2023-03-13 06:41:01+00:00")

            self.assertEqual(pkcs7_signature_data['TimestampIssuer'], "Developer ID Certification Authority")
            self.assertEqual(pkcs7_signature_data['Subject'], "Developer ID Application: 3CX (33CF4654HL)")
            self.assertEqual(pkcs7_signature_data['SubjectLocation'], "US")
            self.assertEqual(pkcs7_signature_data['ValidFrom'], "2019-04-11 12:03:36+00:00")
            self.assertEqual(pkcs7_signature_data['ValidUntil'], "2024-04-11 12:03:36+00:00")
            self.assertEqual(pkcs7_signature_data['Issuer'], "Developer ID Certification Authority")
            self.assertEqual(pkcs7_signature_data['Fingerprint'], "7df5ed6d71b296ed073a5b3efbcdc4c916ba41be")
            self.assertEqual(pkcs7_signature_data['Serial'], "4b0aaf622b260469")
