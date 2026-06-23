from __future__ import annotations

from refinery.lib.wallets import (
    base58check,
    bech32_valid,
    eip55_valid,
    solana_valid,
    validate,
)

from .. import TestBase


class TestWalletValidation(TestBase):

    def test_base58check_roundtrip_authentic(self):
        self.assertIsNotNone(base58check(b'3AZ33zG5Z3ECDyFSvUJeGWkK3jrc1yR6GR'))
        self.assertIsNotNone(base58check(b'XvRd4WhccBJnAPjTnw1fRE65QU1DQpf2sy'))

    def test_base58check_rejects_corrupted(self):
        self.assertIsNone(base58check(b'3AZ33zG5Z3ECDyFSvUJeGWkK3jrc1yR6GA'))

    def test_base58check_rejects_too_short(self):
        self.assertIsNone(base58check(b'1111'))

    def test_bech32_authentic(self):
        self.assertTrue(bech32_valid(b'ltc1qc99jrz7rvshd63ksryxedv5gk4nh0s4vup304n', b'ltc'))

    def test_bech32_rejects_wrong_hrp(self):
        self.assertFalse(bech32_valid(b'ltc1qc99jrz7rvshd63ksryxedv5gk4nh0s4vup304n', b'bc'))

    def test_bech32_rejects_corrupted(self):
        self.assertFalse(bech32_valid(b'ltc1qc99jrz7rvshd63ksryxedv5gk4nh0s4vup304A', b'ltc'))

    def test_eip55_checksummed_authentic(self):
        self.assertTrue(eip55_valid(b'0xd038B95D09831Fe264F0e357Ff9B4B745C0daa1C'))

    def test_eip55_rejects_bad_checksum(self):
        self.assertFalse(eip55_valid(b'0xD038B95D09831Fe264F0e357Ff9B4B745C0daa1C'))

    def test_eip55_accepts_single_case(self):
        lower = b'0xd038b95d09831fe264f0e357ff9b4b745c0daa1c'
        self.assertTrue(eip55_valid(lower))
        self.assertTrue(eip55_valid(lower.upper().replace(b'0X', b'0x')))

    def test_solana_length(self):
        self.assertFalse(solana_valid(b'TQvf32i7Z4tFT2BQ2nqryKqzKDKQciEMc2'))

    def test_validate_passes_unknown_kind(self):
        self.assertTrue(validate('LSK', b'not actually checked'))

    def test_validate_known_kind_rejects(self):
        self.assertFalse(validate('BTC', b'3AZ33zG5Z3ECDyFSvUJeGWkK3jrc1yR6GA'))

    def test_validate_xrp(self):
        addr = b'rD9oqq555eqnsQqKFbaAjpirMmStcTrEtY'
        self.assertTrue(validate('XRP', addr))
        self.assertFalse(validate('XRP', addr[:-1] + b'p'))

    def test_validate_bch_cashaddr(self):
        addr = b'bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a'
        self.assertTrue(validate('BCH', addr))
        self.assertTrue(validate('BCH', b'qphcz8jxm87mnuk7fujj9ze6ark7n4h6m5kpyhccmt'))
        self.assertFalse(validate('BCH', b'qphcz8jxm87mnuk7fujj9ze6ark7n4h6m5kpyhccmq'))

    def test_validate_xlm(self):
        addr = b'GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ'
        self.assertTrue(validate('XLM', addr))
        self.assertFalse(validate('XLM', addr[:-1] + b'A'))

    def test_validate_terra(self):
        addr = b'terra1dcegyrekltswvyy0xy69ydgxn9x8x32zdtapd8'
        self.assertTrue(validate('TERRA', addr))
        self.assertFalse(validate('TERRA', addr[:-1] + b'a'))

    def test_validate_dot_ss58(self):
        addr = b'5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY'
        self.assertTrue(validate('DOT', addr))
        self.assertFalse(validate('DOT', addr[:-1] + b'Z'))

    def test_validate_ada_shelley(self):
        addr = b'addr1vpu5vlrf4xkxv2qpwngf6cjhtw542ayty80v8dyr49rf5eg0yu80w'
        self.assertTrue(validate('ADA', addr))
        self.assertFalse(validate('ADA', addr[:-1] + b'x'))

    def test_validate_ada_byron(self):
        addr = (
            b'37btjrVyb4KDXBNC4haBVPCrro8AQPHwvCMp3RFhhSVWwfFmZ6wwzSK6JK1hY6w'
            b'HNmtrpTf1kdbva8TCneM2YsiXT7mrzT21EacHnPpz5YyUdj64na'
        )
        self.assertTrue(validate('ADA', addr))
        self.assertFalse(validate('ADA', addr[:-1] + b'b'))

    def test_validate_ronin(self):
        addr = b'ronin:d038B95D09831Fe264F0e357Ff9B4B745C0daa1C'
        self.assertTrue(validate('RONIN', addr))
        self.assertFalse(validate('RONIN', b'ronin:D038B95D09831Fe264F0e357Ff9B4B745C0daa1C'))

    def test_validate_wif(self):
        addr = b'5JuW2AMDYu4xVwRG9DZW18VbzQrGcd5RCgb99sS6ehJsNQXu5b9'
        self.assertTrue(validate('WIF', addr))
        self.assertFalse(validate('WIF', addr[:-1] + b'A'))

    def test_validate_iota(self):
        addr = b'iota1qpf0mlq8yxpx2nck8a0slxnzr4ef2ek8f5gqxlzd0wasgp73utryj430ldu'
        self.assertTrue(validate('IOTA', addr))
        self.assertFalse(validate('IOTA', addr[:-1] + b'a'))

    def test_validate_neo(self):
        addr = b'NMBfzaEq2c5zodiNbLPoohVENARMbJim1r'
        self.assertTrue(validate('NEO', addr))
        self.assertFalse(validate('NEO', addr[:-1] + b'a'))

    def test_validate_ont(self):
        addr = b'AMeJEzSMSNMZThqGoxBVVFwKsGXpAdVriS'
        self.assertTrue(validate('ONT', addr))
        self.assertFalse(validate('ONT', addr[:-1] + b'a'))

    def test_validate_ton(self):
        addr = b'EQDXDCFLXgiTrjGSNVBuvKPZVYlPn3J_u96xxLas3_yoRWRk'
        self.assertTrue(validate('TON', addr))
        self.assertFalse(validate('TON', addr[:-2] + b'AA'))

    def test_validate_monero(self):
        addr = (
            b'4AzKEX4gXdJdNeM6dfiBFL7kqund3HYGvMBF3ttsNd9SfzgYB6L7ep1Yg1osYJz'
            b'LdaKAYSLVh6e6jKnAuzj3bw1oGy9kXCb'
        )
        self.assertTrue(validate('XMR', addr))
        self.assertFalse(validate('XMR', addr[:-1] + b'A'))

    def test_validate_nem(self):
        addr = b'NABHFGE5ORQD3LE4O6B7JUFN47ECOFBFASC3SCAC'
        self.assertTrue(validate('XEM', addr))
        self.assertFalse(validate('XEM', addr[:-1] + b'A'))

    def test_validate_tezos(self):
        addr = b'tz1gvF4cD2dDtqitL3ZTraggSR1Mju2BKFEM'
        self.assertTrue(validate('XTZ', addr))
        self.assertFalse(validate('XTZ', b'tz1gvF4cD2dDtqitL3ZTraggSR1Mju2BKFEN'))

    def test_validate_algorand(self):
        addr = b'PNWOET7LLOWMBMLE4KOCELCX6X3D3Q4H2Q4QJASYIEOF7YIPPQBG3YQ5YI'
        self.assertTrue(validate('ALGO', addr))
        self.assertFalse(validate('ALGO', addr[:-1] + b'A'))
