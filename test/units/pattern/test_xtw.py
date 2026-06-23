from .. import TestUnitBase


class TestXTW(TestUnitBase):

    def test_extract_bitcoin_address(self):
        btc = b'1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
        data = b'Send payment to ' + btc + b' please.'
        labels = {bytes(chunk): chunk.meta['kind'] for chunk in data | self.load()}
        self.assertEqual(labels, {btc: 'BTC'})

    def test_no_wallet_found(self):
        unit = self.load()
        data = b'This text contains no wallet addresses at all.'
        results = data | unit | []
        self.assertEqual(len(results), 0)

    def test_extract_eip55_checksum_address(self):
        unit = self.load()
        eth = b'0xd038B95D09831Fe264F0e357Ff9B4B745C0daa1C'
        data = b'pay to ' + eth + b' now'
        results = data | unit | {bytes}
        self.assertIn(eth, results)

    def test_extract_litecoin_bech32_address(self):
        unit = self.load()
        ltc = b'ltc1qc99jrz7rvshd63ksryxedv5gk4nh0s4vup304n'
        data = b'pay to ' + ltc + b' now'
        results = data | unit | {bytes}
        self.assertIn(ltc, results)

    def test_solana_does_not_steal_other_kinds(self):
        unit = self.load()
        addresses = {
            b'TQvf32i7Z4tFT2BQ2nqryKqzKDKQciEMc2' : 'TRON',
            b'rD9oqq555eqnsQqKFbaAjpirMmStcTrEtY' : 'XRP',
            b't1dhxHAe1HVemR312nwKDBYJpzK6RYh8UM4' : 'ZCASH',
        }
        data = b'\n'.join(addresses)
        labels = {bytes(chunk): chunk.meta['kind'] for chunk in data | unit}
        self.assertEqual(labels, {addr: kind for addr, kind in addresses.items()})

    def test_invalid_checksum_is_dropped(self):
        valid = b'3AZ33zG5Z3ECDyFSvUJeGWkK3jrc1yR6GR'
        broken = valid[:-1] + (b'A' if valid[-1:] != b'A' else b'B')
        data = b'send to ' + broken + b' now'
        self.assertEqual(data | self.load() | {bytes}, set())

    def test_bare_evm_address_labeled_eth(self):
        eth = b'0xd038B95D09831Fe264F0e357Ff9B4B745C0daa1C'
        data = b'pay to ' + eth + b' now'
        labels = {bytes(chunk): chunk.meta['kind'] for chunk in data | self.load()}
        self.assertEqual(labels, {eth: 'ETH'})

    def test_ripple_address_survives_validation(self):
        xrp = b'rD9oqq555eqnsQqKFbaAjpirMmStcTrEtY'
        data = b'wallet ' + xrp + b' end'
        labels = {bytes(chunk): chunk.meta['kind'] for chunk in data | self.load()}
        self.assertEqual(labels, {xrp: 'XRP'})

    def test_taproot_address_labeled_btc(self):
        btc = b'bc1p83n3au0rjylefxq2nc2xh2y4jzz4pm6zxj4mw5pagdjjr2a9f36s6jjnnu'
        data = b'pay to ' + btc + b' now'
        labels = {bytes(chunk): chunk.meta['kind'] for chunk in data | self.load()}
        self.assertEqual(labels, {btc: 'BTC'})

    def test_ronin_mixed_case_address_labeled_ronin(self):
        ronin = b'ronin:d038B95D09831Fe264F0e357Ff9B4B745C0daa1C'
        data = b'pay to ' + ronin + b' now'
        labels = {bytes(chunk): chunk.meta['kind'] for chunk in data | self.load()}
        self.assertEqual(labels, {ronin: 'RONIN'})

    def test_wif_private_key_labeled_wif(self):
        wif = b'5JuW2AMDYu4xVwRG9DZW18VbzQrGcd5RCgb99sS6ehJsNQXu5b9'
        data = b'key ' + wif + b' end'
        labels = {bytes(chunk): chunk.meta['kind'] for chunk in data | self.load()}
        self.assertEqual(labels, {wif: 'WIF'})
