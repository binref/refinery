from ... import TestUnitBase

from ...compression import KADATH1

VKADATH = (
    'Klwmr xzkvw Wiahfjgl Hiexvp uvjiziu mw xmm zeitvpqwhw tgkc, fvq xypvi yqzij urw mm frrrtljl '
    'narw nlntr wkgcp mm celqvh tv glv fzkm brviyti fjbzv gk. Eqt tscbvr fvq pftvpd qg fcyqii qa '
    'xyc jysarx, ngkl biypj, rvqutrw, tmcssvnhvq, rri iegycu fwqqkvq fj amvrvb dewjyi, '
    'jgczjz-oejgeii nbyerrmsa bj gpzwrigmt qgvfg vr spfei adyrpvw fvq tvpwyrmq krpuisa, nru uzhj '
    'agvvckw riegygek gmgavce hjtvgrrv xwmrw rlu fqwfwfk-ceima yilj esl vzfpp wyigyvq zr ltredgek '
    'wwjw; nfzpj wa wkcvt swexyurvi aysgcj gqqzfvb kmjzf sw pvh wwbjj yeh ttq tvybii onfccj '
    'lfzoslpzrl tvxkjv pfvrw fd xvfafc tmsfqmf. Mk urw f nrzvp fj ypr kfbj; e kiajrpv sk ahtvpeeq '
    'beydnvxx iah r acexp bjzkdswbnp twdfftf. Qpqkiwg uyee rftcg mk yj gqwhhj ysszb n jrzlptcf '
    'yetzwnbrh dmlryivr; rlu ex Knvkci wywbh spveypyijq rri mktvakesb br kfrx giyyjrieimq trprtjb '
    'glvpv wbmcx ln ks mqz xyc gsnoaeeap esl fyjnvrxm bj rjdsxb-ieegjljl zidmic, ypr trge sk tbwk '
    'rymsof, eeb klj unhucemso aivb ks utngv yxenv jlrr frhm ueu ye ebmfsdc rri ubqvlksza cprav.\0'
)


class TestVigenereCipher(TestUnitBase):

    def test_test_kadath(self):
        unit = self.load('REFINERY', operator='sub', ignore_unknown=True)
        test = KADATH1.encode('utf8') | unit | str
        self.assertEqual(VKADATH, test)
