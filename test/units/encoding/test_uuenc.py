#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase
from ..compression import KADATH1, KADATH2


class TestUUEncDecoder(TestUnitBase):

    def test_simple_printable_buffer_01(self):
        unit = self.load()
        data = b'\n'.join((
            br'''begin 666 -''',
            br'''M5&AR964@=&EM97,@4F%N9&]L<&@@0V%R=&5R(&1R96%M960@;V8@=&AE(&UA''',
            br'''M<G9E;&QO=7,@8VET>2P@86YD('1H<F5E('1I;65S('=A<R!H92!S;F%T8VAE''',
            br'''M9"!A=V%Y('=H:6QE('-T:6QL(&AE('!A=7-E9"!O;B!T:&4@:&EG:"!T97)R''',
            br'''M86-E(&%B;W9E(&ET+B!!;&P@9V]L9&5N(&%N9"!L;W9E;'D@:70@8FQA>F5D''',
            br'''M(&EN('1H92!S=6YS970L('=I=&@@=V%L;',L('1E;7!L97,L(&-O;&]N;F%D''',
            br'''M97,L(&%N9"!A<F-H960@8G)I9&=E<R!O9B!V96EN960@;6%R8FQE+"!S:6QV''',
            br'''M97(M8F%S:6YE9"!F;W5N=&%I;G,@;V8@<')I<VUA=&EC('-P<F%Y(&EN(&)R''',
            br'''M;V%D('-Q=6%R97,@86YD('!E<F9U;65D(&=A<F1E;G,L(&%N9"!W:61E('-T''',
            br'''M<F5E=',@;6%R8VAI;F<@8F5T=V5E;B!D96QI8V%T92!T<F5E<R!A;F0@8FQO''',
            br'''M<W-O;2UL861E;B!U<FYS(&%N9"!I=F]R>2!S=&%T=65S(&EN(&=L96%M:6YG''',
            br'''M(')O=W,[('=H:6QE(&]N('-T965P(&YO<G1H=V%R9"!S;&]P97,@8VQI;6)E''',
            br'''M9"!T:65R<R!O9B!R960@<F]O9G,@86YD(&]L9"!P96%K960@9V%B;&5S(&AA''',
            br'''M<F)O=7)I;F<@;&ET=&QE(&QA;F5S(&]F(&=R87-S>2!C;V)B;&5S+B!)="!W''',
            br'''M87,@82!F979E<B!O9B!T:&4@9V]D<SL@82!F86YF87)E(&]F('-U<&5R;F%L''',
            br'''M('1R=6UP971S(&%N9"!A(&-L87-H(&]F:6UM;W)T86P@8WEM8F%L<RX@37ES''',
            br'''M=&5R>2!H=6YG(&%B;W5T(&ET(&%S(&-L;W5D<R!A8F]U="!A(&9A8G5L;W5S''',
            br'''M('5N=FES:71E9"!M;W5N=&%I;CL@86YD(&%S($-A<G1E<B!S=&]O9"!B<F5A''',
            br'''M=&AL97-S(&%N9"!E>'!E8W1A;G0@;VX@=&AA="!B86QU<W1R861E9"!P87)A''',
            br'''M<&5T('1H97)E('-W97!T('5P('1O(&AI;2!T:&4@<&]I9VYA;F-Y(&%N9"!S''',
            br'''M=7-P96YS92!O9B!A;&UO<W0M=F%N:7-H960@;65M;W)Y+"!T:&4@<&%I;B!O''',
            br'''M9B!L;W-T('1H:6YG<RP@86YD('1H92!M861D96YI;F<@;F5E9"!T;R!P;&%C''',
            br'''M92!A9V%I;B!W:&%T(&]N8V4@:&%D(&%N(&%W97-O;64@86YD(&UO;65N=&]U''',
            br''')<R!P;&%C92X`''',
            br'''`''',
            br'''end''',
        ))
        self.assertEqual(KADATH1, data | unit | str)

    def test_simple_printable_buffer_02(self):
        unit = self.load()
        data = b'\n'.join((
            br'''begin 666 -''',
            br'''M2&4@:VYE=R!T:&%T(&9O<B!H:6T@:71S(&UE86YI;F<@;75S="!O;F-E(&AA''',
            br'''M=F4@8F5E;B!S=7!R96UE.R!T:&]U9V@@:6X@=VAA="!C>6-L92!O<B!I;F-A''',
            br'''M<FYA=&EO;B!H92!H860@:VYO=VX@:70L(&]R('=H971H97(@:6X@9')E86T@''',
            br'''M;W(@:6X@=V%K:6YG+"!H92!C;W5L9"!N;W0@=&5L;"X@5F%G=65L>2!I="!C''',
            br'''M86QL960@=7`@9VQI;7!S97,@;V8@82!F87(L(&9O<F=O='1E;B!F:7)S="!Y''',
            br'''M;W5T:"P@=VAE;B!W;VYD97(@86YD('!L96%S=7)E(&QA>2!I;B!A;&P@=&AE''',
            br'''M(&UY<W1E<GD@;V8@9&%Y<RP@86YD(&1A=VX@86YD(&1U<VL@86QI:V4@<W1R''',
            br'''M;V1E(&9O<G1H('!R;W!H971I8VL@=&\@=&AE(&5A9V5R('-O=6YD(&]F(&QU''',
            br'''M=&5S(&%N9"!S;VYG.R!U;F-L;W-I;F<@9F%E<GD@9V%T97,@=&]W87)D(&9U''',
            br'''M<G1H97(@86YD('-U<G!R:7-I;F<@;6%R=F5L<RX@0G5T(&5A8V@@;FEG:'0@''',
            br'''M87,@:&4@<W1O;V0@;VX@=&AA="!H:6=H(&UA<F)L92!T97)R86-E('=I=&@@''',
            br'''M=&AE(&-U<FEO=7,@=7)N<R!A;F0@8V%R=F5N(')A:6P@86YD(&QO;VME9"!O''',
            br'''M9F8@;W9E<B!T:&%T(&AU<VAE9"!S=6YS970@8VET>2!O9B!B96%U='D@86YD''',
            br'''M('5N96%R=&AL>2!I;6UA;F5N8V4L(&AE(&9E;'0@=&AE(&)O;F1A9V4@;V8@''',
            br'''M9')E86TG<R!T>7)A;FYO=7,@9V]D<SL@9F]R(&EN(&YO('=I<V4@8V]U;&0@''',
            br'''M:&4@;&5A=F4@=&AA="!L;V9T>2!S<&]T+"!O<B!D97-C96YD('1H92!W:61E''',
            br'''M(&UA<FUO<F5A;"!F;&EG:'1S(&9L=6YG(&5N9&QE<W-L>2!D;W=N('1O('=H''',
            br'''M97)E('1H;W-E('-T<F5E=',@;V8@96QD97(@=VET8VAE<GD@;&%Y(&]U='-P''',
            br'''4<F5A9"!A;F0@8F5C:V]N:6YG+@``''',
            br'''`''',
            br'''end''',
        ))
        self.assertEqual(KADATH2, data | unit | str)

    def test_reversible(self):
        u = self.load()
        for k in (1, 2, 3, 5, 12, 54, 67, 77, 212, 23543):
            b = self.generate_random_buffer(k)
            self.assertEqual(b, b | -u | u | bytes)
