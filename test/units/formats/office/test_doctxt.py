#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase

PARAGRAPHS = [
    (
        U'目だリドで元加カロム馬抜親ッぼほせ知未ノネツ島暮懲エワサ学60亡ヲリ守5意ヱル競渡くたはふ歌奇拝括樫クー。総に観前つ図'
        U'府にいぞね題害地語ゃけンの之地ずべひお状致洩価リ動78四ろ州見コイ津怪ユサノソ伸休障由ひトふう。田らてし万線ロ報9時モ'
        U'ヨワ動調ざぶせに二関ろじす備節マレ席朝へ満打大せぴッ割56字上もち特更チムニ以盟なゅ優討エオロノ載海つわぼい。'
    ),
    (
        U'पहोच कराना प्राप्त अन्तरराष्ट्रीयकरन तकनीकी मुश्किले ध्वनि लिये बाजार एछित अनुवाद प्राधिकरन सुचनाचलचित्र अत्यंत उपलब्धता '
        U'वास्तविक एकएस विकास जिसकी उशकी उदेशीत और्४५० विज्ञान पुर्व बाधा बिन्दुओ हार्डवेर हीकम गुजरना अविरोधता भेदनक्षमता '
        U'विभाग होभर देखने हुएआदि मर्यादित मानव लचकनहि विश्वास यन्त्रालय भाषाओ देखने होभर है।अभी पत्रिका करता खरिदने बिन्दुओ गोपनीयता सक्षम'
    ),
    (
        U'Il hav infra lanta, an tuja onin komo nen, halo trudi hot e. Onjo ligvokalo ing be, unt mi kibi praantaŭhieraŭ. '
        U'Kibi ologi jam as. '
        U'Iufoje subfrazo esperanto kaj id, bv por esti grado, onia sanskrito unu tc.'
    ),
    (
        U'Tele frota pre if, nun estiel praantaŭhieraŭ on, tiam sola mallongigoj tro be. Sur sh depost eksploda memmortigo, '
        U'giga kelke kie je. Far afro kaŭzo ni. Cia oj monatonomo tabelvorto, ci nei disde esperantigo. Ili iu lasi geinstruisto, '
        U'sube sepen kz sed. Onia miriametro esceptinte cii um, ene frazo haltostreko multiplikite ts.'
    ),
    (
        U'청춘에서만 청춘의 수 얼음이 하는 힘차게 위하여. 유소년에게서 이상이 가치를 새가 든 꽃 만물은 것은 봄바람이다, '
        U'착목한는 부패를 뛰노는 오직 사막이다. 튼튼하며, 청춘의 모래뿐일 풀밭에 커다란 위하여. 그림자는 동력은 넣는 품으며. '
        U'대중을 어디 그들의 그들은 황금시대다. 사는가 밝은 가슴에 시들어 위하여서.'
    ),
]


class TestOfficeCrypt(TestUnitBase):

    def test_simple_samples(self):
        unit = self.load()
        for filetype, sample in {
            'odt'  : '2b3ed3eea86116bf1e644da8c945f1df4972052fb4e3c4a3a30b1e68da27f0ce',
            'docx' : '36c856d2bf531eb27745f04afe89b9a86035fb6808966001cec9fb751e3e90e3',
            'doc'  : '0adb998791595d9f127750313289d62ad1c452415d4e995d3ca7b903860dd7d5',
        }.items():
            data = self.download_sample(sample)
            output = str(data | unit)
            for k, p in enumerate(PARAGRAPHS):
                self.assertIn(p, output, F'Extraction for {filetype} sample did not contain paragraph {k}')
