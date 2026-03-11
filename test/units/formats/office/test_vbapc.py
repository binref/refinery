import inspect
from ... import TestUnitBase


class TestVBAPC(TestUnitBase):

    def test_maldoc_01(self):
        data = self.download_sample('4bdc8e660ff4fb05e5b6c0a2dd70c537817f46ac3270d779fdddc8e459829c08')
        unit = self.load()
        code = list(data | unit)
        self.assertTrue(any(
            B'http://109.94.209'B'.91/12340.txt' in c for c in code))

    def test_maldoc_02(self):
        data = self.download_sample('ee103f8d64cd8fa884ff6a041db2f7aa403c502f54e26337c606044c2f205394')
        unit = self.load()
        code = list(data | unit)
        self.assertTrue(any(
            B'ActiveDocument.Content.Find.Execute FindText:="$1", ReplaceWith:=dowKarolYou, Replace:=wdReplaceAll' in c for c in code))

    def test_stomped_document_01(self):
        data = self.download_sample('6d8a0f5949adf37330348cc9a231958ad8fb3ea3a3d905abe5e72dbfd75a3d1d')
        unit = self.load()
        code = str(data | unit)
        goal = inspect.cleandoc(
            """
            Function justify_text_to_left(dt As String) As String
              On Error Resume Next
              Dim ks As String
              ks = page_border_width
              Dim dl As Long
              dl = ((Len(dt) / 2) - 1)
              kl = Len(ks)
              Dim s As String
              s = ""
              For i = 0 To dl
                Dim c1 As Integer
                Dim c2 As Integer
                c1 = Val("&H" & Mid(dt, ((i * 2) + 1), 2))
                c2 = Asc(Mid(ks, (i Mod kl) + 1, 1))
                s = s & Chr(c1 Xor c2)
              Next
              justify_text_to_left = s
            End Function
            """
        )
        self.assertIn(goal, code)
