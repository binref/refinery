from inspect import getdoc
from .. import TestUnitBase


class TestScriptDecoder(TestUnitBase):

    def test_doubly_encoded_script(self):
        unit = self.load()
        data = bytes.fromhex(
            '65 78 65 63 5F 73 63 72 69 70 74 28 22 23 40 7E 5E 4E 41 45 41 41 41 3D'
            '3D 40 23 40 26 4E 47 31 45 73 2B 78 44 52 53 2E 6B 44 2B 63 4A 40 21 2F'
            '5E 2E 72 5F 4A 62 32 59 2C 56 6C 09 4C 3B 6C 54 2B 7B 42 42 3F 5E 2E 62'
            '77 4F 52 41 55 6D 4B 4E 6E 76 40 2A 61 40 24 3D 3F 48 6F 29 62 7A 29 7B'
            '5C 27 09 65 36 25 66 33 6E 36 68 57 09 30 78 61 2C 23 69 39 3F 5B 3D 44'
            '2B 7C 32 74 2F 6E 50 76 4B 44 41 55 21 4F 4B 64 73 52 30 53 2F 66 71 20'
            '49 73 20 41 25 33 52 4E 38 09 58 50 34 3A 49 3F 44 5C 5C 5C 27 44 67 76'
            '62 6E 5E 4F 5C 22 74 79 43 34 4B 48 33 72 33 5C 5C 58 71 69 74 23 6E 50'
            '55 32 74 23 5D 48 09 20 6A 3A 68 51 7C 5C 27 20 5C 5C 5C 27 4B 3F 33 4F'
            '45 5C 5C 42 4D 62 4F 5A 5C 5C 4B 49 5A 20 4B 33 36 50 33 36 74 6E 58 7E'
            '39 46 56 47 53 68 28 37 60 7C 57 5D 4B 60 68 6A 78 55 4B 3B 6B 5A 57 2F'
            '7C 3A 77 79 44 73 75 09 60 4A 7E 4A 52 3F 09 7E 33 7B 65 52 23 66 78 5C'
            '5C 71 2E 72 33 4F 2F 37 23 36 5E 48 4A 2F 35 73 33 35 74 61 62 62 31 60'
            '48 29 62 7A 5C 27 78 3F 5B 55 40 24 40 21 26 2F 31 44 4A 33 45 72 77 44'
            '40 2A 72 23 49 40 23 40 26 4D 46 38 41 41 41 3D 3D 5E 23 7E 40 22 29 3B'
        )
        step0 = self.ldu('carve', '-sd', 'string')(data)
        step1 = unit(step0)
        self.assertIn(B'JScript.Encode', step1)
        step2 = unit(step1)
        self.assertIn(B'var pic_obj = new Image();', step2)

    def test_invertible(self):

        def binarystring(c):
            return getdoc(c).encode('utf8')

        @binarystring
        class sample:
            R"""
            set FSO = CreateObject("Scripting.FileSystemObject")

            function backupDriveReady(letter)
                backupDriveReady = False
                for each drive in FSO.Drives
                    if LCase(drive.DriveLetter) = LCase(letter) then
                        backupDriveReady = True
                        exit for
                    end if
                next
            end function

            if backupDriveReady("d") then
                BackupScript = FSO.GetParentFolderName(WScript.ScriptFullName) + "\backup.ps1"
                set shell = CreateObject("Wscript.Shell")
                shell.CurrentDirectory = "C:\Workspace"
                Command = "powershell " & BackupScript & " ."
                shell.Run Command, 0
            else
                WScript.Echo("An error occurred during backup: Drive D: is not ready!")
            end if
            """

        E = self.load(reverse=True)
        D = self.load()

        self.assertEqual(sample, D(E(sample)))
