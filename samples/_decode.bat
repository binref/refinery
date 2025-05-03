@echo off
if "%2"=="" (set key=REFINERYTESTDATA) else (set key=%2)
emit "%1" [| aes -mCBC %key% | dump -t {sha256} | cfmt {sha256} ]]
