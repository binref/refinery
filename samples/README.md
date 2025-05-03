# Binary Refinery Test Data

The files in this directory are samples used for unit tests. As many of the samples are **malware**, they
have been encrypted. Please take all necessary precautions when dealing with these files, they might be
dangerous to your device.
Most samples can be decrypted using AES-128/CBC, using the key `REFINERYTESTDATA` and an all-zero IV. For
example, using binary refinery itself:
```
emit ee790d6f09c2292d457cbe92729937e06b3e21eb6b212bf2e32386ba7c2ff22c.enc \
  | aes --mode=cbc REFINERYTESTDATA \
  | dump ee790d6f09c2292d457cbe92729937e06b3e21eb6b212bf2e32386ba7c2ff22c
```
