# The Refinery Files

### [Volume 1 — NetWalker Dropper][0x01]

Extract a NetWalker sample and its configuration from a PowerShell loader.
The tutorial touches on all fundamental binary refinery concepts.

### [Volume 2 — Amadey Loader Strings][0x02]

A short tutorial extracting the strings (including C2 configuration) of an Amadey Loader sample.
Revisits most of the concepts that were introduced in the tutorial.

### [Volume 3 — SedUpLoader C2s][0x03]

In this tutorial, we extract the C2 configuration from a SedUpLoader sample.
The tutorial introduces the push/pop mechanic,
which is used to first extract a decryption key,
store it as a variable,
continue to extract the C2 data,
and then decrypt the C2 domains using the stored key.

### [Volume 4 — Run Length Encoding][0x04]

A short tutorial about a loader using a custom run-length encoding.
It showcases how to define custom refinery units when it would be too difficult to implement a decoding step using existing units.

### [Volume 5 — FlareOn 9][0x05]

This is a refinery-focused write-up of how to solve FlareOn9.

### [Volume 6 — Qakbot Config Decoder][0x06]

A refinery pipeline that can extract the C2 IP addresses from Qakbot samples.

### [Volume 7 — Unpacking a DCRat Sample][0x07]

Another showcase of writing custom units for very specific tasks, in this case reproducing the logic of a .NET packer.

### [Volume 8 — FlareOn 10][0x08]

This is a refinery-focused write-up of how to solve FlareOn10.

### [Volume 9 — Layer Cake][0x09]

The tutorial goes through several layers of a multi-stage downloader.
It illustrates the use of path extraction units and features some steganography.


[0x01]: notebooks/tbr-files.v0x01.netwalker.dropper.ipynb
[0x02]: notebooks/tbr-files.v0x02.amadey.loader.ipynb
[0x03]: notebooks/tbr-files.v0x03.seduploader.ipynb
[0x04]: notebooks/tbr-files.v0x04.run.length.encoding.ipynb
[0x05]: notebooks/tbr-files.v0x05.flare.on.9.ipynb
[0x06]: notebooks/tbr-files.v0x06.qakbot.decoder.ipynb
[0x07]: notebooks/tbr-files.v0x07.dc.rat.ipynb
[0x08]: notebooks/tbr-files.v0x08.flare.on.10.ipynb
[0x09]: notebooks/tbr-files.v0x09.exploit.document.ipynb