# Binary Refinery
[![Build Status](https://img.shields.io/travis/binref/refinery?style=for-the-badge)][travis]
[![Code Coverage](https://img.shields.io/codecov/c/github/binref/refinery?style=for-the-badge)][codecov]
[![PyPi Versions](https://img.shields.io/pypi/pyversions/binary-refinery?style=for-the-badge)][pypi]
[![PyPi Wheel](https://img.shields.io/pypi/wheel/binary-refinery?style=for-the-badge)][pypi]
[![Documentation](https://img.shields.io/badge/docs-super%20retro-red?style=for-the-badge&logo=Python&logoColor=white)][docs]
```
  __     __  High Octane Triage Analysis          __
  ||    _||______ __       __________     _____   ||
  ||    \||___   \__| ____/   ______/___ / ____\  ||
==||=====||  | __/  |/    \  /==|  / __ \   __\===]|
  '======||  |   \  |   |  \_  _| \  ___/|  |     ||
         ||____  /__|___|__/  / |  \____]|  |     ||
=========''====\/=========/  /==|__|=====|__|======'
                         \  /
                          \/
```
The Binary Refinery&trade; is a collection of Python scripts that implement transformations of binary data such as compression and encryption. We will often refer to it simply by _refinery_, which is also the name of the corresponding package. The scripts are designed to exclusively read input from stdin and write output to stdout. This way, the individual units can be chained with the piping operator `|` on the commandline to perform more complex tasks. The project was born to aid with malware triage, and is an attempt to implement something like [CyberChef](https://github.com/gchq/CyberChef) on the commandline.

The main philosophy of the refinery is that every script should be a unit in the sense that it does _one_ job. It is always a case by case decision, but it is generally desirable to reduce the number of possible arguments of each script to a minimum and prefer strong capsulation if some functionality could be provided by a separate unit.

### License

The Binary Refinery is (c) 2019 Jesko Hüttenhain, and published under a [Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International License][license]. This repository also contains [a copy of the full license text](LICENSE). If you want to do something with it that's not covered by this license, please feel free to contact the author.

### Installing the Refinery

The refinery requires at least **Python 3.6**, and **Python 3.7** is thoroughly recommended. Since binary refinery introduces a large number of new commands, there is a good chance that some of these will clash on some systems. Therefore, you have the option to choose a _prefix_ for the installation, which will be put in front of every command shim that is installed. For example, if you choose `r.` as your prefix, then the [emit](refinery/emit.py) command would be `r.emit` in your terminal. An added benefit is that you can type `r.` and hammer <kbd>Tab</kbd> twice to get a list of all available refinery commands.

Note however that no prefix is assumed in documentation and it is a development goal of refinery to _not_ clash on most systems. The author does not use a prefix and provides this option as a safety blanket.

### Automated Installation

You can either install refinery manually (see below) or use the automated installer script, which creates a virtual environment and installs the refinery package to that virtual environment. To do so, simply run [setup-venv.py](setup-venv.py) using the interpreter on your system which you would like to use for refinery. The script will create a virtual environment cloned from that interpreter version and install the binary refinery package into that virtual environment. On Windows, it also adds the `Scripts` directory of that virtual environment to your `PATH`, so all commands become available on the command line. The syntax for the script is as follows:
```
./setup-venv.py [--wheel] [--prefix pr] [folder]
```
The optional argument `folder` specifies the folder where the virtual Python environment is created, the default is `venv`. The optional value given by `--prefix` is the prefix (see above). Finally, the `--wheel` option will install the refinery package as a wheel, which may have some performance benefits. If this option is omitted, refinery is installed as an editable package, which means that any source code modifications in the repository will immediately take effect.

Some known issues arise when [setup-venv.py](setup-venv.py) is instructed to create the virtual environment in a location which already contains a virtual environment that was created by other means. As a workaround for these issues, don't do that, i.e. simply delete the virtual environment and use [setup-venv.py](setup-venv.py) to re-create it.

### Manual Installation

To install refinery manually, simply set the environment variable `REFINERY_PREFIX` to the prefix you want and use pip. For example:
```
REFINERY_PREFIX=r. pip3 install -e binary-refinery
```
to install refinery into the current Python environment with prefix `r.`.

### Updating

To update refinery, it is sufficient to pull the repository and run [setup-venv.py](setup-venv.py) again with the same arguments after pulling the repository. If you installed refinery manually, you should first run `pip uninstall binary-refinery` and then install the package again. The uninstall is a safeguard to make sure that potentially deprecated command shims are removed before installing the new version. If you are using a virtual environment, you can always just remove the entire directory and install again, of course.

### Generating Documentation

The documentation [is available online][docs], but you can also generate it locally. To do so, execute the [run-pdoc3.py](run-pdoc3.py) script. This will **fail** unless you run it from an environment where binary refinery has been installed as a Python package. To run it, you have to specify the path of a virtual environment as the first command line argument to [run-pdoc3.py](run-pdoc3.py), which will cause the script to run itself again using the interpreter of that environment. If you are certain that you want to run [run-pdoc3.py](run-pdoc3.py), there is a command line switch to force the script to run with the current default Python interpreter. The script installs the [pdoc3 package][pdoc3] and uses it to generate a HTML documentation for the `refinery` package. The documentation can then be found in the subdirectory `html` directly next to this readme file.

### Simple Examples

The units [emit][] and [dump][] play a special role: The former is for outputting data while the latter is for dumping data to the clipboard or to disk. As an example, consider the following pipeline:
```
emit M7EwMzVzBkI3IwNTczM3cyMg2wQA | b64 | zl | hex 
```
Here, we emit the string `M7EwMzVzBkI3IwNTczM3cyMg2wQA`, base64-decode it using [b64][], zlib-decompress the result using [zl][], and finally [hex][]-decode the decompressed data. Each unit performs the _"decoding"_ operation of a certain transformation by default, but some of them also implement the reverse operation. If they do, this is always done by providing the command line switch `-R`, or `--reverse`. You can produce the above base64 string using the following command because [hex][], [zl][], and [b64][] all provide the reverse operation:
```
emit "Hello World" | hex -R | zl -R | b64 -R
```

Given a file `packed.bin` containing a base64 encoded payload buffer, the following pipeline extracts said payload to `payload.bin`:
```
emit packed.bin | carve -l -p1 b64 | b64 | dump payload.bin
```
The [carve][] unit can be used to carve blocks of data out of the input buffer, in this case it looks for base64 encoded data, sorts them by length (`-l`) and returns the first of these (`-p1`), which carves the largest base64-looking chunk of data from `packed.bin`. The data is then base64-decoded and dumped to the file `payload.bin`. 

The unit [pack][], will pick all numeric expressions from a text buffer and turn them into their binary representation. A simple example is the pipeline
```
emit "0xBA 0xAD 0xC0 0xFF 0xEE" | pack | hex -R 
```
which will output the string `BAADC0FFEE`.


### Additional Information

A complete reference of all units is [available on the front page of the documentation][docs]. It is recommended to study the [documentation on the argument syntax][argformats] as well as [framed syntax][frame] to unleash the full power of the refinery.

## Examples

### AES Encryption

Assume that `data` is a file which was encrypted with 256 bit AES in CBC mode. The key was derived from the secret passphrase `swordfish` using the PBKDF2 key derivation routine using the salt `s4lty`. The IV is prefixed to the buffer as the first 16 bytes. It can be decrypted with the following pipeline:
```
emit data | aes CBC  --iv cut::16 PBKDF2[32,s4lty]:swordfish
```
Here, both `cut:0:16` and `PBKDF2[32,s4lty]:swordfish` are multibin arguments that use a special handler. In this case, `cut:0:16` extracts the slice `0:16` (i.e. the first 16 bytes) from the input data - after application of this multibin handler, the input data has the first 16 bytes removed and the argument `iv` is set to these exact 16 bytes. The final argument specifies the 32 byte encryption key: The handler `PBKDF2[32,s4lty]` on the other hand instructs refinery to create an instance of the PBKDF2 unit as if it had been given the command line parameters `32` and `s4lty` in this order and process the byte string `swordfish` with this unit. As a simple test, the following pipeline will encrypt and decrypt a sample piece of text:
```
emit "Once upon a time, at the foot of a great mountain ..." ^
    | aes CBC PBKDF2[32,s4lty]:swordfish --iv md5:X -R | ccp md5:X ^
    | aes CBC PBKDF2[32,s4lty]:swordfish --iv cut:0:16 
```

### Grab Bag of Examples

Extract indicators from all files recursively enumerated inside the current directory:
```
fread ./**/* [| xtp -qn6 ipv4 socket url email | dedup ]]
```
Convert the hard-coded IP address `0xC0A80C2A` in network byte order to a readable format:
```
emit 0xC0A80C2A | pack -NB4 | pack -R [| sep . ]
```
Extract the PowerShell payload from [a malicious XLS macro dropper](https://malshare.com/sample.php?action=detail&hash=c5e1106f9654a23320132cbc61b3f29d):
```
emit MIL0001781108.xls            \
[| xlxtr 9.5:11.5 15.15 12.5:14.5 \
 [| scope -n 3                    \
  | chop -t 5                     \
  [| sorted                       \
   | snip 2:                      \
   | sep                          \
  ]                               \
  | pack 10                       \
  | sub dec:ev:n                  \
]]                                \
| dump payload.ps1
```
And get the domains for the next stage:
```
emit payload.ps1 | carve-b64z | deob-ps1 | carve-b64z | deob-ps1 | xtp domain
```
Exctract the configuration of [unpacked HawkEye samples](https://malshare.com/sample.php?action=detail&hash=30ae8004a14f188d40c024124022d63d):
```
emit 30ae8004a14f188d40c024124022d63d                \
[| xtp guid                                          \
 | PBKDF2 48 rep[8]:H:00                             \
 | cca perc[RCDATA]:30ae8004a14f188d40c024124022d63d \
 | aes -Q CBC x::32 --iv x::16                       \
]                                                    \
| dnds
```


[pdoc3]: https://pdoc3.github.io/pdoc/
[docs]: https://binref.github.io/
[argformats]: https://binref.github.io/lib/argformats.html
[frame]: https://binref.github.io/lib/frame.html
[license]: https://creativecommons.org/licenses/by-nc-nd/4.0/legalcode
[travis]: https://travis-ci.org/binref/refinery
[codecov]: https://codecov.io/github/binref/refinery/?branch=master
[pypi]: https://pypi.org/project/binary-refinery/

[dump]: https://binref.github.io/#refinery.dump
[emit]: https://binref.github.io/#refinery.emit
[hex]: https://binref.github.io/#refinery.hex
[zl]: https://binref.github.io/#refinery.zl
[b64]: https://binref.github.io/#refinery.b64
[carve]: https://binref.github.io/#refinery.carve
[pack]: https://binref.github.io/#refinery.pack