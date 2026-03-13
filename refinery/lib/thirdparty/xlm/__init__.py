# Copyright 2020 Amirreza Niakanlahiji
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Original project: XLMMacroDeobfuscator
#   https://github.com/DissectMalware/XLMMacroDeobfuscator
#
# Ported into Binary Refinery with modifications:
# - Replaced lark-parser with a hand-rolled recursive descent parser
# - Replaced untangle with defusedxml.ElementTree
# - Replaced msoffcrypto-tool decryption (handled by refinery's OLE crypto)
# - Replaced roman dependency with inline implementation
# - Inlined .conf file data as Python dicts
# - Dropped Win32 COM wrapper, CLI, interactive shell, JSON export
"""
Inlined port of XLMMacroDeobfuscator for Excel 4.0 (XLM) macro deobfuscation.
"""
