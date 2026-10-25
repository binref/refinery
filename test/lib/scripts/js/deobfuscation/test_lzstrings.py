"""
Programs that keep their strings compressed with the lz-string library: the minified build of the
library is inserted whole, and one call of its `decompressFromUTF16` with a string literal gives
every string of the program, joined. `refinery.djs` replaces that call by the string it returns
where the name holds the object the library builds, nothing changes that object before the call, and
the built-ins the library reads are the language's when it is built and when the call runs.

`COMPRESSED("...")` in a program stands for the string literal the library's `compressToUTF16`
makes of the text, which the library makes in Node when the test runs.
"""
from __future__ import annotations

import inspect
import json
import re
import unittest

from typing import Mapping

from test import TestBase
from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.ledger import (
    NL,
    FileProgram,
    Reading,
    each_reading_still_prints,
    node_prints_what_each_row_pins,
    prints,
    wontfix,
)

from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.units.scripting.djs import djs

#: The function of the minified build of lz-string 1.5.0, copyright (c) 2013 pieroxy, MIT license,
#: as the package ships it in `libs/lz-string.min.js`; a call of it builds the library object.
LIBRARY = (
    'function(){var r=String.fromCharCode,o="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123'
    '456789+/=",n="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-$",e={};function t'
    '(r,o){if(!e[r]){e[r]={};for(var n=0;n<r.length;n++)e[r][r.charAt(n)]=n}return e[r][o]}var i={com'
    'pressToBase64:function(r){if(null==r)return"";var n=i._compress(r,6,function(r){return o.charAt('
    'r)});switch(n.length%4){default:case 0:return n;case 1:return n+"===";case 2:return n+"==";case '
    '3:return n+"="}},decompressFromBase64:function(r){return null==r?"":""==r?null:i._decompress(r.l'
    'ength,32,function(n){return t(o,r.charAt(n))})},compressToUTF16:function(o){return null==o?"":i.'
    '_compress(o,15,function(o){return r(o+32)})+" "},decompressFromUTF16:function(r){return null==r?'
    '"":""==r?null:i._decompress(r.length,16384,function(o){return r.charCodeAt(o)-32})},compressToUi'
    'nt8Array:function(r){for(var o=i.compress(r),n=new Uint8Array(2*o.length),e=0,t=o.length;e<t;e++'
    '){var s=o.charCodeAt(e);n[2*e]=s>>>8,n[2*e+1]=s%256}return n},decompressFromUint8Array:function('
    'o){if(null==o)return i.decompress(o);for(var n=new Array(o.length/2),e=0,t=n.length;e<t;e++)n[e]'
    '=256*o[2*e]+o[2*e+1];var s=[];return n.forEach(function(o){s.push(r(o))}),i.decompress(s.join(""'
    '))},compressToEncodedURIComponent:function(r){return null==r?"":i._compress(r,6,function(r){retu'
    'rn n.charAt(r)})},decompressFromEncodedURIComponent:function(r){return null==r?"":""==r?null:(r='
    'r.replace(/ /g,"+"),i._decompress(r.length,32,function(o){return t(n,r.charAt(o))}))},compress:f'
    'unction(o){return i._compress(o,16,function(o){return r(o)})},_compress:function(r,o,n){if(null='
    '=r)return"";var e,t,i,s={},u={},a="",p="",c="",l=2,f=3,h=2,d=[],m=0,v=0;for(i=0;i<r.length;i+=1)'
    'if(a=r.charAt(i),Object.prototype.hasOwnProperty.call(s,a)||(s[a]=f++,u[a]=!0),p=c+a,Object.prot'
    'otype.hasOwnProperty.call(s,p))c=p;else{if(Object.prototype.hasOwnProperty.call(u,c)){if(c.charC'
    'odeAt(0)<256){for(e=0;e<h;e++)m<<=1,v==o-1?(v=0,d.push(n(m)),m=0):v++;for(t=c.charCodeAt(0),e=0;'
    'e<8;e++)m=m<<1|1&t,v==o-1?(v=0,d.push(n(m)),m=0):v++,t>>=1}else{for(t=1,e=0;e<h;e++)m=m<<1|t,v=='
    'o-1?(v=0,d.push(n(m)),m=0):v++,t=0;for(t=c.charCodeAt(0),e=0;e<16;e++)m=m<<1|1&t,v==o-1?(v=0,d.p'
    'ush(n(m)),m=0):v++,t>>=1}0==--l&&(l=Math.pow(2,h),h++),delete u[c]}else for(t=s[c],e=0;e<h;e++)m'
    '=m<<1|1&t,v==o-1?(v=0,d.push(n(m)),m=0):v++,t>>=1;0==--l&&(l=Math.pow(2,h),h++),s[p]=f++,c=Strin'
    'g(a)}if(""!==c){if(Object.prototype.hasOwnProperty.call(u,c)){if(c.charCodeAt(0)<256){for(e=0;e<'
    'h;e++)m<<=1,v==o-1?(v=0,d.push(n(m)),m=0):v++;for(t=c.charCodeAt(0),e=0;e<8;e++)m=m<<1|1&t,v==o-'
    '1?(v=0,d.push(n(m)),m=0):v++,t>>=1}else{for(t=1,e=0;e<h;e++)m=m<<1|t,v==o-1?(v=0,d.push(n(m)),m='
    '0):v++,t=0;for(t=c.charCodeAt(0),e=0;e<16;e++)m=m<<1|1&t,v==o-1?(v=0,d.push(n(m)),m=0):v++,t>>=1'
    '}0==--l&&(l=Math.pow(2,h),h++),delete u[c]}else for(t=s[c],e=0;e<h;e++)m=m<<1|1&t,v==o-1?(v=0,d.'
    'push(n(m)),m=0):v++,t>>=1;0==--l&&(l=Math.pow(2,h),h++)}for(t=2,e=0;e<h;e++)m=m<<1|1&t,v==o-1?(v'
    '=0,d.push(n(m)),m=0):v++,t>>=1;for(;;){if(m<<=1,v==o-1){d.push(n(m));break}v++}return d.join("")'
    '},decompress:function(r){return null==r?"":""==r?null:i._decompress(r.length,32768,function(o){r'
    'eturn r.charCodeAt(o)})},_decompress:function(o,n,e){var t,i,s,u,a,p,c,l=[],f=4,h=4,d=3,m="",v=['
    '],g={val:e(0),position:n,index:1};for(t=0;t<3;t+=1)l[t]=t;for(s=0,a=Math.pow(2,2),p=1;p!=a;)u=g.'
    'val&g.position,g.position>>=1,0==g.position&&(g.position=n,g.val=e(g.index++)),s|=(u>0?1:0)*p,p<'
    '<=1;switch(s){case 0:for(s=0,a=Math.pow(2,8),p=1;p!=a;)u=g.val&g.position,g.position>>=1,0==g.po'
    'sition&&(g.position=n,g.val=e(g.index++)),s|=(u>0?1:0)*p,p<<=1;c=r(s);break;case 1:for(s=0,a=Mat'
    'h.pow(2,16),p=1;p!=a;)u=g.val&g.position,g.position>>=1,0==g.position&&(g.position=n,g.val=e(g.i'
    'ndex++)),s|=(u>0?1:0)*p,p<<=1;c=r(s);break;case 2:return""}for(l[3]=c,i=c,v.push(c);;){if(g.inde'
    'x>o)return"";for(s=0,a=Math.pow(2,d),p=1;p!=a;)u=g.val&g.position,g.position>>=1,0==g.position&&'
    '(g.position=n,g.val=e(g.index++)),s|=(u>0?1:0)*p,p<<=1;switch(c=s){case 0:for(s=0,a=Math.pow(2,8'
    '),p=1;p!=a;)u=g.val&g.position,g.position>>=1,0==g.position&&(g.position=n,g.val=e(g.index++)),s'
    '|=(u>0?1:0)*p,p<<=1;l[h++]=r(s),c=h-1,f--;break;case 1:for(s=0,a=Math.pow(2,16),p=1;p!=a;)u=g.va'
    'l&g.position,g.position>>=1,0==g.position&&(g.position=n,g.val=e(g.index++)),s|=(u>0?1:0)*p,p<<='
    '1;l[h++]=r(s),c=h-1,f--;break;case 2:return v.join("")}if(0==f&&(f=Math.pow(2,d),d++),l[c])m=l[c'
    '];else{if(c!==h)return null;m=i+i.charAt(0)}v.push(m),l[h++]=i+m.charAt(0),i=m,0==--f&&(f=Math.p'
    'ow(2,d),d++)}}};return i}'
)

#: The library built and held by a name, as it is inserted into a program.
LIB = F'var L={LIBRARY}();'

#: The line the build is shipped with, which hands the library to a module loader where one is
#: present: an AMD `define`, the `module` of a CommonJS file, or AngularJS.
TAIL = (
    '"function"==typeof define&&define.amd?define(function(){return L}):"undefined"!=typeof module&&null!=module?'
    'module.exports=L:"undefined"!=typeof angular&&null!=angular&&angular.module("LZString",[]).factory("LZString",'
    'function(){return L});'
)

#: The accessor over the strings: one call decompresses all of them, joined by `|`.
TEMPLATE = (
    'var SC;(function(){var compressedString=COMPRESSED("line|column|name|BrainfuckError|located|toString| at line |, '
    'column |freeze|ADD|add|MOVE|move");'
    'var utf8String=L["decompressFromUTF16"](compressedString);var stringArray=utf8String["split"]("|");'
    'SC=function(index){return stringArray[index]}})();'
)

#: Reads of strings through the accessor, at the top of the file and in a function.
USE = 'console.log(SC(0), SC(3), SC(6) + SC(12)); function f() { return SC(9); } console.log(f());'

#: A text whose repeats the library compresses into references to its own earlier parts.
FOX = 'the quick brown fox jumps over the lazy dog|' * 30

#: A file written beside the program that installs an AMD loader, whose `define` writes the object
#: it is handed.
AMD_LOADER_BESIDE = (
    'require("fs").writeFileSync(require("path").join(__dirname, "amd.js"), "global.define = function (f) { '
    'f()._decompress = function () { return 1; }; }; global.define.amd = true;");'
)

#: A program an obfuscator compressed the strings of, as it wrote it: the library under a generated
#: name, its export line, and the accessor in front of an eleven-line fizzbuzz.
STRINGS_COMPRESSED = (
    r'var ZvYyC4L=function(){var r=String.fromCharCode,o="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr'
    r'stuvwxyz0123456789+/=",n="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-$",e={'
    r'};function t(r,o){if(!e[r]){e[r]={};for(var n=0;n<r.length;n++)e[r][r.charAt(n)]=n}return e[r][o'
    r']}var i={compressToBase64:function(r){if(null==r)return"";var n=i._compress(r,6,function(r){retu'
    r'rn o.charAt(r)});switch(n.length%4){default:case 0:return n;case 1:return n+"===";case 2:return '
    r'n+"==";case 3:return n+"="}},decompressFromBase64:function(r){return null==r?"":""==r?null:i._de'
    r'compress(r.length,32,function(n){return t(o,r.charAt(n))})},compressToUTF16:function(o){return n'
    r'ull==o?"":i._compress(o,15,function(o){return r(o+32)})+" "},decompressFromUTF16:function(r){ret'
    r'urn null==r?"":""==r?null:i._decompress(r.length,16384,function(o){return r.charCodeAt(o)-32})},'
    r'compressToUint8Array:function(r){for(var o=i.compress(r),n=new Uint8Array(2*o.length),e=0,t=o.le'
    r'ngth;e<t;e++){var s=o.charCodeAt(e);n[2*e]=s>>>8,n[2*e+1]=s%256}return n},decompressFromUint8Arr'
    r'ay:function(o){if(null==o)return i.decompress(o);for(var n=new Array(o.length/2),e=0,t=n.length;'
    r'e<t;e++)n[e]=256*o[2*e]+o[2*e+1];var s=[];return n.forEach(function(o){s.push(r(o))}),i.decompre'
    r'ss(s.join(""))},compressToEncodedURIComponent:function(r){return null==r?"":i._compress(r,6,func'
    r'tion(r){return n.charAt(r)})},decompressFromEncodedURIComponent:function(r){return null==r?"":""'
    r'==r?null:(r=r.replace(/ /g,"+"),i._decompress(r.length,32,function(o){return t(n,r.charAt(o))}))'
    r'},compress:function(o){return i._compress(o,16,function(o){return r(o)})},_compress:function(r,o'
    r',n){if(null==r)return"";var e,t,i,s={},u={},a="",p="",c="",l=2,f=3,h=2,d=[],m=0,v=0;for(i=0;i<r.'
    r'length;i+=1)if(a=r.charAt(i),Object.prototype.hasOwnProperty.call(s,a)||(s[a]=f++,u[a]=!0),p=c+a'
    r',Object.prototype.hasOwnProperty.call(s,p))c=p;else{if(Object.prototype.hasOwnProperty.call(u,c)'
    r'){if(c.charCodeAt(0)<256){for(e=0;e<h;e++)m<<=1,v==o-1?(v=0,d.push(n(m)),m=0):v++;for(t=c.charCo'
    r'deAt(0),e=0;e<8;e++)m=m<<1|1&t,v==o-1?(v=0,d.push(n(m)),m=0):v++,t>>=1}else{for(t=1,e=0;e<h;e++)'
    r'm=m<<1|t,v==o-1?(v=0,d.push(n(m)),m=0):v++,t=0;for(t=c.charCodeAt(0),e=0;e<16;e++)m=m<<1|1&t,v=='
    r'o-1?(v=0,d.push(n(m)),m=0):v++,t>>=1}0==--l&&(l=Math.pow(2,h),h++),delete u[c]}else for(t=s[c],e'
    r'=0;e<h;e++)m=m<<1|1&t,v==o-1?(v=0,d.push(n(m)),m=0):v++,t>>=1;0==--l&&(l=Math.pow(2,h),h++),s[p]'
    r'=f++,c=String(a)}if(""!==c){if(Object.prototype.hasOwnProperty.call(u,c)){if(c.charCodeAt(0)<256'
    r'){for(e=0;e<h;e++)m<<=1,v==o-1?(v=0,d.push(n(m)),m=0):v++;for(t=c.charCodeAt(0),e=0;e<8;e++)m=m<'
    r'<1|1&t,v==o-1?(v=0,d.push(n(m)),m=0):v++,t>>=1}else{for(t=1,e=0;e<h;e++)m=m<<1|t,v==o-1?(v=0,d.p'
    r'ush(n(m)),m=0):v++,t=0;for(t=c.charCodeAt(0),e=0;e<16;e++)m=m<<1|1&t,v==o-1?(v=0,d.push(n(m)),m='
    r'0):v++,t>>=1}0==--l&&(l=Math.pow(2,h),h++),delete u[c]}else for(t=s[c],e=0;e<h;e++)m=m<<1|1&t,v='
    r'=o-1?(v=0,d.push(n(m)),m=0):v++,t>>=1;0==--l&&(l=Math.pow(2,h),h++)}for(t=2,e=0;e<h;e++)m=m<<1|1'
    r'&t,v==o-1?(v=0,d.push(n(m)),m=0):v++,t>>=1;for(;;){if(m<<=1,v==o-1){d.push(n(m));break}v++}retur'
    r'n d.join("")},decompress:function(r){return null==r?"":""==r?null:i._decompress(r.length,32768,f'
    r'unction(o){return r.charCodeAt(o)})},_decompress:function(o,n,e){var t,i,s,u,a,p,c,l=[],f=4,h=4,'
    r'd=3,m="",v=[],g={val:e(0),position:n,index:1};for(t=0;t<3;t+=1)l[t]=t;for(s=0,a=Math.pow(2,2),p='
    r'1;p!=a;)u=g.val&g.position,g.position>>=1,0==g.position&&(g.position=n,g.val=e(g.index++)),s|=(u'
    r'>0?1:0)*p,p<<=1;switch(s){case 0:for(s=0,a=Math.pow(2,8),p=1;p!=a;)u=g.val&g.position,g.position'
    r'>>=1,0==g.position&&(g.position=n,g.val=e(g.index++)),s|=(u>0?1:0)*p,p<<=1;c=r(s);break;case 1:f'
    r'or(s=0,a=Math.pow(2,16),p=1;p!=a;)u=g.val&g.position,g.position>>=1,0==g.position&&(g.position=n'
    r',g.val=e(g.index++)),s|=(u>0?1:0)*p,p<<=1;c=r(s);break;case 2:return""}for(l[3]=c,i=c,v.push(c);'
    r';){if(g.index>o)return"";for(s=0,a=Math.pow(2,d),p=1;p!=a;)u=g.val&g.position,g.position>>=1,0=='
    r'g.position&&(g.position=n,g.val=e(g.index++)),s|=(u>0?1:0)*p,p<<=1;switch(c=s){case 0:for(s=0,a='
    r'Math.pow(2,8),p=1;p!=a;)u=g.val&g.position,g.position>>=1,0==g.position&&(g.position=n,g.val=e(g'
    r'.index++)),s|=(u>0?1:0)*p,p<<=1;l[h++]=r(s),c=h-1,f--;break;case 1:for(s=0,a=Math.pow(2,16),p=1;'
    r'p!=a;)u=g.val&g.position,g.position>>=1,0==g.position&&(g.position=n,g.val=e(g.index++)),s|=(u>0'
    r'?1:0)*p,p<<=1;l[h++]=r(s),c=h-1,f--;break;case 2:return v.join("")}if(0==f&&(f=Math.pow(2,d),d++'
    r'),l[c])m=l[c];else{if(c!==h)return null;m=i+i.charAt(0)}v.push(m),l[h++]=i+m.charAt(0),i=m,0==--'
    r'f&&(f=Math.pow(2,d),d++)}}};return i}();"function"==typeof define&&define.amd?define(function(){'
    r'return ZvYyC4L}):"undefined"!=typeof module&&null!=module?module.exports=ZvYyC4L:"undefined"!=ty'
    r'peof angular&&null!=angular&&angular.module("LZString",[]).factory("LZString",function(){return '
    r'ZvYyC4L});var __p_2ibP_SC;(function(){var compressedString="\u0C62\u2C37\u4C27\u6062\u0590\u6420'
    r'\u75A1\u4E20\u5A60\u2B23\u6C60\u1DC4\x8D\u582E\u34B4\u0490\u202B\u4021\u0820 ";var utf8String=Zv'
    r'YyC4L["decompressFromUTF16"](compressedString);var stringArray=utf8String["split"]("|");__p_2ibP'
    r'_SC=function(index){return stringArray[index]}})();function fizzbuzz(limit){var lines=[];for(var'
    r' i=1;i<=limit;i++){var line="";if(i%3===0){line+=__p_2ibP_SC(0)}if(i%5===0){line+=__p_2ibP_SC(1)'
    r'}lines[__p_2ibP_SC(2)](line||String(i))}return lines[__p_2ibP_SC(3)](", ")}console[__p_2ibP_SC(4'
    r')](__p_2ibP_SC(5)+fizzbuzz(15));'
)

#: The one line the program prints, as `refinery.djs` recovers it.
FIZZBUZZ_PRINTED = (
    "console.log('FizzBuzz: 1, 2, Fizz, 4, Buzz, Fizz, 7, 8, Fizz, Buzz, 11, Fizz, 13, 14, FizzBuzz');"
)

_COMPRESSED = re.compile(r'COMPRESSED\(("(?:[^"\\]|\\.)*")\)')


def _compressed_by_the_library(texts: tuple[str, ...]) -> dict[str, str]:
    """
    The string literal Node prints for what the library's `compressToUTF16` makes of each of
    *texts*, one to a line.
    """
    calls = ''.join(F'console.log(JSON.stringify(L.compressToUTF16({json.dumps(text)})));' for text in texts)
    out, error = behavior(F'var L = {LIBRARY}(); {calls}')
    assert error is None, error
    literals = out.split(NL)[:-1]
    assert len(literals) == len(texts)
    return dict(zip(texts, literals))


def with_compressed_strings(rows: Mapping[str, FileProgram]) -> dict[str, FileProgram]:
    """
    *rows* with every `COMPRESSED("...")` replaced by the string literal the library makes of it.
    """
    texts = tuple(sorted({json.loads(match.group(1)) for row in rows.values() for match in _COMPRESSED.finditer(row.text)}))
    literals = _compressed_by_the_library(texts)
    return {
        label: row._replace(text=_COMPRESSED.sub(lambda match: literals[json.loads(match.group(1))], row.text))
        for label, row in rows.items()
    }


#: Programs that build the library and decompress strings with it, some after or while they change
#: the object or the built-ins it reads, each with what Node makes of it as a CommonJS file and as an
#: ES module.
A_PROGRAM_DECOMPRESSING_ITS_STRINGS = {
    'the inserted shape: library, its export line, the accessor': FileProgram(
        LIB + TAIL + TEMPLATE + USE,
        prints('line BrainfuckError  at line move', 'ADD'),
        prints('line BrainfuckError  at line move', 'ADD'),
        HostEnvironment.node,
    ),
    'a decompression read back directly': FileProgram(
        LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("a|bb|ccc|a|bb|ccc|abcabcabc"))));',
        prints('"a|bb|ccc|a|bb|ccc|abcabcabc"'),
        prints('"a|bb|ccc|a|bb|ccc|abcabcabc"'),
        HostEnvironment.node,
    ),
    'a string the dictionary cannot hold decompresses to null': FileProgram(
        LIB + 'console.log(L.decompressFromUTF16("\\u4e00\\u4e01\\u4e02"));',
        prints('null'),
        prints('null'),
        HostEnvironment.node,
    ),
    'the empty string decompresses to null': FileProgram(
        LIB + 'console.log(L.decompressFromUTF16(""));',
        prints('null'),
        prints('null'),
        HostEnvironment.node,
    ),
    'a first code the library has no case for': FileProgram(
        LIB + 'try { console.log(JSON.stringify(L.decompressFromUTF16("\\u6020\\u4000\\u4000"))); } catch (e) { console.log(e.constructor.name); }',
        prints('""'),
        prints('""'),
        HostEnvironment.node,
    ),
    'code units below 32': FileProgram(
        LIB + 'console.log(JSON.stringify(L.decompressFromUTF16("\\u0001\\u0002\\u0003\\u001f")));',
        prints('null'),
        prints('null'),
        HostEnvironment.node,
    ),
    'an astral and a lone surrogate round trip': FileProgram(
        LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("\\ud83d\\ude00|\\ud800|x"))));',
        prints('"😀|\\ud800|x"'),
        prints('"😀|\\ud800|x"'),
        HostEnvironment.node,
    ),
    'a long text': FileProgram(
        LIB + 'console.log(L.decompressFromUTF16(COMPRESSED("' + FOX + '")).length);',
        prints('1320'),
        prints('1320'),
        HostEnvironment.node,
    ),
    'the method replaced before the call': FileProgram(
        LIB + 'L.decompressFromUTF16 = function () { return "replaced"; }; console.log(L.decompressFromUTF16(COMPRESSED("abc")));',
        prints('replaced'),
        prints('replaced'),
        HostEnvironment.node,
    ),
    'the core replaced through a second name': FileProgram(
        LIB + 'var M = L; M._decompress = function () { return "core"; }; console.log(L.decompressFromUTF16(COMPRESSED("abc")));',
        prints('core'),
        prints('core'),
        HostEnvironment.node,
    ),
    'the object handed to a function that writes it': FileProgram(
        LIB + '(function (o) { o._decompress = function () { return "handed"; }; })(L); console.log(L.decompressFromUTF16(COMPRESSED("abc")));',
        prints('handed'),
        prints('handed'),
        HostEnvironment.node,
    ),
    'String.fromCharCode replaced before the library is built': FileProgram(
        'String.fromCharCode = function () { return "#"; };' + LIB + 'console.log(L.decompressFromUTF16(COMPRESSED("abc")));',
        prints('###'),
        prints('###'),
        HostEnvironment.node,
    ),
    'Math.pow replaced after the library is built': FileProgram(
        LIB + 'Math.pow = function () { return 2; }; console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abcabcabc"))));',
        prints('""'),
        prints('""'),
        HostEnvironment.node,
    ),
    'Array.prototype.push replaced': FileProgram(
        LIB + 'Array.prototype.push = function (x) { this[this.length] = x + "!"; return this.length; }; console.log(L.decompressFromUTF16(COMPRESSED("abc|abc")));',
        prints('a!b!c!|!ab!c!'),
        prints('a!b!c!|!ab!c!'),
        HostEnvironment.node,
    ),
    'an index on Object.prototype': FileProgram(
        'Object.prototype[7] = "seven";' + LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("ababababab"))));',
        prints('"ababsevenbab"'),
        prints('"ababsevenbab"'),
        HostEnvironment.node,
    ),
    'a library one character away from the build': FileProgram(
        'var L=' + LIBRARY.replace('charCodeAt(o)-32', 'charCodeAt(o)-31') + '();'
        + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abc"))));',
        prints('"aaS"'),
        prints('"aaS"'),
        HostEnvironment.node,
    ),
    'the program defines an AMD define first': FileProgram(
        'globalThis.define = function (f) { f()._decompress = function () { return "amd"; }; }; globalThis.define.amd = true;' + LIB + TAIL + 'console.log(L.decompressFromUTF16(COMPRESSED("abc")));',
        prints('amd'),
        prints('amd'),
        HostEnvironment.node,
    ),
    'a global named at runtime is created before the export line': FileProgram(
        'globalThis[process.argv.length > 99 ? "x" : "define"] = function (f) { f()._decompress = function () { return "amd"; }; }; define.amd = 1;' + LIB + TAIL + 'console.log(L.decompressFromUTF16(COMPRESSED("abc")));',
        prints('amd'),
        prints('amd'),
        HostEnvironment.node,
    ),
    'the program reads its export back': FileProgram(
        LIB + TAIL + TEMPLATE + 'console.log(SC(0), typeof module.exports.decompressFromUTF16);',
        prints('line function'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'the library inside a function whose parameter is named String': FileProgram(
        'function wrap(String) { ' + LIB + ' return L.decompressFromUTF16(COMPRESSED("abcabc")); } console.log(JSON.stringify(wrap({ fromCharCode: function (c) { return "<" + c + ">"; } })));',
        prints('"<97><98><99><97><<99>"'),
        prints('"<97><98><99><97><<99>"'),
        HostEnvironment.node,
    ),
    'two calls, one after the object is written': FileProgram(
        LIB + 'var a = L.decompressFromUTF16(COMPRESSED("first")); L._decompress = function () { return "late"; }; console.log(a, L.decompressFromUTF16(COMPRESSED("second")));',
        prints('first late'),
        prints('first late'),
        HostEnvironment.node,
    ),
    'the value of the store holds the library': FileProgram(
        LIB + 'var M = (module.exports = L); M._decompress = function () { return "x"; }; console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abc|abc"))));',
        prints('"x"'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'the library stored under a condition': FileProgram(
        LIB + '(process.argv.length > 0 ? module.exports = L : 0); console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abc|abc"))));',
        prints('"abc|abc"'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'the library written through module.exports': FileProgram(
        LIB + 'module.exports = L; module.exports._decompress = function () { return "w"; }; console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abc|abc"))));',
        prints('"w"'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'an inherited method called on the library': FileProgram(
        LIB + 'L.hasOwnProperty("x"); console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abc|abc"))));',
        prints('"abc|abc"'),
        prints('"abc|abc"'),
        HostEnvironment.node,
    ),
    'the library stored and called through its export line': FileProgram(
        LIB + TAIL + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abc|abc"))));',
        prints('"abc|abc"'),
        prints('"abc|abc"'),
        HostEnvironment.node,
    ),
    'the full shape, the library written through module.exports after the call': FileProgram(
        LIB + TAIL + TEMPLATE + 'module.exports._decompress = 0; ' + USE,
        prints('line BrainfuckError  at line move', 'ADD'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'the inserted shape after a file is required': FileProgram(
        'require("fs").writeFileSync(require("path").join(__dirname, "amd2.js"), "global.define = function (f) { f()._decompress = function () { return 1; }; }; global.define.amd = true;"); require("./amd2.js"); ' + LIB + TAIL + TEMPLATE + USE,
        ('', 'TypeError'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'a setter on an Object.prototype index': FileProgram(
        'Object.defineProperty(Object.prototype, "4", { set: function (v) {}, get: function () { return "Q"; }, configurable: true });' + LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("ababab"))));',
        prints('"aQaQaQ"'),
        prints('"aQaQaQ"'),
        HostEnvironment.node,
    ),
    '__defineSetter__ on an index': FileProgram(
        'Object.prototype.__defineSetter__("0", function () {});' + LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("ababab"))));',
        prints('"babab"'),
        prints('"babab"'),
        HostEnvironment.node,
    ),
    'with an object holding L': FileProgram(
        LIB + 'with ({ L: { decompressFromUTF16: function () { return "fake"; } } }) { console.log(L.decompressFromUTF16(COMPRESSED("abc"))); }',
        prints('fake'),
        ('', 'SyntaxError'),
        HostEnvironment.node,
    ),
    'a computed write on L': FileProgram(
        LIB + 'L[["_dec", "ompress"].join("")] = function () { return "c"; }; console.log(L.decompressFromUTF16(COMPRESSED("abc")));',
        prints('c'),
        prints('c'),
        HostEnvironment.node,
    ),
    'charCodeAt deleted, an Object.prototype one installed': FileProgram(
        'delete String.prototype.charCodeAt; Object.prototype.charCodeAt = function () { return 40; };' + LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abc"))));',
        prints('"\\u0000"'),
        prints('"\\u0000"'),
        HostEnvironment.node,
    ),
    'the array chain swapped': FileProgram(
        'Object.setPrototypeOf(Array.prototype, { set 4(v) {}, push: Array.prototype.push, join: Array.prototype.join });' + LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("ababab"))));',
        prints('null'),
        prints('null'),
        HostEnvironment.node,
    ),
    'a Math local whose pow differs': FileProgram(
        'var Math = { pow: function (a, b) { return 2; } };' + LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abcabc"))));',
        prints('""'),
        prints('""'),
        HostEnvironment.node,
    ),
    'a String local': FileProgram(
        'var String = { fromCharCode: function (c) { return "<" + c + ">"; } };' + LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abcabc"))));',
        prints('"<97><98><99><97><<99>"'),
        prints('"<97><98><99><97><<99>"'),
        HostEnvironment.node,
    ),
    'the full shape with a reflection surface': FileProgram(
        LIB + TAIL + TEMPLATE + 'globalThis[process.argv.length > 99 ? "a" : "b"] = 2;console.log(SC(0), SC(3));',
        prints('line BrainfuckError'),
        prints('line BrainfuckError'),
        HostEnvironment.node,
    ),
    'a direct eval writes L': FileProgram(
        LIB + 'eval(process.argv.length > 99 ? "" : "L._decompress = function () { return \\"e\\"; }"); console.log(L.decompressFromUTF16(COMPRESSED("abc")));',
        prints('e'),
        prints('e'),
        HostEnvironment.node,
    ),
    'the library handed to an AMD loader a required file installs': FileProgram(
        AMD_LOADER_BESIDE + 'require("./amd.js");' + LIB + TAIL + 'console.log(L.decompressFromUTF16(COMPRESSED("abc")));',
        prints('1'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'the full shape handed to such a loader': FileProgram(
        AMD_LOADER_BESIDE + 'require("./amd.js");' + LIB + TAIL + TEMPLATE + 'console.log(SC(0), SC(3));',
        ('', 'TypeError'),
        ('', 'ReferenceError'),
        HostEnvironment.node,
    ),
    'Math local by a parameter': FileProgram(
        '(function (Math) {' + LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abcabc")))); })({ pow: function () { return 2; } });',
        prints('""'),
        prints('""'),
        HostEnvironment.node,
    ),
    'Math local, pow keeps its first argument': FileProgram(
        'var Math = { pow: function (a) { return a; } };' + LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abcabcabcabc"))));',
        prints('""'),
        prints('""'),
        HostEnvironment.node,
    ),
    'Math local in the full shape': FileProgram(
        'var Math = { pow: function () { return 2; } };' + LIB + TAIL + TEMPLATE + 'console.log(SC(0), SC(3));',
        prints(' undefined'),
        prints(' undefined'),
        HostEnvironment.node,
    ),
    'an inherited __defineGetter__ called on the object': FileProgram(
        LIB + 'L.__defineGetter__("_decompress", function () { return function () { return "pwn"; }; });console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abcabc|abc"))));',
        prints('"pwn"'),
        prints('"pwn"'),
        HostEnvironment.node,
    ),
    'the object handed back by valueOf and written': FileProgram(
        LIB + 'L.valueOf()._decompress = function () { return "pwn"; };console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abcabc|abc"))));',
        prints('"pwn"'),
        prints('"pwn"'),
        HostEnvironment.node,
    ),
    'a method the program installs on Object.prototype writes it': FileProgram(
        'Object.prototype.hijack = function () { this._decompress = function () { return "pwn"; }; };' + LIB + 'L.hijack();console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abcabc|abc"))));',
        prints('"pwn"'),
        prints('"pwn"'),
        HostEnvironment.node,
    ),
    'String.fromCharCode replaced through a second name': FileProgram(
        'var S = String; S.fromCharCode = function () { return "#"; };' + LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abcabc|abc"))));',
        prints('"##########"'),
        prints('"##########"'),
        HostEnvironment.node,
    ),
    'Math.pow replaced through a second name': FileProgram(
        'var M = Math; M.pow = function () { return 2; };' + LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abcabc|abc"))));',
        prints('""'),
        prints('""'),
        HostEnvironment.node,
    ),
    'Math.pow replaced through globalThis': FileProgram(
        'globalThis.Math.pow = function () { return 2; };' + LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abcabc|abc"))));',
        prints('""'),
        prints('""'),
        HostEnvironment.node,
    ),
    'Math.pow replaced by Object.assign': FileProgram(
        'Object.assign(Math, { pow: function () { return 2; } });' + LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abcabc|abc"))));',
        prints('""'),
        prints('""'),
        HostEnvironment.node,
    ),
    'Math.pow replaced inside with': FileProgram(
        'with (Math) { pow = function () { return 2; }; }' + LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abcabc|abc"))));',
        prints('""'),
        ('', 'SyntaxError'),
        HostEnvironment.node,
    ),
    'the full shape, the object written through valueOf': FileProgram(
        LIB + TAIL + 'L.valueOf()._decompress = function () { return "pwn"; };' + TEMPLATE + USE,
        prints('pwn undefined NaN', 'undefined'),
        prints('pwn undefined NaN', 'undefined'),
        HostEnvironment.node,
    ),
    'Math replaced as a global by assignment': FileProgram(
        'Math = { pow: function () { return 2; } };' + LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abcabc|abc"))));',
        prints('""'),
        prints('""'),
        HostEnvironment.node,
    ),
    'Math replaced through globalThis': FileProgram(
        'globalThis.Math = { pow: function () { return 2; } };' + LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abcabc|abc"))));',
        prints('""'),
        prints('""'),
        HostEnvironment.node,
    ),
    'Math shadowed by a let in the block holding the library': FileProgram(
        '{ let Math = { pow: function () { return 2; } };' + LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abcabc|abc"))));}',
        prints('""'),
        prints('""'),
        HostEnvironment.node,
    ),
    'Math shadowed by a catch parameter': FileProgram(
        'try { throw { pow: function () { return 2; } }; } catch (Math) {' + LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abcabc|abc"))));}',
        prints('""'),
        prints('""'),
        HostEnvironment.node,
    ),
    'push replaced through the __proto__ of an array literal': FileProgram(
        '[].__proto__.push = function (x) { this[this.length] = x + "!"; return this.length; };' + LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abcabc|abc"))));',
        prints('"a!b!c!ab!c!|!abc!"'),
        prints('"a!b!c!ab!c!|!abc!"'),
        HostEnvironment.node,
    ),
    'join replaced through Object.getPrototypeOf': FileProgram(
        'Object.getPrototypeOf([]).join = function () { return "joined"; };' + LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abcabc|abc"))));',
        prints('"joined"'),
        prints('"joined"'),
        HostEnvironment.node,
    ),
    'Symbol.split on Object.prototype in the inserted shape': FileProgram(
        'Object.prototype[Symbol.split] = function () { return ["x", "y", "z", "w"]; };' + LIB + TAIL + TEMPLATE + USE,
        prints('x w NaN', 'undefined'),
        prints('x w NaN', 'undefined'),
        HostEnvironment.node,
    ),
    'the library returned by a wrapper whose parameter is named String': FileProgram(
        'var mk = function (String) { return ' + LIBRARY + '(); }; var L = mk({ fromCharCode: function (c) { return "<" + c + ">"; } }); console.log(L.decompressFromUTF16(COMPRESSED("abc")));',
        prints('<97><98><99>'),
        prints('<97><98><99>'),
        HostEnvironment.node,
    ),
    'the same with an arrow wrapper': FileProgram(
        'var mk = (String) => ' + LIBRARY + '(); var L = mk({ fromCharCode: function (c) { return "<" + c + ">"; } }); console.log(L.decompressFromUTF16(COMPRESSED("abc")));',
        prints('<97><98><99>'),
        prints('<97><98><99>'),
        HostEnvironment.node,
    ),
    'the same with a function declaration wrapper': FileProgram(
        'function mk(String) { return ' + LIBRARY + '(); } var L = mk({ fromCharCode: function (c) { return "<" + c + ">"; } }); console.log(L.decompressFromUTF16(COMPRESSED("abc")));',
        prints('<97><98><99>'),
        prints('<97><98><99>'),
        HostEnvironment.node,
    ),
    'the library with Math passed in': FileProgram(
        'function mk(Math) { return ' + LIBRARY + '(); } var L = mk({ pow: function (a, b) { return 2 * Math.pow(a, b); } }); console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abcabcabcabc"))));',
        prints('null'),
        prints('null'),
        HostEnvironment.node,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAProgramDecompressingItsStringsStillPrintsWhatItPrints(TestBase):

    def testnode_prints_what_each_row_pins(self):
        node_prints_what_each_row_pins(self, with_compressed_strings(A_PROGRAM_DECOMPRESSING_ITS_STRINGS))

    def test_each_program_still_prints_what_it_prints(self):
        each_reading_still_prints(
            self,
            with_compressed_strings(A_PROGRAM_DECOMPRESSING_ITS_STRINGS),
            (Reading.COMMONJS,),
        )

    def test_the_inserted_shape_still_prints_what_it_prints_where_the_file_may_be_an_es_module(self):
        rows = with_compressed_strings(A_PROGRAM_DECOMPRESSING_ITS_STRINGS)
        each_reading_still_prints(
            self,
            {'the inserted shape': rows['the inserted shape: library, its export line, the accessor']},
            (Reading.MODULE, Reading.ES_MODULE),
        )


#: Programs that replace a method of strings or arrays the library calls through the prototype of a
#: literal before decompressing, each with what Node makes of it as a CommonJS file and as an ES
#: module.
A_METHOD_THE_LIBRARY_CALLS_REPLACED_THROUGH_THE_PROTOTYPE_OF_A_LITERAL = {
    'charCodeAt replaced through the __proto__ of a string literal': FileProgram(
        '"".__proto__.charCodeAt = function () { return 40; };' + LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abcabc|abc"))));',
        prints('"\\u0000"'),
        prints('"\\u0000"'),
        HostEnvironment.node,
    ),
    'charCodeAt replaced through Object.getPrototypeOf': FileProgram(
        'Object.getPrototypeOf("").charCodeAt = function () { return 40; };' + LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abcabc|abc"))));',
        prints('"\\u0000"'),
        prints('"\\u0000"'),
        HostEnvironment.node,
    ),
    'charAt replaced through the __proto__ of a string literal': FileProgram(
        '"".__proto__.charAt = function () { return "Z"; };' + LIB + 'console.log(JSON.stringify(L.decompressFromUTF16(COMPRESSED("abcabc|abc"))));',
        prints('"abcaZc|aZZ"'),
        prints('"abcaZc|aZZ"'),
        HostEnvironment.node,
    ),
    'split through __proto__ in the inserted shape': FileProgram(
        '"".__proto__.split = function () { return ["x", "y", "z", "w"]; };' + LIB + TAIL + TEMPLATE + USE,
        prints('x w NaN', 'undefined'),
        prints('x w NaN', 'undefined'),
        HostEnvironment.node,
    ),
    'the same with a reflection surface after': FileProgram(
        '"".__proto__.split = function () { return ["x", "y", "z", "w"]; };' + LIB + TAIL + TEMPLATE + USE + 'globalThis[process.argv.length > 99 ? "a" : "b"] = 2;',
        prints('x w NaN', 'undefined'),
        prints('x w NaN', 'undefined'),
        HostEnvironment.node,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAMethodTheLibraryCallsReplacedThroughThePrototypeOfALiteral(TestBase):

    def testnode_prints_what_each_row_pins(self):
        node_prints_what_each_row_pins(
            self,
            with_compressed_strings(A_METHOD_THE_LIBRARY_CALLS_REPLACED_THROUGH_THE_PROTOTYPE_OF_A_LITERAL),
        )

    @wontfix(
        'no obfuscated file writes a method of strings through the prototype of a literal or through '
        'Object.getPrototypeOf, and no fold of a method call has ever seen such a write'
    )
    def test_each_program_still_prints_what_it_prints(self):
        each_reading_still_prints(
            self,
            with_compressed_strings(A_METHOD_THE_LIBRARY_CALLS_REPLACED_THROUGH_THE_PROTOTYPE_OF_A_LITERAL),
            (Reading.COMMONJS,),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheInsertedShapeIsDecompressed(TestBase):

    @property
    def _inserted(self) -> str:
        rows = with_compressed_strings(A_PROGRAM_DECOMPRESSING_ITS_STRINGS)
        return rows['the inserted shape: library, its export line, the accessor'].text

    def _deobfuscated(self, source: str, *switches: str) -> str:
        return source.encode('utf8') | djs.assemble(*switches) | str

    def test_the_library_its_export_line_and_the_accessor_go_from_a_commonjs_file(self):
        self.assertEqual(
            self._deobfuscated(self._inserted, '-c', '-e', 'node'),
            inspect.cleandoc("""
                console.log('line', 'BrainfuckError', ' at line move');
                console.log('ADD');
                """),
        )

    def test_the_strings_decode_and_the_library_stays_where_the_file_may_be_an_es_module(self):
        deobfuscated = self._deobfuscated(self._inserted, '-m', '-e', 'node')
        self.assertNotIn('.decompressFromUTF16("', deobfuscated)
        self.assertIn('decompressFromUTF16:', deobfuscated)
        self.assertTrue(deobfuscated.endswith(NL.join((
            "console.log('line', 'BrainfuckError', ' at line move');",
            "console.log('ADD');",
        ))))

    def test_nothing_decodes_where_other_files_load_the_input(self):
        self.assertIn('.decompressFromUTF16("', self._deobfuscated(self._inserted, '-c', '-l', '-e', 'node'))

    def test_nothing_decodes_where_a_page_may_hand_the_library_to_its_loader(self):
        self.assertIn('.decompressFromUTF16("', self._deobfuscated(self._inserted, '-c', '-e', 'browser'))


class TestAProgramAnObfuscatorCompressedTheStringsOf(TestBase):
    """
    The program `STRINGS_COMPRESSED`, deobfuscated as an analyst runs `refinery.djs` on a Node
    script and read as text only.
    """

    def _deobfuscated(self, *switches: str) -> str:
        return STRINGS_COMPRESSED.encode('utf8') | djs.assemble(*switches) | str

    def test_a_commonjs_file_is_recovered_as_the_line_it_prints(self):
        self.assertEqual(self._deobfuscated('-c', '-e', 'node'), FIZZBUZZ_PRINTED)

    def test_where_the_file_may_be_an_es_module_the_line_follows_the_library(self):
        deobfuscated = self._deobfuscated('-m', '-e', 'node')
        self.assertTrue(deobfuscated.endswith(NL + FIZZBUZZ_PRINTED))

    def test_where_other_files_load_the_input_the_strings_stay_compressed(self):
        self.assertIn('.decompressFromUTF16(', self._deobfuscated('-c', '-l', '-e', 'node'))
