"""
Decompress the strings a program keeps in the compressed form of the lz-string library. The
library's minified build is inserted whole and called once with every string of the program joined
into one:

    var L = function () { var r = String.fromCharCode, ...; return i; }();
    var strings = L.decompressFromUTF16("...").split("|");

A call of its `decompressFromUTF16` with a string literal becomes the string it returns, where the
name holds the library's object and nothing changes that object before the call. The library is
recognized by its normal form (`refinery.lib.scripts.js.deobfuscation.templates`), in which a name
it reads as a global is one that resolves to no binding. The deobfuscation's own rewrites change the
library before the call can be decoded (dropping an initializer nothing reads, folding `!0`), so the
run records the builds the input holds before its first pass (`JsLZStringDecoder.read_input`); a
rewrite keeps what a function computes, and a pass that builds a new function makes a node the
record does not hold.

The template below is the minified build of the lz-string library, copyright (c) 2013 pieroxy,
covered by an MIT license. Regardless of the license used for the binary refinery, this code file
is also subject to the terms and conditions of that license, which is included in
`refinery.lib.lzstring`.
"""
from __future__ import annotations

from weakref import WeakKeyDictionary

from refinery.lib.lzstring import decompress_from_utf16
from refinery.lib.scripts import Node, _replace_in_parent
from refinery.lib.scripts.js.analysis.cache import ModelCache, model_cache
from refinery.lib.scripts.js.analysis.model import enclosing_function
from refinery.lib.scripts.js.deobfuscation.helpers import (
    ScriptLevelTransformer,
    access_key,
    make_string_literal,
)
from refinery.lib.scripts.js.deobfuscation.interpreter import MAX_STRING_LEN
from refinery.lib.scripts.js.deobfuscation.templates import Template, matches
from refinery.lib.scripts.js.model import (
    JsArrowFunctionExpression,
    JsCallExpression,
    JsFunctionExpression,
    JsIdentifier,
    JsMemberExpression,
    JsNullLiteral,
    JsProperty,
    JsScript,
    JsStringLiteral,
    strip_parens,
)

_LIBRARY = (
    'function(){var r=String.fromCharCode,o="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",'
    'n="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-$",e={};function t(r,o){if(!e[r]){e[r]={};'
    'for(var n=0;n<r.length;n++)e[r][r.charAt(n)]=n}return e[r][o]}var i={compressToBase64:function(r){if(null==r)'
    'return"";var n=i._compress(r,6,function(r){return o.charAt(r)});switch(n.length%4){default:case 0:return n;case 1:'
    'return n+"===";case 2:return n+"==";case 3:return n+"="}},decompressFromBase64:function(r){return null==r?"":""=='
    'r?null:i._decompress(r.length,32,function(n){return t(o,r.charAt(n))})},compressToUTF16:function(o){return null=='
    'o?"":i._compress(o,15,function(o){return r(o+32)})+" "},decompressFromUTF16:function(r){return null==r?"":""==r?'
    'null:i._decompress(r.length,16384,function(o){return r.charCodeAt(o)-32})},compressToUint8Array:function(r){for('
    'var o=i.compress(r),n=new Uint8Array(2*o.length),e=0,t=o.length;e<t;e++){var s=o.charCodeAt(e);n[2*e]=s>>>8,n[2*e'
    '+1]=s%256}return n},decompressFromUint8Array:function(o){if(null==o)return i.decompress(o);for(var n=new Array(o'
    '.length/2),e=0,t=n.length;e<t;e++)n[e]=256*o[2*e]+o[2*e+1];var s=[];return n.forEach(function(o){s.push(r(o))}),i'
    '.decompress(s.join(""))},compressToEncodedURIComponent:function(r){return null==r?"":i._compress(r,6,function(r)'
    '{return n.charAt(r)})},decompressFromEncodedURIComponent:function(r){return null==r?"":""==r?null:(r=r.replace(/ '
    '/g,"+"),i._decompress(r.length,32,function(o){return t(n,r.charAt(o))}))},compress:function(o){return i._compress'
    '(o,16,function(o){return r(o)})},_compress:function(r,o,n){if(null==r)return"";var e,t,i,s={},u={},a="",p="",c="'
    '",l=2,f=3,h=2,d=[],m=0,v=0;for(i=0;i<r.length;i+=1)if(a=r.charAt(i),Object.prototype.hasOwnProperty.call(s,a)||('
    's[a]=f++,u[a]=!0),p=c+a,Object.prototype.hasOwnProperty.call(s,p))c=p;else{if(Object.prototype.hasOwnProperty.ca'
    'll(u,c)){if(c.charCodeAt(0)<256){for(e=0;e<h;e++)m<<=1,v==o-1?(v=0,d.push(n(m)),m=0):v++;for(t=c.charCodeAt(0),e'
    '=0;e<8;e++)m=m<<1|1&t,v==o-1?(v=0,d.push(n(m)),m=0):v++,t>>=1}else{for(t=1,e=0;e<h;e++)m=m<<1|t,v==o-1?(v=0,d.pu'
    'sh(n(m)),m=0):v++,t=0;for(t=c.charCodeAt(0),e=0;e<16;e++)m=m<<1|1&t,v==o-1?(v=0,d.push(n(m)),m=0):v++,t>>=1}0==-'
    '-l&&(l=Math.pow(2,h),h++),delete u[c]}else for(t=s[c],e=0;e<h;e++)m=m<<1|1&t,v==o-1?(v=0,d.push(n(m)),m=0):v++,t'
    '>>=1;0==--l&&(l=Math.pow(2,h),h++),s[p]=f++,c=String(a)}if(""!==c){if(Object.prototype.hasOwnProperty.call(u,c)'
    '){if(c.charCodeAt(0)<256){for(e=0;e<h;e++)m<<=1,v==o-1?(v=0,d.push(n(m)),m=0):v++;for(t=c.charCodeAt(0),e=0;e<8;'
    'e++)m=m<<1|1&t,v==o-1?(v=0,d.push(n(m)),m=0):v++,t>>=1}else{for(t=1,e=0;e<h;e++)m=m<<1|t,v==o-1?(v=0,d.push(n(m)'
    '),m=0):v++,t=0;for(t=c.charCodeAt(0),e=0;e<16;e++)m=m<<1|1&t,v==o-1?(v=0,d.push(n(m)),m=0):v++,t>>=1}0==--l&&(l='
    'Math.pow(2,h),h++),delete u[c]}else for(t=s[c],e=0;e<h;e++)m=m<<1|1&t,v==o-1?(v=0,d.push(n(m)),m=0):v++,t>>=1;0='
    '=--l&&(l=Math.pow(2,h),h++)}for(t=2,e=0;e<h;e++)m=m<<1|1&t,v==o-1?(v=0,d.push(n(m)),m=0):v++,t>>=1;for(;;){if(m<'
    '<=1,v==o-1){d.push(n(m));break}v++}return d.join("")},decompress:function(r){return null==r?"":""==r?null:i._dec'
    'ompress(r.length,32768,function(o){return r.charCodeAt(o)})},_decompress:function(o,n,e){var t,i,s,u,a,p,c,l=[],'
    'f=4,h=4,d=3,m="",v=[],g={val:e(0),position:n,index:1};for(t=0;t<3;t+=1)l[t]=t;for(s=0,a=Math.pow(2,2),p=1;p!=a;)'
    'u=g.val&g.position,g.position>>=1,0==g.position&&(g.position=n,g.val=e(g.index++)),s|=(u>0?1:0)*p,p<<=1;switch(s'
    '){case 0:for(s=0,a=Math.pow(2,8),p=1;p!=a;)u=g.val&g.position,g.position>>=1,0==g.position&&(g.position=n,g.val='
    'e(g.index++)),s|=(u>0?1:0)*p,p<<=1;c=r(s);break;case 1:for(s=0,a=Math.pow(2,16),p=1;p!=a;)u=g.val&g.position,g.'
    'position>>=1,0==g.position&&(g.position=n,g.val=e(g.index++)),s|=(u>0?1:0)*p,p<<=1;c=r(s);break;case 2:return""}'
    'for(l[3]=c,i=c,v.push(c);;){if(g.index>o)return"";for(s=0,a=Math.pow(2,d),p=1;p!=a;)u=g.val&g.position,g.positio'
    'n>>=1,0==g.position&&(g.position=n,g.val=e(g.index++)),s|=(u>0?1:0)*p,p<<=1;switch(c=s){case 0:for(s=0,a=Math.po'
    'w(2,8),p=1;p!=a;)u=g.val&g.position,g.position>>=1,0==g.position&&(g.position=n,g.val=e(g.index++)),s|=(u>0?1:0)'
    '*p,p<<=1;l[h++]=r(s),c=h-1,f--;break;case 1:for(s=0,a=Math.pow(2,16),p=1;p!=a;)u=g.val&g.position,g.position>>=1'
    ',0==g.position&&(g.position=n,g.val=e(g.index++)),s|=(u>0?1:0)*p,p<<=1;l[h++]=r(s),c=h-1,f--;break;case 2:return'
    ' v.join("")}if(0==f&&(f=Math.pow(2,d),d++),l[c])m=l[c];else{if(c!==h)return null;m=i+i.charAt(0)}v.push(m),l[h++'
    ']=i+m.charAt(0),i=m,0==--f&&(f=Math.pow(2,d),d++)}}};return i}'
)

_TEMPLATES = tuple(
    Template(F'function LZString{text[len("function"):]}')
    for written in (_LIBRARY, _LIBRARY.replace('i+=1', 'i++').replace('t+=1', 't++'))
    for text in (written, written.replace('m="",', 'm,'))
)
"""
The function of the library's minified build: as inserted, with its two counting loops written with
`++`, which is how a minifier rewrites them, and either of these with the initializer of `m` in
`_decompress` left out, which no read reaches and which the deobfuscation drops before the library
can be decoded.
"""

_METHODS = frozenset({
    'compressToBase64',
    'decompressFromBase64',
    'compressToUTF16',
    'decompressFromUTF16',
    'compressToUint8Array',
    'decompressFromUint8Array',
    'compressToEncodedURIComponent',
    'decompressFromEncodedURIComponent',
    'compress',
    '_compress',
    'decompress',
    '_decompress',
})
"""
The methods of the object the library returns. Each reads the object and none writes it.
"""

_WRITTEN: WeakKeyDictionary[ModelCache, dict[int, Node]] = WeakKeyDictionary()
"""
The builds of the library each run's input holds, by identity, recorded before the run's first
pass (`JsLZStringDecoder.read_input`). The nodes are held, so an identity stays theirs.
"""


def _library_builds(cache: ModelCache) -> dict[int, Node]:
    """
    The functions of the tree *cache* is created over that have the normal form of the library's
    build, by identity. The semantic model the normal form needs is asked for only where a function
    holds a property named as the library's.
    """
    builds: dict[int, Node] = {}
    for node in cache.root.walk():
        if not isinstance(node, JsProperty) or node.computed:
            continue
        key = node.key
        if not isinstance(key, JsIdentifier) or key.name != 'decompressFromUTF16':
            continue
        function = enclosing_function(node)
        if (
            isinstance(function, (JsFunctionExpression, JsArrowFunctionExpression))
            and id(function) not in builds
            and matches(cache.model, function, _TEMPLATES, {})
        ):
            builds[id(function)] = function
    return builds


def _is_the_library(cache: ModelCache, function: JsFunctionExpression | JsArrowFunctionExpression) -> bool:
    """
    Whether *function* is a build of the library: one the run's input held, or one that has the
    library's normal form now.
    """
    written = _WRITTEN.get(cache)
    if written is not None and written.get(id(function)) is function:
        return True
    return matches(cache.model, function, _TEMPLATES, {})


def _library_call(cache: ModelCache, call: JsCallExpression) -> JsStringLiteral | None:
    """
    The string literal *call* decompresses when it is `L.decompressFromUTF16("...")` and `L` holds
    the object the library's function returns, unchanged where *call* runs: the function is a build
    of the library (`_is_the_library`) and reads `String` and `Math` as globals; its value is a call
    of that function made where it is written; the name is established before *call*; no code
    touches the object it holds but a call of one of the object's own methods, which read the object
    and never write it, and a store no code observes
    (`refinery.lib.scripts.js.analysis.effects.EffectModel.binding_is_immutable_container`); and the
    built-ins the library reads, `String.fromCharCode` when it is built and `Math.pow` and the
    methods of strings and arrays when it decompresses, are those of the language at both points
    (`refinery.lib.scripts.js.analysis.cache.ModelCache.trust_at`).
    """
    model = cache.model
    effects = cache.effects
    callee = strip_parens(call.callee)
    if not isinstance(callee, JsMemberExpression) or access_key(callee) != 'decompressFromUTF16':
        return None
    if callee.optional or call.optional or len(call.arguments) != 1:
        return None
    if not isinstance(argument := strip_parens(call.arguments[0]), JsStringLiteral) or argument.value is None:
        return None
    if not isinstance(name := strip_parens(callee.object), JsIdentifier):
        return None
    if (binding := model.resolve(name)) is None or model.reflection_can_reach(binding):
        return None
    built = strip_parens(model.singular_value(binding))
    if not isinstance(built, JsCallExpression) or built.arguments:
        return None
    if not isinstance(function := strip_parens(built.callee), (JsFunctionExpression, JsArrowFunctionExpression)):
        return None
    if not _is_the_library(cache, function):
        return None
    for node in function.walk():
        if isinstance(node, JsIdentifier) and node.name in ('String', 'Math') and model.resolve(node) is not None:
            return None
    if not cache.dominance.binding_established_before(binding, call):
        return None
    if not effects.binding_is_immutable_container(binding, inert_methods=_METHODS):
        return None
    for anchor in (built, call):
        trust = cache.trust_at(anchor)
        if not trust.intrinsic_name('String') or not trust.intrinsic_name('Math'):
            return None
        if not trust.prototype(str) or not trust.prototype(list) or not trust.chain(list):
            return None
    return argument


class JsLZStringDecoder(ScriptLevelTransformer):
    """
    Replace every call decompressing a string literal with the lz-string library this module
    describes by the string it returns.
    """

    @staticmethod
    def read_input(models: ModelCache) -> None:
        """
        Record the builds of the library the tree *models* was created over holds, before the run's
        first pass changes them.
        """
        if models not in _WRITTEN:
            _WRITTEN[models] = _library_builds(models)

    def _process_script(self, node: JsScript):
        cache = model_cache(self, node)
        replacements: list[tuple[Node, Node]] = []
        for call in node.walk():
            if not isinstance(call, JsCallExpression):
                continue
            if (argument := _library_call(cache, call)) is None or argument.value is None:
                continue
            try:
                decompressed = decompress_from_utf16(argument.value, MAX_STRING_LEN)
            except ValueError:
                continue
            replacement = JsNullLiteral() if decompressed is None else make_string_literal(decompressed)
            replacements.append((call, replacement))
        if not replacements:
            return
        for call, replacement in replacements:
            _replace_in_parent(call, replacement)
        self.mark_changed()
