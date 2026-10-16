"""
Programs declaring a function in a block outside strict code. Such a function has two bindings: the
block's, holding the function from the moment the block is entered, and a variable of the enclosing
function or script, which receives what the block's binding holds when the declaration runs (Annex
B.3.3). A fold reading either name has to read the one the program reads, from the point at which
it holds what the fold assumes.

SECURITY: every program here is hand-authored and benign. No sample and no stored obfuscator fixture
may be fed to this.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import (
    a_program,
    before_and_after,
    before_and_after_in_a_host,
    each_program_still_prints,
)

#: Programs calling or reading a function declared in a block through either of its names,
#: before and after the block, on runs that enter the block and on runs that do not, mapped
#: to what Node prints for them.
A_CALL_ORDERED_BY_THE_NAME_IT_READS = {
    a_program("""
        function outer(c) {
          if (c) { function W() { return 1; } }
          try { console.log(W()); } catch (e) { console.log(e.constructor.name); }
        }
        outer(0); outer(1);
        """): 'TypeError\n1\n',
    a_program("""
        function outer(c) {
          try { if (c) throw 1; { function W() { return 2; } } } catch (e) {}
          try { console.log(W()); } catch (e) { console.log(e.constructor.name); }
        }
        outer(1); outer(0);
        """): 'TypeError\n2\n',
    a_program("""
        function target(a) { return a + 1; }
        function outer() {
          try { console.log(wrap(1)); } catch (e) { console.log(e.constructor.name); }
          { function wrap(a) { return target(a); } }
          console.log(wrap(2));
        }
        outer();
        """): 'TypeError\n3\n',
    a_program("""
        function outer() {
          function h() { return W(); }
          try { console.log(h()); } catch (e) { console.log(e.constructor.name); }
          { function W() { return 3; } }
          console.log(h());
        }
        outer();
        """): 'TypeError\n3\n',
    a_program("""
        function outer() {
          { function W() { return 4; } W = function () { return 5; }; console.log(W()); }
          console.log(W());
        }
        outer();
        """): '5\n4\n',
    a_program("""
        function outer(n) {
          for (var i = 0; i < n; i++) { function W() { return i; } }
          try { console.log(W()); } catch (e) { console.log(e.constructor.name); }
        }
        outer(0); outer(2);
        """): 'TypeError\n2\n',
    a_program("""
        function outer(k) {
          switch (k) { case 1: function W() { return 'one'; } break; default: break; }
          try { console.log(W()); } catch (e) { console.log(e.constructor.name); }
        }
        outer(2); outer(1);
        """): 'TypeError\none\n',
    a_program("""
        function outer(c) {
          if (c) function W() { return 6; }
          try { console.log(W()); } catch (e) { console.log(e.constructor.name); }
        }
        outer(0); outer(1);
        """): 'TypeError\n6\n',
    a_program("""
        function o() {
          { W(); var c = 5; function W() { console.log(c); } }
          W();
        }
        o();
        """): 'undefined\n5\n',
    a_program("""
        function o() {
          try { W(); console.log('ran'); } catch (e) { console.log(e.constructor.name); }
          { function W() {} }
        }
        o();
        """): 'TypeError\n',
    a_program("""
        function o() {
          var a = String.fromCharCode(65);
          { function T() { String.fromCharCode = function () { return 'T'; }; } }
          T();
          var b = String.fromCharCode(66);
          return a + b;
        }
        console.log(o());
        """): 'AT\n',
    a_program("""
        function o() {
          var a = String.fromCharCode(65);
          { T(); function T() { String.fromCharCode = function () { return 'T'; }; } }
          var b = String.fromCharCode(66);
          return a + b;
        }
        console.log(o());
        """): 'AT\n',
    a_program("""
        function o() {
          var x;
          { function W() { return x; } }
          console.log(W());
          x = 5;
          console.log(W());
        }
        o();
        """): 'undefined\n5\n',
    a_program("""
        function o() {
          var c = 7;
          { function W() { return c; } console.log(W()); }
          return W();
        }
        console.log(o());
        """): '7\n7\n',
    a_program("""
        function o() {
          { function W() { return c; } }
          console.log(W());
          var c = 8;
          console.log(W());
        }
        o();
        """): 'undefined\n8\n',
    a_program("""
        function o() {
          { function W() { return c; } }
          try { console.log(W()); } catch (e) { console.log(e.constructor.name); }
          let c = 9;
          console.log(W());
        }
        o();
        """): 'ReferenceError\n9\n',
    a_program("""
        function o() {
          try { console.log(W()); } catch (e) { console.log(e.constructor.name); }
          if (true) { function W() { return 1; } }
          console.log(W());
        }
        o();
        """): 'TypeError\n1\n',
    a_program("""
        try { console.log(W()); } catch (e) { console.log(e.constructor.name); }
        if (1) { function W() { return 2; } }
        console.log(W());
        """): 'TypeError\n2\n',
    a_program("""
        function o() {
          if (true) { console.log(W()); function W() { return 3; } }
          return W();
        }
        console.log(o());
        """): '3\n3\n',
    a_program("""
        function outer() {
          var W;
          try { console.log(W()); } catch (e) { console.log(e.constructor.name); }
          { function W() { return 1; } }
          console.log(W());
        }
        outer();
        """): 'TypeError\n1\n',
    a_program("""
        function outer() {
          function wrap(a) { return target(a); }
          {
            var r;
            try { r = wrap(1); } catch (e) { r = e.constructor.name; }
            console.log(r);
            function target(a) { return a + 1; }
          }
          console.log(wrap(2));
        }
        outer();
        """): 'TypeError\n3\n',
    a_program("""
        function outer() {
          function once() { return typeof f; }
          {
            console.log(once());
            function f() {}
          }
          console.log(typeof f);
        }
        outer();
        """): 'undefined\nfunction\n',
    a_program("""
        function outer() {
          var show = function () { return typeof f; };
          var r = [];
          { r.push(show()); function f() {} r.push(show()); }
          return r.join(',');
        }
        console.log(outer());
        """): 'undefined,function\n',
    a_program("""
        function outer() {
          var r = [];
          try { r.push(f()); } catch (e) { r.push(e.constructor.name); }
          if (true) function f() { return 1; }
          r.push(f());
          return r.join();
        }
        console.log(outer());
        """): 'TypeError,1\n',
    a_program("""
        function outer(x) {
          if (x) var y = 1; else function f() { return 2; }
          return typeof f;
        }
        console.log(outer(true), outer(false));
        """): 'undefined function\n',
    a_program("""
        function outer() {
          var r = [];
          { r.push(f()); function f() { return 1; } r.push(f()); function f() { return 2; } }
          r.push(f());
          return r.join();
        }
        console.log(outer());
        """): '2,2,2\n',
    a_program("""
        function g() { return f.length; }
        {
          var r;
          try { r = g(); } catch (e) { r = e.constructor.name; }
          console.log(r);
          function f(a) { return 1; }
        }
        console.log(g());
        """): 'TypeError\n1\n',
}

#: Programs declaring a variable named like a function declared in a block, which holds its
#: own values until the declaration runs and the function from then on, mapped to what Node
#: prints for them.
A_VARIABLE_NAMED_LIKE_A_BLOCK_FUNCTION = {
    a_program("""
        function outer() {
          var W = 14;
          console.log(W);
          { function W() { return 15; } }
          console.log(typeof W);
        }
        outer();
        """): '14\nfunction\n',
    a_program("""
        function outer(p) {
          var a = p;
          { function a() { return 'f'; } }
          return typeof a;
        }
        console.log(outer(1));
        """): 'function\n',
    a_program("""
        function outer() {
          var t;
          t = 'abc';
          function g() { return t; }
          console.log(g());
          { function t() {} }
          console.log(typeof g());
        }
        outer();
        """): 'abc\nfunction\n',
    a_program("""
        function o() {
          var W = 4;
          if (false) { function W() { return 5; } }
          return W;
        }
        console.log(o());
        """): '4\n',
    a_program("""
        function outer() {
          var t = 'abc';
          for (var i = 0; i < 2; i++) {
            console.log(typeof t);
            { function t() {} }
          }
        }
        outer();
        """): 'string\nfunction\n',
    a_program("""
        function outer(c) {
          var t = 'abc';
          if (c) { function t() {} }
          return typeof t;
        }
        console.log(outer(0), outer(1));
        """): 'string function\n',
    a_program("""
        function outer() {
          var t = 'abc';
          function g() { return typeof t; }
          var r = [g()];
          { function t() {} }
          r.push(g());
          return r.join(',');
        }
        console.log(outer());
        """): 'string,function\n',
    a_program("""
        var t = 'abc';
        function g() { return typeof t; }
        console.log(g());
        { function t() {} }
        console.log(g());
        """): 'string\nfunction\n',
    a_program("""
        function outer() {
          { function f() { return 1; } function f() { return 2; } }
          return f();
        }
        console.log(outer());
        """): '2\n',
    a_program("""
        var t = "abc";
        function g(n) { return n <= 0 ? t : g(n - 1); }
        console.log(g(1));
        { function t() {} }
        console.log(typeof g(1));
        """): 'abc\nfunction\n',
    a_program("""
        var t = "abc";
        console.log(t);
        { function t() {} }
        console.log(typeof t);
        """): 'abc\nfunction\n',
}

#: Programs writing the name of a function declared in a block inside the block, directly or
#: through a closure, before or after the declaration runs and hands what the name holds to
#: the variable outside the block, mapped to what Node prints for them.
A_BLOCK_NAME_WRITTEN_BEFORE_THE_COPY = {
    a_program("""
        function outer() {
          { W = 9; function W() { return 1; } }
          console.log(W);
        }
        outer();
        """): '9\n',
    a_program("""
        function outer() {
          { function W() { return 1; } W = 9; }
          console.log(typeof W);
        }
        outer();
        """): 'function\n',
    a_program("""
        function outer() {
          var fs = [];
          for (var i = 0; i < 2; i++) { function W() { return i; } fs.push(W); }
          return [fs[0] === fs[1], W === fs[1]].join(',');
        }
        console.log(outer());
        """): 'false,true\n',
    a_program("""
        function outer() {
          var set;
          { set = function () { f = function () { return 2; }; }; set(); function f() { return 1; } }
          return f();
        }
        console.log(outer());
        """): '2\n',
    a_program("""
        var set;
        { set = function () { f = 'two'; }; set(); function f() { return 1; } }
        console.log(f);
        """): 'two\n',
    a_program("""
        function outer() {
          var set;
          { set = function () { f = 'two'; }; set(); function f() { return 1; } }
          return typeof f;
        }
        console.log(outer());
        """): 'string\n',
    a_program("""
        function outer() {
          var bump;
          { bump = function () { f = 7; }; for (var i = 0; i < 1; i++) bump(); function f() {} }
          return f;
        }
        console.log(outer());
        """): '7\n',
    a_program("""
        function outer() {
          var set;
          { set = function () { f = 'two'; }; function f() { return 1; } set(); }
          return typeof f;
        }
        console.log(outer());
        """): 'function\n',
    a_program("""
        function outer() {
          var o = {};
          { o.set = () => { f = 'two'; }; o.set(); function f() { return 1; } }
          return typeof f;
        }
        console.log(outer());
        """): 'string\n',
    a_program("""
        function outer() {
          var set;
          { set = function () { f = 'two'; }; set(); function f() { return 1; } }
          function show() { return typeof f; }
          return show();
        }
        console.log(outer());
        """): 'string\n',
    a_program("""
        function outer() {
          var set;
          { set = function () { f = 'two'; return typeof f; }; set(); function f() { return 1; } }
          return typeof f;
        }
        console.log(outer());
        """): 'string\n',
    a_program("""
        function outer() {
          var set;
          { set = function () { f.x = 2; }; function f() {} }
          set();
          return f.x;
        }
        console.log(outer());
        """): '2\n',
    a_program("""
        function outer() {
          var add;
          { add = function () { f = []; f.push(5); }; add(); function f() {} }
          return f.length;
        }
        console.log(outer());
        """): '1\n',
    a_program("""
        function outer() {
          {
            var set = function () { f = 'two'; };
            { set(); }
            function f() {}
          }
          return typeof f;
        }
        console.log(outer());
        """): 'string\n',
    a_program("""
        function outer() {
          var n;
          { n = function (v) { f = v; return v; }; n(1); n(2); function f() {} }
          return f;
        }
        console.log(outer());
        """): '2\n',
    a_program("""
        function outer() {
          var set;
          { set = function () { f = 'two'; return 1; }; var r = set(); function f() {} }
          return [r, typeof f].join(',');
        }
        console.log(outer());
        """): '1,string\n',
    a_program("""
        function outer() {
          var set;
          { set = function () { f.x = 2; }; set(); function f() {} }
          return f.x;
        }
        console.log(outer());
        """): '2\n',
    a_program("""
        function outer() {
          var set;
          { set = function () { console.log('set'); f = 'two'; }; set(); function f() {} }
          return typeof f;
        }
        console.log(outer());
        """): 'set\nstring\n',
    a_program("""
        function outer() {
          {
            g();
            function g() { f = 'two'; }
            function f() {}
          }
          return typeof f;
        }
        console.log(outer());
        """): 'string\n',
    a_program("""
        function read() { return typeof f; }
        var f;
        var set;
        { set = function () { f = 'two'; }; set(); function f() {} }
        console.log(read());
        """): 'string\n',
    a_program("""
        function outer() {
          var set;
          { set = function () { f = function () { String.prototype.trim = function () { return "T"; }; }; }; set(); function f() {} }
          f();
          return ' a '.trim();
        }
        console.log(outer());
        """): 'T\n',
    a_program("""
        function outer() {
          var r = [];
          { function f(a) { return a * 2; } r.push(f(1)); }
          r.push(f(2));
          return r.join();
        }
        console.log(outer());
        """): '2,4\n',
    a_program("""
        function outer(o) {
          { function f() { return 1; } }
          with (o) { return f(); }
        }
        console.log(outer({}), outer({ f: function () { return 2; } }));
        """): '1 2\n',
    a_program("""
        function outer(s) {
          { function f() { return 1; } f.a = 1; }
          return eval(s);
        }
        console.log(outer('typeof f'), outer('f.a'));
        """): 'function 1\n',
}

#: Programs reaching one function declared in a block through both of its names: calling,
#: constructing and handing it on, and storing, deleting or asking for its properties through
#: one name and reading them through the other, mapped to what Node prints for them.
ONE_FUNCTION_THROUGH_TWO_NAMES = {
    a_program("""
        function outer() {
          { function W() { return 1; } console.log(W()); }
          console.log(W());
        }
        outer();
        """): '1\n1\n',
    a_program("""
        function outer() {
          { function W() { return 7; } }
          return function () { return W(); };
        }
        console.log(outer()());
        """): '7\n',
    a_program("""
        function outer() {
          var r = [];
          { function W(a) { r.push(a); return a * 2; } r.push(W(1)); }
          r.push(W(3));
          return r.join(',');
        }
        console.log(outer());
        """): '1,2,3,6\n',
    a_program("""
        function outer() {
          { function W(x) { return x + 1; } }
          return [1, 2].map(W).join(',');
        }
        console.log(outer());
        """): '2,3\n',
    a_program("""
        function outer() {
          { function W() { String.fromCharCode = function () { return 'T'; }; } }
          W();
          return String.fromCharCode(65);
        }
        console.log(outer());
        """): 'T\n',
    a_program("""
        function outer() {
          { function P(v) { this.v = v; } }
          var p = new P(8);
          return p.v;
        }
        console.log(outer());
        """): '8\n',
    a_program("""
        function outer() {
          var o = { k: 1 };
          { function P() { this.k = 9; } }
          P.call(o);
          return o.k;
        }
        console.log(outer());
        """): '9\n',
    a_program("""
        function outer() {
          { function W() { return 10; } }
          with ({}) { return W(); }
        }
        console.log(outer());
        """): '10\n',
    a_program("""
        function outer(s) {
          { function W() { return 11; } }
          return eval(s);
        }
        console.log(outer('W()'));
        """): '11\n',
    a_program("""
        function outer() {
          { function W() { return 12; } }
          function h() { return W(); }
          return h();
        }
        console.log(outer());
        """): '12\n',
    a_program("""
        { function W() { return 13; } }
        console.log(W());
        """): '13\n',
    a_program("""
        function outer() {
          { function W() { return W.x; } }
          W.x = 5;
          return W();
        }
        console.log(outer());
        """): '5\n',
    a_program("""
        function outer() {
          { function W() {} W.list = []; }
          W.list.push(1);
          return W.list.length;
        }
        console.log(outer());
        """): '1\n',
    a_program("""
        function outer() {
          { function W(a) { return a + 1; } }
          W.toString = function () { return 'T'; };
          return String(W);
        }
        console.log(outer());
        """): 'T\n',
    a_program("""
        function outer() {
          var get;
          { function f() {} f.a = 5; get = function () { return 'a' in f; }; }
          delete f.a;
          return get();
        }
        console.log(outer());
        """): 'false\n',
    a_program("""
        function outer() {
          var has;
          { function f() {} has = function () { return 'b' in f; }; }
          f.b = 1;
          return has();
        }
        console.log(outer());
        """): 'true\n',
    a_program("""
        function outer() {
          { function f() {} f.a = 5; }
          return 'a' in f;
        }
        console.log(outer());
        """): 'true\n',
    a_program("""
        { function f() {} f.a = 5; }
        console.log('a' in f);
        """): 'true\n',
    a_program("""
        function outer() {
          var keep = [];
          { function f() { return 3; } keep.push(f); }
          keep[0].tag = 1;
          return [f(), f.tag].join();
        }
        console.log(outer());
        """): '3,1\n',
}

#: Programs whose deobfuscation moves code into, out of or next to a block declaring a
#: function, by inlining, flattening a namespace, unwrapping a dispatcher or recovering a
#: generator, where a name may mean the other binding, mapped to what Node prints for them.
CODE_MOVED_ACROSS_A_BLOCK_FUNCTION = {
    a_program("""
        function outer() {
          var NS = { k: 1, m: function () { return 2; } };
          { function k() { return 'f'; } }
          return [NS.k, NS.m(), typeof k].join(',');
        }
        console.log(outer());
        """): '1,2,function\n',
    a_program("""
        var out = (function () {
          var v = 'local';
          { function v2() {} }
          return v;
        })();
        { function v() { return 'f'; } }
        console.log(out, typeof v);
        """): 'local function\n',
    a_program("""
        function g() { var W = 1; return W; }
        function outer() {
          console.log(g());
          { function W() { return 2; } }
          console.log(W());
        }
        outer();
        """): '1\n2\n',
    a_program("""
        function outer() {
          var NS = {};
          NS.k = function () { return 'm'; };
          { function k() { return 'f'; } }
          return [NS.k(), typeof k, k()].join(',');
        }
        console.log(outer());
        """): 'm,function,f\n',
    a_program("""
        var NS = {};
        NS.k = function () { return 'm'; };
        console.log(NS.k());
        { function k() { return 'f'; } }
        console.log(k());
        """): 'm\nf\n',
    a_program("""
        var W = 'outer';
        var r = (function () { { function W() { return 1; } } return W(); })();
        console.log(r, typeof W);
        """): '1 string\n',
    a_program("""
        console.log(typeof W);
        var r = (function () { { function W() { return 1; } } return W(); })();
        console.log(r, typeof W);
        """): 'undefined\n1 undefined\n',
    a_program("""
        {
          console.log(typeof X);
          var X = (function () { return function () { return 1; }; })();
        }
        console.log(X());
        """): 'undefined\n1\n',
    a_program("""
        function wrap(W) { return W + 1; }
        function outer() {
          var a = wrap(1);
          { function W() { return 2; } }
          return [a, W()].join(',');
        }
        console.log(outer());
        """): '2,2\n',
    a_program("""
        function o() {
          {
            (function () { var f = 1; console.log(f); })();
            function f() { return 2; }
          }
          return f();
        }
        console.log(o());
        """): '1\n2\n',
    a_program("""
        {
          (function () { var f = 1; console.log(f); })();
          function f() { return 2; }
        }
        console.log(f());
        """): '1\n2\n',
    a_program("""
        function g() { var f = 3; return f + 1; }
        function o() {
          { var r = g(); function f() { return 5; } }
          return [r, f()].join(',');
        }
        console.log(o());
        """): '4,5\n',
    a_program("""
        var f = 'top';
        var w = (function () { { function f() { return 6; } } return f(); })();
        console.log(w, f);
        """): '6 top\n',
    a_program("""
        function outer(k) {
          {
            function f(v) { return v + k; }
            function g(x) { return f(x); }
          }
          f = function (v) { return 'other'; };
          return g(1);
        }
        console.log(outer(2));
        """): '3\n',
    a_program("""
        function target() { return 'T'; }
        function outer() {
          {
            function f(a) { return 'inner' + a; }
            function w(a) { return f(a); }
          }
          f = target;
          return w(1);
        }
        console.log(outer());
        """): 'inner1\n',
    a_program("""
        function outer() {
          { function f(a) { return 'copy' + a; } }
          function w(a) { return f(a); }
          {
            console.log(w(1));
            function f(a) { return 'inner' + a; }
          }
          console.log(w(2));
        }
        outer();
        """): 'copy1\ninner2\n',
    a_program("""
        var r = (function f() {
          var before = typeof f;
          { function f() { return 1; } }
          return before + ',' + typeof f + ',' + f();
        })();
        console.log(r);
        """): 'undefined,function,1\n',
    a_program("""
        var ns = {};
        ns.a = 1;
        ns.b = 2;
        function inner() { { function ns() {} } ns.a = 5; return ns.a; }
        console.log(ns.a + ns.b, inner());
        """): '3 5\n',
    a_program("""
        var ns = {};
        ns.a = 1;
        ns.b = 2;
        function inner() { function ns() {} ns.a = 5; return ns.a; }
        console.log(ns.a + ns.b, inner());
        """): '3 5\n',
    a_program("""
        function once() { var x = 5; return x; }
        function outer() {
          { function x() { return 1; } console.log(once()); }
          return typeof x;
        }
        console.log(outer());
        """): '5\nfunction\n',
    a_program("""
        var log = [];
        function once() { var x = 5; log.push(x); }
        function outer() {
          { function x() { return 1; } once(); }
          return typeof x;
        }
        console.log(outer(), log.join());
        """): 'function 5\n',
    a_program("""
        function w(a) { var x = a + 1; return x; }
        function outer() {
          { function x() { return 1; } var r = w(1); }
          return [r, typeof x].join();
        }
        console.log(outer());
        """): '2,function\n',
    a_program("""
        function outer(n) {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.t = n;
                    var hold = function(...rest) {
                      return gen(20, 30, {}, rest)["next"]()["value"];
                    };
                    return done = true, [hold, function () { return t; }];
                    break;
                  case 50:
                    scope.t = args[0];
                    return done = true, function () { return t; };
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          { function t() { return 'f'; } }
          if (done) { return [result[1](), typeof t]; }
        }
        console.log(outer(1).join(','));
        """): '1,function\n',
    a_program("""
        function outer(n) {
          { function t() { return 'f'; } }
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.t = n;
                    var hold = function(...rest) {
                      return gen(20, 30, {}, rest)["next"]()["value"];
                    };
                    return done = true, [hold, function () { return t; }];
                    break;
                  case 50:
                    scope.t = args[0];
                    return done = true, function () { return t; };
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return [result[1](), typeof t]; }
        }
        console.log(outer(1).join(','));
        """): '1,function\n',
    a_program("""
        var probe;
        function outer(n) {
          { function t() { return 'f'; } }
          probe = function () { return typeof t; };
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.t = n;
                    var hold = function(...rest) {
                      return gen(20, 30, {}, rest)["next"]()["value"];
                    };
                    return done = true, [hold, function () { return t; }];
                    break;
                  case 50:
                    scope.t = args[0];
                    return done = true, function () { return t; };
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        var r = outer(1);
        console.log(r[1](), probe());
        """): '1 function\n',
    a_program("""
        { function setLen(fn, length) { return "block:" + length; } console.log(setLen(null, 2)); }
        function setLen(fn, length = 1) {
          Object["defineProperty"](fn, "length", { "value": length, "configurable": false });
          return fn;
        }
        var c = Object["create"](null);
        var p;
        function d(name, flagArg, returnTypeArg, fnLengths = {}) {
          var output;
          var fns = {
        "k1": function () { var [a, b] = p; return a + b; },
        "k2": function () { return 7; }
          };
          if (flagArg === "clearF") { p = []; }
          if (flagArg === "createF") {
            function createFunction() {
              var fn = function (...args) { p = args; return fns[name].apply(this); };
              var fnLength = fnLengths[name];
              if (fnLength) { setLen(fn, fnLength); }
              return fn;
            }
            output = c[name] || (c[name] = createFunction());
          } else {
            output = fns[name]();
          }
          if (returnTypeArg === "wrapF") { return { "wk": output }; }
          else { return output; }
        }
        console.log((p = [1, 2], d("k1")), (p = [], d("k2")));
        """): 'block:2\n3 7\n',
    a_program("""
        function setLen(fn, length = 1) {
          Object["defineProperty"](fn, "length", { "value": length, "configurable": false });
          return fn;
        }
        var c = Object["create"](null);
        var p;
        function d(name, flagArg, returnTypeArg, fnLengths = {}) {
          var output;
          var fns = {
        "k1": function () { var [a, b] = p; return a + b; },
        "k2": function () { return 7; }
          };
          if (flagArg === "clearF") { p = []; }
          if (flagArg === "createF") {
            function createFunction() {
              var fn = function (...args) { p = args; return fns[name].apply(this); };
              var fnLength = fnLengths[name];
              if (fnLength) { setLen(fn, fnLength); }
              return fn;
            }
            output = c[name] || (c[name] = createFunction());
          } else {
            output = fns[name]();
          }
          if (returnTypeArg === "wrapF") { return { "wk": output }; }
          else { return output; }
        }
        console.log((p = [1, 2], d("k1")));
        { function setLen(fn, length) { return "block:" + length; } console.log(setLen(null, 2)); }
        """): '3\nblock:2\n',
}

#: Programs declaring a function in a block of a shape of its own: under a label, as the
#: clause of an `if`, in a block holding one of its name, named `arguments` or like a
#: parameter, in a dead branch, mapped to what Node prints for them.
A_BLOCK_FUNCTION_IN_A_SHAPE_OF_ITS_OWN = {
    a_program("""
        function o() {
          { function f() { return 1; } { function f() { return 2; } } }
          return f();
        }
        console.log(o());
        """): '2\n',
    a_program("""
        function o() {
          var r = [];
          { function f() { return 1; } { function f() { return 2; } r.push(f()); } r.push(f()); }
          r.push(f());
          return r.join(',');
        }
        console.log(o());
        """): '2,1,2\n',
    a_program("""
        function o() {
          let f = 1;
          { lab: function f() { return 2; } console.log(typeof f); }
          return f;
        }
        console.log(o());
        """): 'function\n1\n',
    a_program("""
        function o() {
          { lab: function f() { return 3; } console.log(f()); }
          return f();
        }
        console.log(o());
        """): '3\n3\n',
    a_program("""
        function o() {
          { function arguments() { return 4; } }
          return typeof arguments;
        }
        console.log(o(1));
        """): 'function\n',
    a_program("""
        function o() {
          { function f() { return 5; } function f() { return 6; } }
          return f();
        }
        console.log(o());
        """): '6\n',
    a_program("""
        function o() {
          try { throw 7; } catch (f) {
            { function f() { return 8; } }
            console.log(f);
          }
          return typeof f;
        }
        console.log(o());
        """): '7\nfunction\n',
    a_program("""
        function o() {
          var obj = { f: 9 };
          with (obj) { { function f() { return 10; } } }
          return [obj.f, typeof f].join(',');
        }
        console.log(o());
        """): '9,function\n',
    a_program("""
        function o() {
          { function f() { return 11; } }
          var f = 12;
          return f;
        }
        console.log(o());
        """): '12\n',
    a_program("""
        function o(a = 1) {
          { function f() { return a; } }
          return f();
        }
        console.log(o());
        """): '1\n',
    a_program("""
        function outer() {
          { function arguments() { return 1; } }
          return typeof arguments;
        }
        console.log(outer(1, 2));
        """): 'function\n',
    a_program("""
        function outer() {
          { function arguments(a, b, c) { return 1; } }
          return arguments.length;
        }
        console.log(outer(1, 2));
        """): '3\n',
    a_program("""
        function outer() {
          var r = [];
          { function f() { return 1; } { function f() { return 2; } r.push(f()); } r.push(f()); }
          r.push(f());
          return r.join();
        }
        console.log(outer());
        """): '2,1,2\n',
    a_program("""
        function outer() {
          { function f() { return 1; } var dead = f(); }
          return f();
        }
        console.log(outer());
        """): '1\n',
    a_program("""
        { function f() { return 1; } var dead = f(); }
        console.log(f());
        """): '1\n',
    a_program("""
        function outer() {
          function f() { return 1; }
          function g() { return f(); }
          var dead = f();
          return g();
        }
        console.log(outer());
        """): '1\n',
    a_program("""
        function outer() {
          if (true) function f() { f = 2; return 1; }
          var a = f();
          return [a, typeof f].join();
        }
        console.log(outer());
        """): '1,function\n',
}

#: Scripts writing the name of a function declared in a block at the top level before the
#: declaration runs, and reading the variable it is copied into through the global object,
#: mapped to what Node prints for them when it runs them as classic scripts.
A_TOP_LEVEL_BLOCK_NAME_READ_THROUGH_THE_GLOBAL_OBJECT = {
    a_program("""
        { f = 9; function f() {} }
        console.log(globalThis.f);
        """): '9\n',
    a_program("""
        var set;
        { set = function () { f = 9; }; set(); function f() {} }
        console.log(globalThis.f);
        """): '9\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutAFunctionDeclaredInABlock(TestBase):

    def test_a_name_is_called_only_once_it_holds_the_function(self):
        rows = A_CALL_ORDERED_BY_THE_NAME_IT_READS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_variable_of_the_name_holds_its_own_values_until_the_declaration_runs(self):
        rows = A_VARIABLE_NAMED_LIKE_A_BLOCK_FUNCTION
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_the_variable_receives_what_the_block_name_holds_when_the_declaration_runs(self):
        rows = A_BLOCK_NAME_WRITTEN_BEFORE_THE_COPY
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_both_names_reach_one_function_object(self):
        rows = ONE_FUNCTION_THROUGH_TWO_NAMES
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_moved_code_reads_the_binding_it_read_where_it_stood(self):
        rows = CODE_MOVED_ACROSS_A_BLOCK_FUNCTION
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_the_name_is_bound_where_the_language_binds_it(self):
        rows = A_BLOCK_FUNCTION_IN_A_SHAPE_OF_ITS_OWN
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_script_reads_the_variable_through_the_global_object(self):
        rows = A_TOP_LEVEL_BLOCK_NAME_READ_THROUGH_THE_GLOBAL_OBJECT
        self.assertEqual(
            {source: before_and_after_in_a_host(source) for source in rows},
            each_program_still_prints(rows),
        )
