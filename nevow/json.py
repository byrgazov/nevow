# -*- test-case-name: nevow.test.test_json -*-
# Copyright (c) 2004-2007 Divmod.
# See LICENSE for details.

"""
JavaScript Object Notation.

This is not (nor does it intend to be) a faithful JSON implementation, but it
is kind of close.
"""

import re, types

from twisted.python import compat

from nevow.inevow import IAthenaTransportable
from nevow import rend, page, _flat, tags

class ParseError(ValueError):
    pass

whitespace = re.compile(
            ur'('
            ur'[\r\n\t\ ]+'
            ur'|/\*.*?\*/'
            ur'|//[^\n]*[\n]'
            ur')'
            , re.VERBOSE + re.DOTALL)
openBrace = re.compile(ur'{')
closeBrace = re.compile(ur'}')
openSquare = re.compile(ur'\[')
closeSquare = re.compile(ur'\]')

class StringTokenizer(object):
    """
    because r'(?<!\\)"([^"]+|\\")*(?<!\\)"'
    """

    def match(self, s):
        if not s.startswith(u'"'):
            return None

        bits = []

        SLASH = u"\\"

        IT = iter(s)
        bits = [next(IT)]
        for char in IT:
            bits.append(char)
            if char == SLASH:
                try:
                    bits.append(next(IT))
                except StopIteration:
                    return None
            if char == u'"':
                self.matched = u''.join(bits)
                return self

        return None

    def group(self, num):
        return self.matched

string = StringTokenizer()
identifier = re.compile(u'[A-Za-z_][A-Za-z_0-9]*')
colon = re.compile(u':')
comma = re.compile(u',')
true = re.compile(u'true')
false = re.compile(u'false')
null = re.compile(u'null')
undefined = re.compile(u'undefined')
floatNumber = re.compile(ur'-?([1-9][0-9]*|0)(\.[0-9]+)([eE][-+]?[0-9]+)?')
longNumber = re.compile(u'-?([1-9][0-9]*|0)([eE][-+]?[0-9]+)?')

class StringToken(compat.unicode):
    pass

class IdentifierToken(compat.unicode):
    pass

class WhitespaceToken(object):
    pass

def jsonlong(s):
    if u'e' in s:
        m, e = list(map(int, s.split(u'e', 1)))
    else:
        m, e = int(s), 0
    return m * 10 ** e

# list of tuples, the first element is a compiled regular expression the second
# element returns a token and the original string.
actions = [
    (whitespace, lambda s: (WhitespaceToken, s)),
    (openBrace, lambda s: (u'{',s)),
    (closeBrace, lambda s: (u'}',s)),
    (openSquare, lambda s: (u'[',s)),
    (closeSquare, lambda s: (u']',s)),
    (string, lambda s: (StringToken(s), s)),
    (colon, lambda s: (u':', s)),
    (comma, lambda s: (u',', s)),
    (true, lambda s: (True, s)),
    (false, lambda s: (False, s)),
    (null, lambda s: (None, s)),
    (undefined, lambda s: (None, s)),
    (identifier, lambda s: (IdentifierToken(s), s)),
    (floatNumber, lambda s: (float(s), s)),
    (longNumber, lambda s: (jsonlong(s), s)),
]
def tokenise(s):
    tokens = []
    while s:
        for regexp, action in actions:
            m = regexp.match(s)
            if m:
                tok, tokstr = action(m.group(0))
                break
        else:
            raise ValueError("Invalid Input, %r" % (s[:10],))

        if tok is not WhitespaceToken:
            tokens.append(tok)
        s = s[len(tokstr):]

    return tokens

def accept(want, tokens):
    t = tokens.pop(0)
    if want != t:
        raise ParseError("Unexpected %r, %s expected" % (t , want))

def parseValue(tokens):
    if tokens[0] == u'{':
        return parseObject(tokens)

    if tokens[0] == u'[':
        return parseList(tokens)

    if tokens[0] in (True, False, None):
        return tokens.pop(0), tokens

    if type(tokens[0]) == StringToken:
        return parseString(tokens)

    if type(tokens[0]) in (int, float, compat.long):
        return tokens.pop(0), tokens

    raise ParseError("Unexpected %r" % tokens[0])


_stringExpr = re.compile(
    ur'(?:\\x(?P<unicode>[a-fA-F0-9]{2})) # Match hex-escaped unicode' '\n'
    ur'|' '\n'
    ur'(?:\\u(?P<unicode2>[a-fA-F0-9]{4})) # Match hex-escaped high unicode' '\n'
    ur'|' '\n'
    ur'(?P<control>\\[fbntr\\"]) # Match escaped control characters' '\n',
    re.VERBOSE)

_controlMap = {
    u'\\f': u'\f',
    u'\\b': u'\b',
    u'\\n': u'\n',
    u'\\t': u'\t',
    u'\\r': u'\r',
    u'\\"': u'"',
    u'\\\\': u'\\',
    }

def _stringSub(m):
    u = m.group('unicode')
    if u is None:
        u = m.group('unicode2')
    if u is not None:
        return unichr(int(u, 16))
    c = m.group('control')
    return _controlMap[c]


def parseString(tokens):
    if type(tokens[0]) is not StringToken:
        raise ParseError("Unexpected %r" % tokens[0])
    s = _stringExpr.sub(_stringSub, tokens.pop(0)[1:-1])
    return s, tokens


def parseIdentifier(tokens):
    if type(tokens[0]) is not IdentifierToken:
        raise ParseError("Unexpected %r" % (tokens[0],))
    return tokens.pop(0), tokens


def parseList(tokens):
    l = []
    tokens.pop(0)
    first = True
    while tokens[0] != u']':
        if not first:
            accept(u',', tokens)
        first = False

        value, tokens = parseValue(tokens)
        l.append(value)

    accept(u']', tokens)
    return l, tokens


def parseObject(tokens):
    o = {}
    tokens.pop(0)
    first = True
    while tokens[0] != u'}':
        if not first:
            accept(u',', tokens)
        first = False

        name, tokens = parseString(tokens)
        accept(u':', tokens)
        value, tokens = parseValue(tokens)
        o[name] = value

    accept(u'}', tokens)
    return o, tokens


def parse(s):
    """
    Return the object represented by the JSON-encoded string C{s}.
    """
    if isinstance(s, bytes):
        s = s.decode("utf-8")

    tokens = tokenise(s)
    value, tokens = parseValue(tokens)
    if tokens:
        raise ParseError("Unexpected %r" % tokens[0])
    return value

class CycleError(Exception):
    pass

_translation = dict([(o, u'\\x%02x' % (o,)) for o in range(0x20)])

# Characters which cannot appear as literals in the output
_translation.update({
    ord('\\'): u'\\\\',
    ord('"'): ur'\"',
    ord('\f'): ur'\f',
    ord('\b'): ur'\b',
    ord('\n'): ur'\n',
    ord('\t'): ur'\t',
    ord('\r'): ur'\r',
    # The next two are sneaky, see
    # http://timelessrepo.com/json-isnt-a-javascript-subset
    ord(u'\u2028'): u'\\u2028',
    ord(u'\u2029'): u'\\u2029',
    })

def stringEncode(s):
    if not isinstance(s, compat.unicode):
        s = s.decode('utf-8')
    return s.translate(_translation)


def _serialize(obj, w, seen):
    from nevow import athena

    if isinstance(obj, bool):
        if obj:
            w(u'true')
        else:
            w(u'false')
    elif isinstance(obj, (int, float)):
        w(str(obj))
    elif isinstance(obj, (bytes, unicode)):
        w(u'"')
        w(stringEncode(obj))
        w(u'"')
    elif isinstance(obj, type(None)):
        w(u'null')
    elif id(obj) in seen:
        raise CycleError(type(obj))
    elif isinstance(obj, (tuple, list)):
        w(u'[')
        for n, e in enumerate(obj):
            _serialize(e, w, seen)
            if n != len(obj) - 1:
                w(u',')
        w(u']')
    elif isinstance(obj, dict):
        w(u'{')
        for n, (k, v) in enumerate(obj.items()):
            _serialize(k, w, seen)
            w(u':')
            _serialize(v, w, seen)
            if n != len(obj) - 1:
                w(u',')
        w(u'}')
    elif isinstance(obj, (athena.LiveFragment, athena.LiveElement)):
        _serialize(obj._structured(), w, seen)
    elif isinstance(obj, (rend.Fragment, page.Element)):
        def _w(s):
            w(stringEncode(s))
        wrapper = tags.div(xmlns="http://www.w3.org/1999/xhtml")
        w(u'"')
        for _ in _flat.flatten(None, _w, wrapper[obj], False, False):
            pass
        w(u'"')
    else:
        transportable = IAthenaTransportable(obj, None)
        if transportable is not None:
            w(u'(new ' + compat.unicode(
                transportable.jsClass.encode('ascii')) + u'(')
            arguments = transportable.getInitialArguments()
            for n, e in enumerate(arguments):
                _serialize(e, w, seen)
                if n != len(arguments) - 1:
                    w(',')
            w(u'))')
        else:
            raise TypeError("Unsupported type %r: %r" % (type(obj), obj))



_undefined = object()
def serialize(obj=_undefined, **kw):
    """
    JSON-encode an object.

    @param obj: None, True, False, an int, long, float, unicode string,
    list, tuple, or dictionary the JSON-encoded form of which will be
    returned.
    """
    if obj is _undefined:
        obj = kw

    L = []
    _serialize(obj, L.append, {})
    return u''.join(L)

__all__ = ['parse', 'serialize']
