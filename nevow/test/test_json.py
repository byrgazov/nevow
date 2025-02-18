# Copyright (c) 2004-2007 Divmod.
# See LICENSE for details.

"""
Tests for L{nevow.json}.
"""

from twisted.python import compat

from zope.interface import implementer

from nevow.inevow import IAthenaTransportable
from nevow import json, rend, page, loaders, tags, athena, testutil

from twisted.trial import unittest

TEST_OBJECTS = [
    0,
    None,
    True,
    False,
    [],
    [0],
    [0, 1, 2],
    [None, 1, 2],
    [None, 'one', 2],
    [True, False, 'string', 10],
    [[1, 2], [3, 4]],
    [[1.5, 2.5], [3.5, 4.5]],
    [0, [1, 2], ['hello'], ['world'], [True, None, False]],
    {},
    {'foo': 'bar'},
    {'foo': None},
    {'bar': True},
    {'baz': [1, 2, 3]},
    {'quux': {'bar': 'foo'}},
    ]

TEST_STRINGLIKE_OBJECTS = [
    '',
    'string',
    'string with "embedded" quotes',
    "string with 'embedded' single-quotes",
    'string with \\"escaped embedded\\" quotes',
    "string with \\'escaped embedded\\' single-quotes",
    "string with backslashes\\\\",
    u"string with trailing accented vowels: \xe1\xe9\xed\xf3\xfa\xfd\xff",
    "string with trailing control characters: \f\b\n\t\r",
    u'string with high codepoint characters: \u0111\u2222\u3333\u4444\uffff',
    'string with very high codepoint characters: \U00011111\U00022222\U00033333\U00044444\U000fffff',
    ]


class DummyLivePage(object):
    """
    Stand-in for L{athena.LivePage} which implements only enough of its
    behavior so that a L{LiveFragment} or L{LiveElement} can be set as its
    child and flattened.
    """
    localCounter = 0

    def __init__(self):
        self.page = self
        self.liveFragmentChildren = []
        self._jsDepsMemo = {}
        self._cssDepsMemo = {}
        self._didConnect = True


    def addLocalObject(self, obj):
        """
        Return an Athena ID for the given object.  Returns a new value on every
        call.
        """
        self.localCounter += 1
        return self.localCounter


    def _shouldInclude(self, module):
        """
        Stub module-system method.  Always declares that the given module
        should not be included.
        """
        return False



class JavascriptObjectNotationTestCase(unittest.TestCase):

    def testSerialize(self):
        for struct in TEST_OBJECTS:
            json.serialize(struct)

    def testRoundtrip(self):
        for struct in TEST_OBJECTS:
            bytes = json.serialize(struct)
            unstruct = json.parse(bytes)
            self.assertEqual(
                unstruct, struct,
                "Failed to roundtrip %r: %r (through %r)" % (
                    struct, unstruct, bytes))


    def test_undefined(self):
        """
        C{undefined} is parsed as Python C{None}.
        """
        self.assertEqual(None, json.parse(b'undefined'))


    def testStringlikeRoundtrip(self):
        for struct in TEST_STRINGLIKE_OBJECTS:
            serialised = json.serialize(struct)
            deserialised = json.parse(serialised)
            failMsg = "Failed to roundtrip %r: %r (through %r)" % (
                    struct, deserialised, serialised)
            self.assertEqual(deserialised, struct, failMsg)
            self.assertTrue(isinstance(deserialised, compat.unicode), failMsg)


    def test_lineTerminators(self):
        """
        When passed a unicode string containing a line terminator,
        L{json.serialize} emits an escape sequence representing that character
        (not a UTF-8 sequence directly representing that the line terminator
        code point).

        Literal line terminators are allowed in JSON, but some parsers do not
        handle them properly.
        """
        # These are the four line terminators currently in Unicode.
        self.assertEqual(u'"\\r"', json.serialize("\r"))
        self.assertEqual(u'"\\n"', json.serialize("\n"))
        self.assertEqual(u'"\\u2028"', json.serialize(u"\u2028"))
        self.assertEqual(u'"\\u2029"', json.serialize(u"\u2029"))


    def testScientificNotation(self):
        self.assertEqual(json.parse('1e10'), 10**10)
        self.assertEqual(json.parse('1e0'), 1)


    def testHexEscapedCodepoints(self):
        self.assertEqual(
            json.parse('"\\xe1\\xe9\\xed\\xf3\\xfa\\xfd"'),
            u"\u00e1\u00e9\u00ed\u00f3\u00fa\u00fd")

    def testEscapedControls(self):
        self.assertEqual(
            json.parse('"\\f\\b\\n\\t\\r"'),
            "\f\b\n\t\r")


    def _rendererTest(self, cls):
        self.assertEqual(
            json.serialize(
                cls(
                    docFactory=loaders.stan(tags.p['Hello, world.']))),
            '"<div xmlns=\\"http://www.w3.org/1999/xhtml\\"><p>Hello, world.</p></div>"')


    def test_fragmentSerialization(self):
        """
        Test that instances of L{nevow.rend.Fragment} serialize as an xhtml
        string.
        """
        return self._rendererTest(rend.Fragment)


    def test_elementSerialization(self):
        """
        Test that instances of L{nevow.page.Element} serialize as an xhtml
        string.
        """
        return self._rendererTest(page.Element)


    def _doubleSerialization(self, cls):
        fragment = cls(docFactory=loaders.stan(tags.div['Hello']))
        self.assertEqual(
            json.serialize(fragment),
            json.serialize(fragment))


    def test_doubleFragmentSerialization(self):
        """
        Test that repeatedly calling L{json.serialize} with an instance of
        L{rend.Fragment} results in the same result each time.
        """
        return self._doubleSerialization(rend.Fragment)


    def test_doubleElementSerialization(self):
        """
        Like L{test_doubleElementSerialization} but for L{page.Element}
        instances.
        """
        return self._doubleSerialization(page.Element)


    def _doubleLiveSerialization(self, cls, renderer):
        livePage = DummyLivePage()
        liveFragment = cls(
            docFactory=loaders.stan(
                [tags.div(render=tags.directive(renderer))['Hello'],
                 tags.div(render=tags.directive('foo'))]))
        liveFragment.setFragmentParent(livePage)
        self.assertEqual(
            json.serialize(liveFragment),
            json.serialize(liveFragment))


    def test_doubleLiveFragmentSerialization(self):
        """
        Like L{test_doubleFragmentSerialization} but for L{athena.LiveFragment}
        instances.
        """
        class AnyLiveFragment(athena.LiveFragment):
            """
            Just some L{LiveFragment} subclass, such as an application might
            define.
            """
            def render_foo(self, ctx, data):
                return ctx.tag
        self._doubleLiveSerialization(AnyLiveFragment, 'liveFragment')


    def test_doubleLiveElementSerialization(self):
        """
        Like L{test_doubleFragmentSerialization} but for L{athena.LiveElement}
        instances.
        """
        requests = []
        class AnyLiveElement(athena.LiveElement):
            """
            Just some L{LiveElement} subclass, such as an application might
            define.
            """
            def foo(self, request, tag):
                requests.append(request)
                return tag
            page.renderer(foo)
        self._doubleLiveSerialization(AnyLiveElement, 'liveElement')
        self.assertTrue(isinstance(requests[0], testutil.FakeRequest))


    def test_unsupportedSerialization(self):
        """
        L{json.serialize} should raise a L{TypeError} if it is passed an object
        which it does not know how to serialize.
        """
        class Unsupported(object):
            def __repr__(self):
                return 'an unsupported object'
        exception = self.assertRaises(TypeError, json.serialize, Unsupported())

        self.assertIn('Unsupported type <class \'nevow.test.test_json.', str(exception))
        self.assertIn('.Unsupported\'>: an unsupported object', str(exception))


    def test_customSerialization(self):
        """
        L{json.serialize} should emit JavaScript calls to the JavaScript object
        named by L{IAthenaTransportable.jsClass} with the arguments returned by
        L{IAthenaTransportable.getInitialArguments} when passed an object which
        can be adapted to L{IAthenaTransportable}.
        """
        @implementer(IAthenaTransportable)
        class Transportable(object):
            """
            Completely parameterized L{IAthenaTransportable} implementation so
            different data can be easily tested.
            """

            def __init__(self, jsClass, initialArgs):
                self.jsClass = compat.unicode(jsClass)
                self.getInitialArguments = lambda: initialArgs

        self.assertEqual(
            json.serialize(Transportable("Foo", ())),
            "(new Foo())")
        self.assertEqual(
            json.serialize(Transportable("Bar", (None,))),
            "(new Bar(null))")
        self.assertEqual(
            json.serialize(Transportable("Baz.Quux", (1, 2))),
            "(new Baz.Quux(1,2))")

        # The style of the quotes in this assertion is basically irrelevant.
        # If, for some reason, the serializer changes to use ' instead of ",
        # there's no reason not to change this test to reflect that. -exarkun
        self.assertEqual(
            json.serialize(Transportable("Quux", ("Foo",))),
            '(new Quux("Foo"))')
