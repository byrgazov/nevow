# -*- test-case-name: nevow.test -*-
# Copyright (c) 2004-2006 Divmod.
# See LICENSE for details.
import builtins

def _versions():
    import re
    from nevow._version import get_versions
    from twisted.python.versions import Version

    # From `packaging`
    VERSION_PATTERN = re.compile(r"""
        v?
        (?:
            (?:(?P<epoch>[0-9]+)!)?                           # epoch
            (?P<release>[0-9]+(?:\.[0-9]+)*)                  # release segment
            (?P<pre>                                          # pre-release
                [-_\.]?
                (?P<pre_l>(a|b|c|rc|alpha|beta|pre|preview))
                [-_\.]?
                (?P<pre_n>[0-9]+)?
            )?
            (?P<post>                                         # post release
                (?:-(?P<post_n1>[0-9]+))
                |
                (?:
                    [-_\.]?
                    (?P<post_l>post|rev|r)
                    [-_\.]?
                    (?P<post_n2>[0-9]+)?
                )
            )?
            (?P<dev>                                          # dev release
                [-_\.]?
                (?P<dev_l>dev)
                [-_\.]?
                (?P<dev_n>[0-9]+)?
            )?
        )
        (?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?       # local version
    """, re.VERBOSE)
    __version__ = get_versions()["version"]
    parts = VERSION_PATTERN.match(__version__)
    __version_info__ = tuple(int(i) for i in parts.group('release').split("."))
    rc = parts.group('pre')
    if rc:
        rc = int(rc.replace('rc', ''))
    dev = parts.group('dev')
    if dev:
        dev = int(dev.replace('dev', ''))
    try:
        version = Version(
            "nevow",
            __version_info__[0],
            __version_info__[1],
            __version_info__[2],
            release_candidate=rc,
            dev=dev)
    except TypeError:
        # Version might be too old for rc/dev, try without
        version = Version(
            "nevow",
            __version_info__[0],
            __version_info__[1],
            __version_info__[2])
    return __version__, __version_info__, version


__version__, __version_info__, version = _versions()

import sys
from twisted.python.components import registerAdapter

from nevow import flat
from nevow.util import _namedAnyWithBuiltinTranslation


# Python2.2 has a stupidity where instance methods have name
# 'builtins.instance method' instead of 'builtins.instancemethod'
# Workaround this error.

def clean(o):
    if o == 'builtins.instancemethod' and sys.version_info < (2, 3):
        return 'builtins.instance method'
    return o


def load(S):
    for line in S.split('\n'):
        line = line.split('#', 1)[0].strip()
        if line:
            (a, o, i) = line.split()
            registerAdapter(_namedAnyWithBuiltinTranslation(a),
                            _namedAnyWithBuiltinTranslation(clean(o)),
                            _namedAnyWithBuiltinTranslation(i))


def loadFlatteners(S):
    for line in S.split('\n'):
        line = line.split('#', 1)[0].strip()
        if line:
            f, o = line.split()
            flat.registerFlattener(f, clean(o))


# The xml namespace of the nevow elements and attributes
namespace = "http://nevow.com/ns/nevow/0.1"

basic_adapters = """
formless.annotate.Group                   formless.annotate.MetaTypedInterface        formless.iformless.ITyped

nevow.accessors.DictionaryContainer    builtins.dict                         nevow.inevow.IContainer
nevow.accessors.ListContainer          builtins.list                         nevow.inevow.IContainer
nevow.accessors.ListContainer          builtins.tuple                        nevow.inevow.IContainer

nevow.accessors.FunctionAccessor       types.FunctionType                     nevow.inevow.IGettable
nevow.accessors.FunctionAccessor       types.MethodType                       nevow.inevow.IGettable
nevow.accessors.DirectiveAccessor      nevow.stan.directive                     nevow.inevow.IGettable
nevow.accessors.SlotAccessor           nevow.stan.slot                          nevow.inevow.IGettable
nevow.accessors.SlotAccessor           nevow.stan._PrecompiledSlot              nevow.inevow.IGettable

    #

formless.webform.PropertyBindingRenderer  formless.annotate.Property         formless.iformless.IBindingRenderer
formless.webform.MethodBindingRenderer    formless.annotate.MethodBinding    formless.iformless.IBindingRenderer
formless.webform.GroupBindingRenderer     formless.annotate.GroupBinding     formless.iformless.IBindingRenderer

    #

formless.webform.StringRenderer         formless.annotate.String         formless.iformless.ITypedRenderer
formless.webform.StringRenderer         formless.annotate.Integer        formless.iformless.ITypedRenderer
formless.webform.StringRenderer         formless.annotate.Directory      formless.iformless.ITypedRenderer
formless.webform.PasswordRenderer       formless.annotate.Password       formless.iformless.ITypedRenderer
formless.webform.PasswordEntryRenderer  formless.annotate.PasswordEntry  formless.iformless.ITypedRenderer
formless.webform.TextRenderer           formless.annotate.Text           formless.iformless.ITypedRenderer
formless.webform.BooleanRenderer        formless.annotate.Boolean        formless.iformless.ITypedRenderer
formless.webform.ChoiceRenderer         formless.annotate.Choice         formless.iformless.ITypedRenderer
formless.webform.RadioRenderer         formless.annotate.Radio         formless.iformless.ITypedRenderer
formless.webform.ObjectRenderer         formless.annotate.Object         formless.iformless.ITypedRenderer
formless.webform.NullRenderer           formless.annotate.Request        formless.iformless.ITypedRenderer
formless.webform.NullRenderer           formless.annotate.Context        formless.iformless.ITypedRenderer
formless.webform.FileUploadRenderer     formless.annotate.FileUpload     formless.iformless.ITypedRenderer
formless.webform.ButtonRenderer         formless.annotate.Button         formless.iformless.ITypedRenderer

    #

formless.processors.ProcessGroupBinding    formless.annotate.GroupBinding     formless.iformless.IInputProcessor
formless.processors.ProcessMethodBinding   formless.annotate.MethodBinding    formless.iformless.IInputProcessor
formless.processors.ProcessPropertyBinding    formless.annotate.Property         formless.iformless.IInputProcessor
formless.processors.ProcessTyped           formless.iformless.ITyped           formless.iformless.IInputProcessor
formless.processors.ProcessPassword        formless.annotate.Password         formless.iformless.IInputProcessor
formless.processors.ProcessRequest         formless.annotate.Request          formless.iformless.IInputProcessor
formless.processors.ProcessContext         formless.annotate.Context          formless.iformless.IInputProcessor
formless.processors.ProcessUpload          formless.annotate.FileUpload       formless.iformless.IInputProcessor

    #

formless.webform.FormDefaults     nevow.appserver.NevowRequest                formless.iformless.IFormDefaults
formless.webform.FormDefaults     nevow.testutil.FakeRequest                  formless.iformless.IFormDefaults
formless.webform.FormDefaults     nevow.testutil.FakeSession                  formless.iformless.IFormDefaults
formless.webform.FormDefaults     twisted.web.server.Session                  formless.iformless.IFormDefaults
formless.webform.FormDefaults     nevow.guard.GuardSession                    formless.iformless.IFormDefaults

formless.webform.FormErrors       twisted.web.server.Session               formless.iformless.IFormErrors
formless.webform.FormErrors       nevow.guard.GuardSession                 formless.iformless.IFormErrors
formless.webform.FormErrors       nevow.testutil.FakeSession               formless.iformless.IFormErrors

nevow.appserver.OldResourceAdapter                  twisted.web.resource.IResource      nevow.inevow.IResource
nevow.static.staticHTML                 builtins.str                          nevow.inevow.IResource

nevow.appserver.sessionFactory  nevow.context.RequestContext    nevow.inevow.ISession
nevow.rend.handFactory   nevow.context.RequestContext    nevow.inevow.IHand
nevow.rend.statusFactory   nevow.context.RequestContext    nevow.inevow.IStatusMessage
nevow.rend.defaultsFactory   nevow.context.RequestContext    formless.iformless.IFormDefaults
nevow.rend.errorsFactory   nevow.context.RequestContext    formless.iformless.IFormErrors
nevow.rend.originalFactory  nevow.context.RequestContext   nevow.inevow.IRequest
nevow.appserver.defaultExceptionHandlerFactory   nevow.context.SiteContext    nevow.inevow.ICanHandleException
nevow.appserver.defaultExceptionHandlerFactory   nevow.context.WebContext     nevow.inevow.ICanHandleException  # @xxx: [bw] ?

nevow.rend.originalFactory  nevow.context.PageContext   nevow.inevow.IRenderer
nevow.rend.originalFactory  nevow.context.PageContext   nevow.inevow.IRendererFactory

nevow.rend.originalFactory  nevow.context.PageContext   formless.iformless.IConfigurableFactory

# URL IResource adapters
nevow.url.URLRedirectAdapter    nevow.url.URL           nevow.inevow.IResource
nevow.url.URLRedirectAdapter    nevow.url.URLOverlay    nevow.inevow.IResource

## The tests rely on these. Remove them ASAP.
nevow.util.remainingSegmentsFactory  nevow.context.RequestContext   nevow.inevow.IRemainingSegments
nevow.util.currentSegmentsFactory  nevow.context.RequestContext   nevow.inevow.ICurrentSegments

nevow.query.QueryContext    nevow.context.WovenContext    nevow.inevow.IQ
nevow.query.QueryLoader     nevow.inevow.IDocFactory      nevow.inevow.IQ
nevow.query.QueryList       builtins.list              nevow.inevow.IQ
nevow.query.QuerySlot       nevow.stan.slot               nevow.inevow.IQ
nevow.query.QuerySlot       nevow.stan._PrecompiledSlot   nevow.inevow.IQ
nevow.query.QueryNeverFind  nevow.stan.xml                nevow.inevow.IQ
nevow.query.QueryNeverFind  nevow.stan.raw                nevow.inevow.IQ
nevow.query.QueryNeverFind  nevow.stan.directive          nevow.inevow.IQ

# I18N
nevow.i18n.languagesFactory     nevow.context.RequestContext    nevow.inevow.ILanguages
"""

load(basic_adapters)


flatteners = """
nevow.flat.flatmdom.MicroDomDocumentSerializer          twisted.web.microdom.Document
nevow.flat.flatmdom.MicroDomTextSerializer              twisted.web.microdom.Text
nevow.flat.flatmdom.MicroDomCommentSerializer           twisted.web.microdom.Comment
nevow.flat.flatmdom.MicroDomElementSerializer           twisted.web.microdom.Element
nevow.flat.flatmdom.MicroDomEntityReferenceSerializer   twisted.web.microdom.EntityReference
nevow.flat.flatmdom.MicroDomCDATASerializer   twisted.web.microdom.CDATASection

nevow.flat.flatstan.ProtoSerializer               nevow.stan.Proto
nevow.flat.flatstan.TagSerializer                 nevow.stan.Tag
nevow.flat.flatstan.EntitySerializer                 nevow.stan.Entity
nevow.flat.flatstan.CommentSerializer             nevow.stan.Comment
nevow.flat.flatstan.XmlSerializer                 nevow.stan.xml
nevow.flat.flatstan.RawSerializer                 nevow.stan.raw
nevow.flat.flatstan.StringSerializer              builtins.str
nevow.flat.flatstan.StringSerializer              builtins.bytes
nevow.flat.flatstan.NoneWarningSerializer         builtins.NoneType
nevow.flat.flatstan.StringCastSerializer          builtins.int
nevow.flat.flatstan.StringCastSerializer          builtins.float
nevow.flat.flatstan.BooleanSerializer             builtins.bool
nevow.flat.flatstan.ListSerializer                builtins.list
nevow.flat.flatstan.StringCastSerializer          builtins.dict
nevow.flat.flatstan.ListSerializer                builtins.tuple
nevow.flat.flatstan.ListSerializer                types.GeneratorType
nevow.flat.flatstan.FunctionSerializer            builtins.type  # @ex: tag(...render=str) -> type(str) -> <class 'type'>
nevow.flat.flatstan.FunctionSerializer            builtins.function
nevow.flat.flatstan.MethodSerializer              types.MethodType
nevow.flat.flatstan.RendererSerializer            nevow.inevow.IRenderer
nevow.flat.flatstan.DirectiveSerializer           nevow.stan.directive
nevow.flat.flatstan.SlotSerializer                nevow.stan.slot
nevow.flat.flatstan.PrecompiledSlotSerializer     nevow.stan._PrecompiledSlot
nevow.flat.flatstan.ContextSerializer             nevow.context.WovenContext
nevow.flat.twist.DeferredSerializer               twisted.internet.defer.Deferred
nevow.flat.twist.DeferredSerializer               twisted.internet.defer.DeferredList

nevow.flat.flatstan.FailureSerializer             twisted.python.failure.Failure

nevow.url.URLOverlaySerializer            nevow.url.URLOverlay
nevow.url.URLSerializer            nevow.url.URL

    # Itertools uses special types

nevow.flat.flatstan.ListSerializer  itertools.chain
nevow.flat.flatstan.ListSerializer  itertools.count
nevow.flat.flatstan.ListSerializer  itertools.cycle
nevow.flat.flatstan.ListSerializer  itertools.dropwhile
nevow.flat.flatstan.ListSerializer  builtins.filter
nevow.flat.flatstan.ListSerializer  itertools.filterfalse
nevow.flat.flatstan.ListSerializer  builtins.map
nevow.flat.flatstan.ListSerializer  itertools.islice
nevow.flat.flatstan.ListSerializer  builtins.zip
nevow.flat.flatstan.ListSerializer  itertools.repeat
nevow.flat.flatstan.ListSerializer  itertools.starmap
nevow.flat.flatstan.ListSerializer  itertools.takewhile

nevow.flat.flatstan.DocFactorySerializer nevow.inevow.IDocFactory

# I18N
nevow.i18n.flattenL10n              nevow.i18n.PlaceHolder
"""

flatteners_2_4 = """
nevow.flat.flatstan.StringCastSerializer          decimal.Decimal
"""
if sys.version_info >= (2, 4):
    flatteners += flatteners_2_4

loadFlatteners(flatteners)


__all__ = [
    'accessors', 'appserver', 'blocks', 'canvas', 'context', 'dirlist', 'entities', 'events', 'failure', 'guard', 'inevow',
    'loaders', 'rend', 'scripts', 'stan', 'static', 'tags', 'test', 'testutil', 'url', 'util', 'vhost', 'flat', 'version',
]
