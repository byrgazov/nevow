
import operator

from twisted.python import compat

from zope.interface import implementer

from nevow import inevow


def languagesFactory(ctx):
    langs  = []
    header = inevow.IRequest(ctx).getHeader('accept-language')

    if header is not None:
        for no, lang in enumerate(header.split(',')):
            quality = 1.0

            if ';' in lang:
                lang, quality = lang.split(';', 1)
                if quality[:2] == 'q=':
                    try:
                        quality = float(quality[2:])
                    except ValueError:
                        pass
            if type(quality) in (int, float):
                quality = (0, quality, -no)
            else:
                quality = (1, str(quality), -no)

            langs.append((quality, lang))

            if '-' in lang:
                langs.append((quality, lang.split('-')[0]))

        langs.sort(key=operator.itemgetter(0), reverse=True)

    return [lang for quality, lang in langs]


@implementer(inevow.II18NConfig)
class I18NConfig(object):
    def __init__(self,
                 domain=None,
                 localeDir=None,
                 ):
        self.domain = domain
        self.localeDir = localeDir

class PlaceHolder(object):
    def __init__(self, translator, *args, **kwargs):
        self.translator = translator
        self.args = args
        self.kwargs = kwargs
        _mod = kwargs.pop('_mod', None)
        if _mod is None:
            _mod = []
        self.mod = _mod

    def __mod__(self, other):
        kw = {}
        kw.update(self.kwargs)
        kw['_mod'] = self.mod+[other]
        return self.__class__(self.translator,
                              *self.args,
                              **kw)

    def __repr__(self):
        args = []
        if self.args:
            args.append('*%r' % (self.args,))
        args.append('translator=%r' % self.translator)
        if self.kwargs:
            args.append('**%r' % self.kwargs)
        s = '%s(%s)' % (
            self.__class__.__name__,
            ', '.join(args),
            )
        for mod in self.mod:
            s += ' %% %r' % (mod,)
        return s

def flattenL10n(placeHolder, ctx):
    kw = placeHolder.kwargs

    try:
        languages = inevow.ILanguages(ctx)
    except TypeError:
        pass
    else:
        kw = dict(kw) # copy before we mutate it
        kw['languages'] = languages

    try:
        cfg = inevow.II18NConfig(ctx)
    except TypeError:
        pass
    else:
        kw = dict(kw) # copy before we mutate it
        if cfg.domain is not None:
            kw['domain'] = cfg.domain
        if cfg.localeDir is not None:
            kw['localeDir'] = cfg.localeDir

    s = placeHolder.translator(*placeHolder.args, **kw)
    for mod in placeHolder.mod:
        s = s % mod
    return s


class Translator(object):
    """
    A gettext-like Translator for Nevow.

    The major difference between this and naive gettext is that with
    Translator, the actual translation is done as part of Nevow's
    flattening process, allowing per-user settings to be retrieved via
    the context.

    @ivar translator: the actual translation function to use.

    @ivar args: positional arguments to pass to translator.

    @ivar kwargs: keyword arguments to pass to translator.

    @ivar gettextFunction: If using the default translator function,
    name of GNU gettext function to wrap. Useful for 'ungettext'.
    """
    translator = None
    args = None
    kwargs = None

    gettextFunction = 'gettext' if compat._PY3 else 'ugettext'

    def _gettextTranslation(self, *args, **kwargs):
        domain = kwargs.pop('domain', None)
        localeDir = kwargs.pop('localeDir', None)
        languages = kwargs.pop('languages', None)
        import gettext
        translation = gettext.translation(
            domain=domain,
            localedir=localeDir,
            languages=languages,
            fallback=True,
            )
        fn = getattr(translation, self.gettextFunction)
        return fn(*args, **kwargs)

    def __init__(self, **kwargs):
        """
        Initialize.

        @keyword translator: the translator function to use.

        @keyword gettextFunction: The GNU gettext function to
        wrap. See class docstring.

        @param kwargs: keyword arguments for the translator function.
        """
        translator = kwargs.pop('translator', None)
        if translator is not None:
            self.translator = translator
        if self.translator is None:
            self.translator = self._gettextTranslation

        gettextFunction = kwargs.pop('gettextFunction', None)
        if gettextFunction is not None:
            self.gettextFunction = gettextFunction

        self.kwargs = kwargs

    def __call__(self, *args, **kwargs):
        """
        Translate a string.

        @param args: arguments to pass to translator, usually the
        string to translate, or for things like ungettext two strings
        and a number.

        @param kwargs: keyword arguments for the translator.
        Arguments given here will override the ones given at
        initialization.

        @return: a placeholder that will be translated
        when flattened.

        @rtype: PlaceHolder
        """
        kw = dict(self.kwargs)
        kw.update(kwargs)
        return PlaceHolder(self.translator, *args, **kw)


_ = Translator()

ungettext = Translator(gettextFunction='ngettext' if compat._PY3 else 'ungettext')

def render(translator=None):
    """
    Render a localised message.

    >>> from nevow import i18n, rend
    >>> class MyPage(rend.Page):
    ...     render_i18n = i18n.render()

    or, to use a specific domain:

    >>> from nevow import i18n, rend
    >>> _ = i18n.Translator(domain='foo')
    >>> class MyPage(rend.Page):
    ...     render_i18n = i18n.render(translator=_)

    """
    if translator is None:
        translator = _

    def _render(page, ctx, data):
        # TODO why does this get page? Is it
        # the Page's self? Why would this look
        # like a bound method?
        children = ctx.tag.children
        ctx.tag.clear()
        for child in children:
            # The bytes in the following is for py2 *exclusively*.  In py3,
            # bytes in here won't match strings (raise a warning if bytes
            # are encountered here?)
            if isinstance(child, (compat.unicode, bytes)):
                child = translator(child)
            ctx.tag[child]
        return ctx.tag

    return _render

# TODO also provide macro()
