from time import time as now

import twisted.python.components as tpc
import twisted.python.compat     as compat

from nevow import rend, static, inevow, url, util, loaders, tags as t
from nevow.rend import _CARRYOVER
from formless import iformless

#
# This example is meant to be of some inspiration to those people
# who need to have some inspiration to handle forms without using
# formless. It _WILL_ raise an exception when you submit a form
# without filling all values. This example should NOT be used as-is
# but should be modified and enhanced to fit one's need.
#
# To sum up: it's just a starting point.
#

SUBMIT = b'_submit'
BUTTON = b'post_btn'


class WebException(Exception):
    pass


class ManualFormMixin(rend.Page):
    def locateChild(self, ctx, segments):
        # Handle the form post
        if segments[0].startswith(SUBMIT):
            # Get a method name from the action in the form plus
            # the firt word in the button name (or simply the form action if
            # no button name is specified
            kwargs = {}
            args   = inevow.IRequest(ctx).args

            bindingName = b''

            for key in args:
                if key != BUTTON:
                    if args[key] != [b'']:
                        kwargs[compat.nativeString(key)] = args[key] if 1 < len(args[key]) else args[key][0]
                else:
                    bindingName = args[key][0]

            name_prefix = segments[0].split(b'!!')[1]

            if bindingName == b'':
                name = name_prefix
            else:
                name = name_prefix + b'_' + bindingName.split()[0].lower()

            method = getattr(self, 'form_' + compat.nativeString(name), None)

            if method is not None:
                return self.onManualPost(ctx, method, bindingName, kwargs)

            raise WebException("You should define a form_action_button method")

        return super(ManualFormMixin, self).locateChild(ctx, segments)

    def onManualPost(self, ctx, method, bindingName, kwargs):
        # This is copied from rend.Page.onWebFormPost
        def redirectAfterPost(aspects):
            redirectAfterPost = request.getComponent(iformless.IRedirectAfterPost, None)

            if redirectAfterPost is None:
                ref = request.getHeader('referer') or ''
            else:
                ## Use the redirectAfterPost url
                ref = str(redirectAfterPost)

            magicCookie = str(now())

            refpath = url.URL.fromString(ref)
            refpath = refpath.replace('_nevow_carryover_', magicCookie)

            _CARRYOVER[magicCookie] = C = tpc.Componentized()

            for k, v in aspects.items():
                C.setComponent(k, v)

            request.redirect(str(refpath))

            return static.Data(b'You posted a form to %s' % bindingName, 'text/plain'), ()

        request = inevow.IRequest(ctx)

        return util.maybeDeferred(method, **kwargs)\
            .addCallback(self.onPostSuccess, request, ctx, bindingName, redirectAfterPost)\
            .addErrback(self.onPostFailure, request, ctx, bindingName, redirectAfterPost)


class Page(ManualFormMixin, rend.Page):
    addSlash = True
    docFactory = loaders.stan(
        t.html[
            t.head[
                t.title['Advanced Manualform']
            ],
            t.body[
                t.p['Use the form to find out how to easily and manually handle them'],
                t.form(action=url.here.child('_submit!!post'),
                       enctype="multipart/form-data",
                       method='post'
                      )[
                          t.input(type='text', name='what'),
                          # the name attribute must be present and must be
                          # post_btn for all the buttons in the form
                          t.input(type='submit', value='btn1', name=compat.nativeString(BUTTON)),
                          t.input(type='submit', value='btn2', name=compat.nativeString(BUTTON))
                        ]
            ]
        ]
    )

    def form_post_btn1(self, what=None):
        # 'what' is a keyword argument, and must be the same name that you
        # give to the widget.
        print("btn1:", what)

    def form_post_btn2(self, what=None):
        # see above for 'what'.
        print("btn2:", what)
