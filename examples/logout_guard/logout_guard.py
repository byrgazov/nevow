"""
How to access the session from guard's logout function.
"""

# Some resource for our site
from zope.interface import implementer

from twisted.cred.portal      import IRealm, Portal
from twisted.cred.checkers    import AllowAnonymousAccess, ANONYMOUS
from twisted.cred.credentials import IAnonymous

from nevow import guard
from nevow import inevow
from nevow import loaders
from nevow import rend
from nevow import tags as T
from nevow import url


class MyRootResource(rend.Page):
    addSlash = True
    docFactory = loaders.stan(T.html[T.body[
       T.a(href=url.here.child(guard.LOGOUT_AVATAR))['Click here to log out']
    ]])


class Mind:
    def __init__(self, request, credentials):
        self.request = request
        self.credentials = credentials


@implementer(IRealm)
class MyRealm:
    def requestAvatar(self, avatar_id, mind, *interfaces):
        if inevow.IResource in interfaces:
            return (
                inevow.IResource,
                MyRootResource(),
                self.createLogout(avatar_id, mind)
            )
        raise NotImplementedError

    def createLogout(self, avatar_id, mind):
        def logout():
            # This will be a nevow.guard.GuardSession instance
            session = mind.request.getSession()
            if avatar_id is ANONYMOUS:
                avatar_repr = '<ANONYMOUS>'
            else:
                avatar_repr = repr(avatar_id)
            print('Logging avatar', avatar_repr, 'out of session', session)
        return logout


def createResource():
    portal = Portal(MyRealm())
    portal.registerChecker(AllowAnonymousAccess(), IAnonymous)
    # Here is the vital part: specifying a mindFactory for guard to use
    return guard.SessionWrapper(portal, mindFactory=Mind)
