from zope.interface import implementer

from twisted.cred   import portal, checkers, credentials
from twisted.python import compat

from nevow import inevow, rend, tags, guard, loaders


### Renderers
class NotLoggedIn(rend.Page):
    """The resource that is returned when you are not logged in"""
    addSlash = True
    docFactory = loaders.stan(
    tags.html[
        tags.head[tags.title["Not Logged In"]],
        tags.body[
            tags.form(action=compat.nativeString(guard.LOGIN_AVATAR), method='post')[
                tags.table[
                    tags.tr[
                        tags.td[ "Username:" ],
                        tags.td[ tags.input(type='text',name='username') ],
                    ],
                    tags.tr[
                        tags.td[ "Password:" ],
                        tags.td[ tags.input(type='password',name='password') ],
                    ]
                ],
                tags.input(type='submit'),
                tags.p,
            ]
        ]
    ]
)


class LoggedIn(rend.Page):
    """The resource that is returned when you login"""
    addSlash = True
    docFactory = loaders.stan(
    tags.html[
        tags.head[tags.title["Logged In"]],
        tags.body[
            tags.h3(render=tags.directive("welcome")),
            tags.a(href=compat.nativeString(guard.LOGOUT_AVATAR))["Logout"]
        ]
    ]
)

    def render_welcome(self, context, data):
        return context.tag[ "Hello, %s!" % data]

    def logout(self):
        ## self.original is the page's main data -- the object that was passed in to the constructor, and
        ## the object that is initially passed as the 'data' parameter to renderers
        print("%s logged out!" % self.original)


### Authentication
def noLogout():
    return None


@implementer(portal.IRealm)
class MyRealm:
    """A simple implementor of cred's IRealm.
       For web, this gives us the LoggedIn page.
    """

    def requestAvatar(self, avatarId, mind, *interfaces):
        for iface in interfaces:
            if iface is inevow.IResource:
                # do web stuff
                if avatarId is checkers.ANONYMOUS:
                    resc = NotLoggedIn()
                    resc.realm = self
                    return (inevow.IResource, resc, noLogout)

                resc = LoggedIn(avatarId)
                resc.realm = self
                return (inevow.IResource, resc, resc.logout)

        raise NotImplementedError("Can't support that interface.")


### Application setup

def createResource():
    realm = MyRealm()
    porta = portal.Portal(realm)

    myChecker = checkers.InMemoryUsernamePasswordDatabaseDontUse()
    myChecker.addUser(b"user", b"password")
    myChecker.addUser(b"fred", b"flintstone")
    porta.registerChecker(checkers.AllowAnonymousAccess(), credentials.IAnonymous)
    porta.registerChecker(myChecker)
    res = guard.SessionWrapper(porta)

    return res
