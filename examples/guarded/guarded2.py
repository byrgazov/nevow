from zope.interface import implementer

from twisted.cred   import portal, checkers, credentials
from twisted.python import compat

from nevow import inevow, rend, tags, guard, loaders


class MyPage(rend.Page):
    addSlash = True
    docFactory = loaders.stan(
    tags.html[
        tags.head[tags.title["Hi Boy"]],
        tags.body[
            tags.invisible(render=tags.directive("isLogged"))[
                tags.div(pattern="False")[
                    tags.form(action=compat.nativeString(guard.LOGIN_AVATAR), method='post')[
                        tags.table[
                            tags.tr[
                                tags.td["Username:"],
                                tags.td[tags.input(type='text', name='username')],
                            ],
                            tags.tr[
                                tags.td["Password:"],
                                tags.td[tags.input(type='password', name='password')],
                            ]
                        ],
                        tags.input(type='submit'),
                        tags.p,
                    ]
                ],
                tags.invisible(pattern="True")[
                    tags.h3["Hi bro"],
                    tags.invisible(render=tags.directive("sessionId")),
                    tags.br,
                    tags.a(href=compat.nativeString(guard.LOGOUT_AVATAR))["Logout"]
                ]
            ]
        ]
    ])

    def __init__(self, avatarId=None):
        super(MyPage, self).__init__()
        self.avatarId = avatarId

    def render_isLogged(self, context, data):
        q = inevow.IQ(context)
        true_pattern  = q.onePattern('True')
        false_pattern = q.onePattern('False')
        if self.avatarId:
            return true_pattern or context.tag().clear()
        return false_pattern or context.tag().clear()

    def render_sessionId(self, context, data):
        sess = inevow.ISession(context)
        return context.tag[compat.nativeString(sess.uid)]

    def logout(self):
        print("Bye")


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
                    resc = MyPage()
                    resc.realm = self
                    return (inevow.IResource, resc, noLogout)

                resc = MyPage(avatarId)
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
