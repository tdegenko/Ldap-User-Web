from pyramid.security import Allow, Everyone, Authenticated

class Root(object):
    __acl__ = [(Allow, Everyone, 'view'),
               (Allow, Authenticated, 'authed'),
               (Allow, 'Domain Users', 'user'),
               (Allow, 'Domain Admins', 'admin')
    ]

    def __init__(self, request):
        pass
