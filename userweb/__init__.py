from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.config import Configurator

from .security import groupfinder

import usermanagement.LDAP


def main(global_config, **settings):
    config = Configurator(settings=settings, root_factory='.resources.Root')
    config.include('pyramid_chameleon')

    # Security policies
    authn_policy = AuthTktAuthenticationPolicy(
        settings['userweb.secret'], callback=groupfinder,
        hashalg='sha512')
    authz_policy = ACLAuthorizationPolicy()
    config.set_authentication_policy(authn_policy)
    config.set_authorization_policy(authz_policy)

    config.add_route('home', '/')
    config.add_route('login', '/login')
    config.add_route('guests', '/guests')
    config.add_route('add_guest', '/guest/add')
    config.add_route('remove_user', '/user/{uid}/remove')
    config.add_route('users', '/users')
    config.add_route('add_user', '/user/add')
    config.add_route('reset_password', '/user/{uid}/reset_pw')
    config.add_route('change_password', '/user/change_pw')
    config.add_route('change_groups', '/user/{uid}/change_groups')

    config.add_route('computers', '/computers')
    config.add_route('add_computer', '/computer/add')
    config.add_route('remove_computer', '/computer/{uid}/remove')
    config.add_route('reset_computer_password', '/computer/{uid}/reset_pw')
    config.add_route('logout', '/logout')
    config.add_static_view(name='static', path='userweb:static')
    config.add_settings({
        'ldap.server':usermanagement.LDAP.LDAPServer(settings['ldap.url'],settings['ldap.base'])
    })
    config.scan('.views')
    return config.make_wsgi_app()
