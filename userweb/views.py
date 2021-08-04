from pyramid.httpexceptions import HTTPFound
from pyramid.security import (
    remember,
    forget,
    )


from pyramid.view import (
    view_config,
    view_defaults,
    forbidden_view_config,
    )
import usermanagement.group
import usermanagement.user


@view_defaults(renderer='templates/home.pt')
class UserwebViews:
    def __init__(self, request):
        self.request = request
        self.logged_in = request.authenticated_userid

    def permission(self):
        return{
            'user':self.request.has_permission('user'),
            'admin':self.request.has_permission('admin'),
        }

    @view_config(route_name='home', permission='authed')
    def home(self):
        return {
            'uid': self.request.authenticated_userid,
            'permission': self.permission(),
        }

    @view_config(route_name='login', renderer='templates/login.pt')
    @forbidden_view_config(renderer='templates/login.pt')
    def login(self):
        request = self.request
        login_url = request.route_url('login')
        referrer = request.url
        if referrer == login_url:
            referrer = '/'  # never use login form itself as came_from
        came_from = request.params.get('came_from', referrer)
        message = ''
        login = ''
        password = ''
        if 'form.submitted' in request.params:
            login = request.params['login']
            password = request.params['password']
            conn = request.registry.settings['ldap.server'].connect()
            
            if conn.User(login,password).authenticate():
                headers = remember(request, login)
                return HTTPFound(location=came_from,
                                 headers=headers)
            message = 'Failed login'

        return {
            'name': 'Login',
            'message': message,
            'url': request.application_url + '/login',
            'came_from': came_from,
            'login': login,
            'password': password,
        }

    @view_config(route_name='guests', renderer='templates/users.pt', permission='user')
    def guests(self):
        conn = self.request.registry.settings['ldap.server'].connect()
        users = usermanagement.group.Group.Guests(conn).get_users()
        return {
            'name':'Guests',
            'users': users,
            'permission': self.permission(),
        }

    def _system_add_user(self):
        pass
        

    @view_config(route_name='add_guest', renderer='templates/add_user.pt', permission='user')
    @view_config(route_name='add_user', renderer='templates/add_user.pt', permission='admin')
    def add_user(self):
        request = self.request
        conn = request.registry.settings['ldap.server'].connect()
        adding_full_user = request.matched_route.name == 'add_user'
        if adding_full_user:
            groups = usermanagement.group.Group.Groups(conn)
            name = 'Add User'
        else:
            groups = []
            name = 'Add Guest'

        add_url = request.url
        referrer = request.url
        if referrer == add_url:
            referrer = '/'  # never use login form itself as came_from
        added = False
        user_id = None
        user_name = None
        user_password = None
        auth_password = None
        message = None
        if 'form.submitted' in request.params:
            if adding_full_user:
                primary_group = conn.Group(gid=request.params['user_primary_group'])
                secondary_groups = [conn.Group(gid=x) for x in request.params.getall('user_secondary_groups')]
            else:
                primary_group = usermanagement.group.Group.Guests(conn)
                secondary_groups = []
            uid = request.params['user_id']
            full_name = request.params['user_name']
            user_password = request.params['user_password']
            if conn.User(request.authenticated_userid, request.params['auth_password']).authenticate():
                try:
                    new_user = usermanagement.user.User.add(conn, uid, full_name, user_password, primary_group, secondary_groups)
                    message = "%(uid)s added" % {'uid':uid}
                    added = True
                except usermanagement.ldap.INSUFFICIENT_ACCESS as e:
                    message = "Insufficient Permissions"
            else:
                message = "Authentication Failed"
        return {
            'name': name,
            'message': message,
            'groups': groups,
            'added': added,
            'url': add_url,
            'user_id': user_id,
            'user_name': user_name,
            'user_password': user_password,
            'auth_password': auth_password,
            'permission': self.permission(),
        }

    
    
    @view_config(route_name='users', renderer='templates/users.pt', permission='admin')
    def users(self):
        conn = self.request.registry.settings['ldap.server'].connect()
        users = usermanagement.group.Group.Users(conn).get_users()
        return {
            'name':'Users',
            'users': users,
            'permission': self.permission(),
        }

    @view_config(route_name='change_password', renderer='templates/change_pw.pt', permission='authed')
    def change_pw(self):
        uid = self.request.authenticated_userid
        request = self.request
        change_url = request.route_url('change_password',uid=uid)
        referrer = request.url
        if referrer == change_url:
            referrer = '/'  # never use login form itself as came_from
        came_from = request.params.get('came_from', referrer)
        message = ''
        password = ''
        if 'form.submitted' in request.params:
            conn = request.registry.settings['ldap.server'].connect()
            new_pw = request.params['new_password']
            if new_pw!= request.params['new_password']:
                message = 'New passwords do not match'
            elif conn.User(request.authenticated_userid, request.params['auth_password']).authenticate():
                conn.User(uid).update_password(new_pw)
                message = "Password for %(uid)s reset" % {'uid':uid}
            else:
                message = "Failed Authentication or Insufficent Permissions"

        return {
            'title': 'Change password for %(uid)s' % {'uid':uid},
            'message': message,
            'url': change_url,
            'came_from': came_from,
            'new_password': password,
            'confirm_password': password,
            'auth_password': password,
            'permission': self.permission(),
        }

        
    @view_config(route_name='reset_password', renderer='templates/change_pw.pt', permission='user')
    def reset_pw(self):
        uid = self.request.matchdict['uid']
        request = self.request
        reset_url = request.route_url('reset_password',uid=uid)
        referrer = request.url
        if referrer == reset_url:
            referrer = '/'  # never use login form itself as came_from
        came_from = request.params.get('came_from', referrer)
        message = ''
        password = ''
        if 'form.submitted' in request.params:
            conn = request.registry.settings['ldap.server'].connect()
            new_pw = request.params['new_password']
            if new_pw!= request.params['confirm_password']:
                message = 'New passwords do not match'
            elif conn.User(request.authenticated_userid, request.params['auth_password']).authenticate():
                conn.User(uid).update_password(new_pw)
                message = "Password for %(uid)s reset" % {'uid':uid}
            else:
                message = "Failed Authentication or Insufficent Permissions"

        return {
            'title': 'Change password for %(uid)s' % {'uid':uid},
            'message': message,
            'url': reset_url,
            'came_from': came_from,
            'new_password': password,
            'confirm_password': password,
            'auth_password': password,
            'permission': self.permission(),
        }


    @view_config(route_name='remove_user', renderer='templates/remove_user.pt', permission='user')
    def remove_user(self):
        uid = self.request.matchdict['uid']
        request = self.request
        remove_url = request.route_url('remove_user',uid=uid)
        referrer = request.url
        if referrer == remove_url:
            referrer = '/'  # never use login form itself as came_from
        came_from = request.params.get('came_from', referrer)
        message = ''
        password = ''
        deleted = False
        if 'form.submitted' in request.params:
            conn = request.registry.settings['ldap.server'].connect()
            conf_user = request.params['confirm_user']
            if conf_user != uid:
                message = 'username entered does not match user to be deleted'
            elif conn.User(request.authenticated_userid, request.params['auth_password']).authenticate():
                conn.User(uid).delete()
                message = "%(uid)s deleted" % {'uid':uid}
                deleted = True
            else:
                message = "Failed Authentication or Insufficent Permissions"

        return {
            'title': 'Are you sure you want to delete the user:  %(uid)s' % {'uid':uid},
            'message': message,
            'url': remove_url,
            'came_from': came_from,
            'confirm_user': '',
            'auth_password': password,
            'deleted': deleted,
            'permission': self.permission(),
        }

    @view_config(route_name='logout')
    def logout(self):
        request = self.request
        headers = forget(request)
        url = request.route_url('home')
        return HTTPFound(location=url,
                         headers=headers)
