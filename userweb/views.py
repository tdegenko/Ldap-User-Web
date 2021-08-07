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
            with request.registry.settings['ldap.server'].connect() as conn:
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
    @view_config(route_name='users', renderer='templates/users.pt', permission='admin')
    def guests(self):
        with self.request.registry.settings['ldap.server'].connect() as conn:
            users = []
            if self.request.matched_route.name == 'users':
                users = usermanagement.group.Group.Users(conn).get_users()
                name = 'Users'
            else:
                users = usermanagement.group.Group.Guests(conn).get_users()
                name = 'Guests'
            user_sort = lambda x: x.uid
        return {
            'name': name,
            'users': sorted(users, key=user_sort),
            'permission': self.permission(),
        }

    def _system_add_user(self, uid, full_name, user_password, primary_group, secondary_groups):
        settings = self.request.registry.settings
        with settings['ldap.server'].connect(settings['ldap.user'], settings['ldap.password']) as conn:
            if primary_group is None:
                primary_group = usermanagement.group.Group.Guests(conn)
            else:
                primary_group = conn.Group(conn, gid=primary_group)
            secondary_groups = [conn.Group(gid=x) for x in secondary_groups]
            new_user = usermanagement.user.User.add(conn, uid, full_name, user_password, primary_group, secondary_groups)

    @view_config(route_name='add_guest', renderer='templates/add_user.pt', permission='user')
    @view_config(route_name='add_user', renderer='templates/add_user.pt', permission='admin')
    def add_user(self):
        request = self.request
        with request.registry.settings['ldap.server'].connect() as conn:
            adding_full_user = request.matched_route.name == 'add_user'
            if adding_full_user:
                groups = usermanagement.group.Group.Groups(conn)
                name = 'Add User'
            else:
                groups = []
                name = 'Add Guest'

            add_url = request.url
            added = False
            user_id = None
            user_name = None
            user_password = None
            auth_password = None
            message = None
            primary_group = None
            secondary_groups = []
            if 'form.submitted' in request.params:
                if adding_full_user:
                    primary_group = request.params['user_primary_group']
                    secondary_groups = request.params.getall('user_secondary_groups')
                else:
                    primary_group = None
                    secondary_groups = []
                user_id = request.params['user_id']
                user_name = request.params['user_name']
                user_password = request.params['user_password']
                if conn.User(request.authenticated_userid, request.params['auth_password']).authenticate():
                    new_user = self._system_add_user(user_id, user_name, user_password, primary_group, secondary_groups)
                    message = "%(uid)s added" % {'uid':user_id}
                    added = True
                else:
                    message = "Authentication Failed"
        return {
            'name': name,
            'message': message,
            'groups': groups,
            'primary_group': primary_group,
            'secondary_groups': secondary_groups,
            'added': added,
            'url': add_url,
            'user_id': user_id,
            'user_name': user_name,
            'user_password': user_password,
            'auth_password': auth_password,
            'permission': self.permission(),
        }

    @view_config(route_name='change_groups', renderer='templates/change_groups.pt', permission='admin')
    def change_groups(self):
        request = self.request
        with request.registry.settings['ldap.server'].connect() as conn:
            message = None
            changed = False
            auth_password = None

            groups = usermanagement.group.Group.Groups(conn)
            user_id = request.matchdict['uid']
            user = conn.User(user_id)
            user_groups = user.get_groups()
            primary_group = user_groups['primary'].gid
            secondary_groups = [x.gid for x in user_groups['secondary']]
            name = "Change groups for %(uid)s" % {'uid':user_id}
            if 'form.submitted' in request.params:
                if conn.User(request.authenticated_userid, request.params['auth_password']).authenticate():
                    primary_group = request.params['user_primary_group']
                    secondary_groups = request.params.getall('user_secondary_groups')
                    user.update_groups(primary=conn.Group(gid=primary_group), secondary=[conn.Group(gid=x) for x in secondary_groups])
                    message = "%(uid)s's group membership changed" % {'uid':user_id}
                    changed = True
                else:
                    message = "Authentication Failed"
        return{
            'name': name,
            'message': message,
            'changed': changed,
            'url': request.url,
            'groups': groups,
            'primary_group': primary_group,
            'secondary_groups': secondary_groups,
            'auth_password': auth_password,
            'permission': self.permission(),
        }

    
    @view_config(route_name='change_password', renderer='templates/change_pw.pt', permission='authed')
    @view_config(route_name='reset_password', renderer='templates/change_pw.pt', permission='user')
    def change_pw(self):
        request = self.request
        if request.matched_route.name == 'reset_password':
            uid = request.matchdict['uid']
            title = 'Reset password for %(uid)s' % {'uid':uid}
        else:
            uid = request.authenticated_userid
            title = 'Change account password'
        change_url = request.route_url(request.matched_route.name,uid=uid)
        message = ''
        password = ''
        changed = False
        if 'form.submitted' in request.params:
            with request.registry.settings['ldap.server'].connect() as conn:
                new_pw = request.params['new_password']
                if new_pw!= request.params['new_password']:
                    message = 'New passwords do not match'
                elif conn.User(request.authenticated_userid, request.params['auth_password']).authenticate():
                    conn.User(uid).update_password(new_pw)
                    message = "Password for %(uid)s reset" % {'uid':uid}
                    changed = True
                else:
                    message = "Failed Authentication or Insufficent Permissions"

        return {
            'title': title,
            'message': message,
            'url': change_url,
            'changed': changed,
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
        message = ''
        password = ''
        deleted = False
        if 'form.submitted' in request.params:
            with request.registry.settings['ldap.server'].connect() as conn:
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
