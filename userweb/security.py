import usermanagement


def groupfinder(userid, request):
    conn = request.registry.settings["ldap.server"].connect()
    groups = conn.User(userid).get_groups()
    groups = [g.cn for g in [groups["primary"]] + groups["secondary"]]

    return groups
