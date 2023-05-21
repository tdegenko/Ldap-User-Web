import usermanagement
import logging

log = logging.getLogger(__name__)


def groupfinder(userid, request):
    conn = request.registry.settings["ldap.server"].connect()
    try:
        groups = conn.User(userid).get_groups()
        groups = [g.cn for g in [groups["primary"]] + groups["secondary"]]
    except Exception as e:
        log.exception(e)
        return []

    return groups
