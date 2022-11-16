from constants import constants


def mk_error_msg(error_str):
    return {"type": "error", "error": error_str}


def mk_hello_msg():
    return {"type": "hello", "version": constants.VERSION, "agent": constants.AGENT}


def mk_getpeers_msg():
    return {"type": "getpeers"}


def mk_peers_msg(peers):
    pl = [f'{peer}' for peer in peers]
    return {"type": "peers", "peers": pl}


def mk_getobject_msg(objectid):
    return {"type": "getobject", "objectid": objectid}


def mk_object_msg(object):
    return {"type": "object", "object": object}


def mk_ihaveobject_msg(objectid):
    return {"type": "ihaveobject", "objectid": objectid}

