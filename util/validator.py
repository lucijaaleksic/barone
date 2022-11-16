import json
import re
import ipaddress
from copy import deepcopy

import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519

from models.Object import Object
from exceptions.msgexceptions import *
import objects_db as objects_db


def validate_allowed_keys(msg_dict, allowed_keys, msg_type):
    if len(set(msg_dict.keys()) - set(allowed_keys)) != 0:
        raise MalformedMsgException(
            "Message malformed: {} exceptions contains invalid keys!".format(msg_type))


def validate_hello_msg(msg_dict):
    if msg_dict['type'] != 'hello':
        raise UnexpectedMsgException("Message type is not 'hello'!")

    try:
        if 'version' not in msg_dict:
            raise MalformedMsgException(
                "Message malformed: version is missing!")

        version = msg_dict['version']
        if not isinstance(version, str):
            raise MalformedMsgException(
                "Message malformed: version is not a string!")

        version_parts = version.split(".")
        if len(version_parts) != 3:
            raise MalformedMsgException(
                "Message malformed: version does not contain three parts!")

        if version_parts[0] != '0' or version_parts[1] != '8':
            raise MalformedMsgException(
                "Message malformed: version is not 0.8.x!")

        try:
            int(version_parts[2], 10)
        except:
            raise MalformedMsgException(
                "Message malformed: version is not 0.8.x!")

        validate_allowed_keys(msg_dict, ['type', 'version', 'agent'], 'hello')

    except MalformedMsgException as e:
        raise e
    except Exception as e:
        raise MalformedMsgException("Message malformed: {}".format(str(e)))


def validate_hostname(host_str):
    # Copied from here:
    # https://stackoverflow.com/questions/2532053/validate-a-hostname-string/2532344#2532344

    if len(host_str) > 255:
        return False
    if host_str[-1] == ".":
        host_str = host_str[:-1]  # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)

    return all(allowed.match(x) for x in host_str.split("."))


def validate_ipv4addr(host_str):
    try:
        ip = ipaddress.IPv4Address(host_str)

    except:
        return False

    return True


def validate_ipv6addr(host_str):
    if host_str[0] != '[':
        return False
    if host_str[-1] != ']':
        return False
    try:
        ip = ipaddress.IPv6Address(host_str[1:-1])

    except:
        return False

    return True


def validate_peer_str(peer_str):
    peer_parts = peer_str.rsplit(':', 1)
    if len(peer_parts) != 2:
        return False

    host_str = peer_parts[0]
    port_str = peer_parts[1]

    port = 0
    try:
        port = int(port_str, 10)
    except:
        return False

    if port <= 0:
        return False

    if len(host_str) <= 0:
        return False

    if validate_hostname(host_str):
        return True
    if validate_ipv4addr(host_str):
        return True
    if validate_ipv6addr(host_str):
        return True

    return False


def validate_peers_msg(msg_dict):
    if msg_dict['type'] != 'peers':
        raise UnexpectedMsgException("Message type is not 'peers'!")

    try:
        if 'peers' not in msg_dict:
            raise MalformedMsgException("Message malformed: peers is missing!")

        peers = msg_dict['peers']
        if not isinstance(peers, list):
            raise MalformedMsgException(
                "Message malformed: peers is not a list!")

        validate_allowed_keys(msg_dict, ['type', 'peers'], 'peers')

        for p in peers:
            if not isinstance(p, str):
                raise MalformedMsgException(
                    "Message malformed: peer is not a string!")

            if not validate_peer_str(p):
                raise MalformedMsgException(
                    "Message malformed: malformed peer '{}'!".format(p))

    except MalformedMsgException as e:
        raise e
    except Exception as e:
        raise MalformedMsgException("Message malformed: {}".format(str(e)))


def validate_getpeers_msg(msg_dict):
    if msg_dict['type'] != 'getpeers':
        raise UnexpectedMsgException("Message type is not 'getpeers'!")

    validate_allowed_keys(msg_dict, ['type'], 'getpeers')


def validate_getchaintip_msg(msg_dict):
    if msg_dict['type'] != 'getchaintip':
        raise UnexpectedMsgException("Message type is not 'getchaintip'!")

    validate_allowed_keys(msg_dict, ['type'], 'getchaintip')


def validate_getmempool_msg(msg_dict):
    if msg_dict['type'] != 'getmempool':
        raise UnexpectedMsgException("Message type is not 'getmempool'!")

    validate_allowed_keys(msg_dict, ['type'], 'getmempool')


def validate_error_msg(msg_dict):
    if msg_dict['type'] != 'error':
        raise UnexpectedMsgException("Message type is not 'error'!")

    try:
        if 'error' not in msg_dict:
            raise MalformedMsgException("Message malformed: error is missing!")

        error = msg_dict['error']
        if not isinstance(error, str):
            raise MalformedMsgException(
                "Message malformed: error is not a string!")

        validate_allowed_keys(msg_dict, ['type', 'error'], 'error')

    except MalformedMsgException as e:
        raise e
    except Exception as e:
        raise MalformedMsgException("Message malformed: {}".format(str(e)))


def validate_ihaveobject_msg(msg_dict):
    if msg_dict['type'] != 'ihaveobject':
        raise UnexpectedMsgException("Message type is not 'ihaveobject'!")


def validate_getobject_msg(msg_dict):
    if msg_dict['type'] != 'getobject':
        raise UnexpectedMsgException("Message type is not 'getobject'!")


def validate_object_msg(msg_dict):
    if msg_dict['type'] != 'object':
        raise UnexpectedMsgException("Message type is not 'object'!")


def validate_msg(msg_dict):
    msg_type = msg_dict['type']
    if msg_type == 'hello':
        validate_hello_msg(msg_dict)
    elif msg_type == 'getpeers':
        validate_getpeers_msg(msg_dict)
    elif msg_type == 'peers':
        validate_peers_msg(msg_dict)
    elif msg_type == 'getchaintip':
        validate_getchaintip_msg(msg_dict)
    elif msg_type == 'getmempool':
        validate_getmempool_msg(msg_dict)
    elif msg_type == 'error':
        validate_error_msg(msg_dict)
    elif msg_type == 'ihaveobject':
        validate_ihaveobject_msg(msg_dict)
    elif msg_type == 'getobject':
        validate_getobject_msg(msg_dict)
    elif msg_type == 'object':
        validate_object_msg(msg_dict)
    else:
        raise UnsupportedMsgException(
            "Message type {} not supported!".format(msg_type))


def verify_signature(signature, pubkey, message):
    pubkey = ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(pubkey)
    )
    try:
        pubkey.verify(bytes.fromhex(signature), message.encode("UTF-8"))
        return True
    except:
        return False


def validate_tx_format(transaction):
    if not "type" in transaction:
        return False
    if not "inputs" in transaction:
        if not "height" in transaction:
            return False
    else:
        for input in transaction["inputs"]:
            if not all(key in input for key in ("outpoint", "sig")):
                return False
            if not all(key in input["outpoint"] for key in ("txid", "index")):
                return False

    if not "outputs" in transaction:
        return False
    else:
        for output in transaction["outputs"]:
            if not all(key in output for key in ("pubkey", "value")):
                return False
    return True


def validate_tx(tx):
    if "height" in tx['object'] or tx['object']['type'] == 'blocks':
        return True
    obj = Object(tx)
    tx = json.loads(obj.object)
    validate_tx_format(tx)
    copy_tx = deepcopy(tx)
    for (i, input) in enumerate(tx['inputs']):
        copy_tx['inputs'][i]['sig'] = None
    copy_tx = json.dumps(copy_tx)
    copy_tx = copy_tx.replace("None", "null")
    copy_tx = copy_tx.replace(" ", "")
    # coservation
    for (i, input) in enumerate(tx['inputs']):
        if not objects_db.get_object(input['outpoint']['txid']) or input['outpoint']['index'] > len(tx['outputs']):
            return False
        prev_tx = json.loads(objects_db.get_object(input['outpoint']['txid']))
        return verify_signature(input['sig'], prev_tx['outputs'][i]['pubkey'], copy_tx)
