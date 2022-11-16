import hashlib

from models.Peer import Peer
import constants.constants as const
from exceptions.msgexceptions import *
from util import messenger, validator

import peer_db
import objects_db
import asyncio
import ipaddress
import json # change to canonicaljson
import random

PEERS = set()
CONNECTIONS = set()
BACKGROUND_TASKS = set()


def add_peer(peer):
    # Do not add banned peer addresses
    if peer.host in const.BANNED_HOSTS:
        return

    # Do not add loopback or multicast addrs
    try:
        ip = ipaddress.ip_address(peer.host)

        if ip.is_loopback or ip.is_multicast:
            return
    except:
        pass

    peer_db.store_peer(peer, PEERS)
    PEERS.add(peer)


def add_connection(peer):
    ip, port = peer
    CONNECTIONS.add(Peer(ip, port))


def del_connection(peer):
    ip, port = peer
    CONNECTIONS.remove(Peer(ip, port))


def parse_msg(msg_str):
    try:
        msg = json.loads(msg_str)
    except Exception as e:
        raise MsgParseException("JSON parse error: {}".format(str(e)))

    if not isinstance(msg, dict):
        raise MsgParseException("Malformed exceptions!")
    if not 'type' in msg:
        raise MsgParseException("Malformed exceptions!")

    return msg


def serialize_msg(msg_dict):
    return json.dumps(msg_dict, separators=(',', ':')) + '\n'


async def write_msg(writer, msg_dict):
    msg_str = serialize_msg(msg_dict)
    writer.write(msg_str.encode("utf-8"))
    await writer.drain()


async def gossip(objectid):
    print(objectid)
    await broadcast_message(messenger.mk_ihaveobject_msg(objectid))


def handle_peers_msg(msg_dict):
    for p in msg_dict['peers']:
        peer_parts = p.rsplit(':', 1)

        host_str, port_str = peer_parts

        port = int(port_str, 10)

        peer = Peer(host_str, port)
        add_peer(peer)


def handle_error_msg(msg_dict):
    raise Exception("Received error '{}'".format(msg_dict['error']))


def handle_getobject(msg):
    obj = objects_db.get_object(msg['objectid'])
    if obj is not None:
        return obj
    else:
        print("[DEBUG] Error no such object!")


async def handle_ihaveobject(msg, writer):
    if objects_db.get_object(msg['objectid']) is None:
        await write_msg(writer, messenger.mk_getobject_msg(msg['objectid']))


async def handle_object(msg):
    if not validator.validate_tx(msg):
        return False
    if objects_db.store_object(msg):
        await gossip(hashlib.sha256(json.dumps(msg['object']).encode("UTF-8")).hexdigest())  # should be async


async def handle_connection(reader, writer):
    peer = None
    try:
        peer = writer.get_extra_info('peername')
        if not peer:
            raise Exception("Failed to get peername!")
        add_connection(peer)

        print("New connection with {}".format(peer))
    except Exception as e:
        print(str(e))
        try:
            writer.close()
        except:
            pass

    try:
        if peer not in CONNECTIONS:
            await write_msg(writer, messenger.mk_hello_msg())
            await write_msg(writer, messenger.mk_getpeers_msg())

            firstmsg_str = await asyncio.wait_for(reader.readline(), timeout=const.HELLO_MSG_TIMEOUT)
            firstmsg = parse_msg(firstmsg_str)
            validator.validate_hello_msg(firstmsg)

        while True:
            msg_str = await reader.readline()
            msg = parse_msg(msg_str)
            validator.validate_msg(msg)

            msg_type = msg['type']
            if msg_type == 'hello':
                pass
            elif msg_type == 'getpeers':
                await write_msg(writer, messenger.mk_peers_msg(PEERS))
            elif msg_type == 'peers':
                handle_peers_msg(msg)
            elif msg_type == 'error':
                handle_error_msg(msg)
            elif msg_type == 'getobject':
                o = handle_getobject(msg)
                if o is not None:
                    await write_msg(writer, messenger.mk_object_msg(o))
                else:
                    await write_msg(writer, messenger.mk_error_msg("No such object."))
            elif msg_type == 'ihaveobject':
                await handle_ihaveobject(msg, writer)
            elif msg_type == 'object':
                if not await handle_object(msg):
                    await write_msg(writer, messenger.mk_error_msg("Invalid transaction."))
                else:
                    objects_db.store_object(msg)

    except asyncio.exceptions.TimeoutError:
        print("{}: Timeout".format(peer))
        try:
            await write_msg(writer, messenger.mk_error_msg("Timeout"))
        except:
            pass
    except MessageException as e:
        print("{}: {}".format(peer, str(e)))
        try:
            await write_msg(writer, messenger.mk_error_msg(e.NETWORK_ERROR_MESSAGE))
        except:
            pass
    except Exception as e:
        print("{}: {}".format(peer, str(e)))
    finally:
        print("Closing connection with {}".format(peer))
        writer.close()
        del_connection(peer)


async def connect_to_node(peer: Peer):
    try:
        reader, writer = await asyncio.open_connection(peer.host, peer.port)
    except Exception as e:
        print(str(e))
        return

    await handle_connection(reader, writer)


async def broadcast_message(message):
    for peer in CONNECTIONS:
        try:
            reader, writer = await asyncio.open_connection(peer.host, peer.port)
        except Exception as e:
            print(str(e))
            return
        print("[DEBUG] Gossiping: " + json.dumps(message) + " to " + peer.host)
        await write_msg(writer, message)


async def listen():
    server = await asyncio.start_server(handle_connection, '0.0.0.0', const.PORT)

    print("Listening on port {}".format(const.PORT))

    async with server:
        await server.serve_forever()


async def bootstrap():
    for p in const.PRELOADED_PEERS:
        add_peer(p)
        t = asyncio.create_task(connect_to_node(p))
        BACKGROUND_TASKS.add(t)
        t.add_done_callback(BACKGROUND_TASKS.discard)


def resupply_connections():
    if len(CONNECTIONS) >= const.LOW_CONNECTION_THRESHOLD:
        return

    npeers = const.LOW_CONNECTION_THRESHOLD - len(CONNECTIONS)
    available_peers = PEERS - CONNECTIONS

    if len(available_peers) == 0:
        print("Not enough peers available to reconnect.")
        return

    if len(available_peers) < npeers:
        npeers = len(available_peers)

    print("Connecting to {} new peers.".format(npeers))

    chosen_peers = random.sample(tuple(available_peers), npeers)
    for p in chosen_peers:
        t = asyncio.create_task(connect_to_node(p))
        BACKGROUND_TASKS.add(t)
        t.add_done_callback(BACKGROUND_TASKS.discard)


async def init():
    PEERS.update(peer_db.get_peers())

    bootstrap_task = asyncio.create_task(bootstrap())
    listen_task = asyncio.create_task(listen())

    # Service loop
    while True:
        print("Service loop reporting in.")
        print("Open connections: {}".format(CONNECTIONS))

        # Open more connections if necessary
        # resupply_connections()

        await asyncio.sleep(const.SERVICE_LOOP_DELAY)

    await bootstrap_task
    await listen_task


def main():
    asyncio.run(init())


if __name__ == "__main__":
    main()
