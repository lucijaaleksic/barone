from models.Peer import Peer


PORT = 18018
SERVICE_LOOP_DELAY = 100
VERSION = '0.8.0'
AGENT = 'barone'
LOW_CONNECTION_THRESHOLD = 3
HELLO_MSG_TIMEOUT = 10.0

BANNED_HOSTS = [
        "1.1.1.1",
        "8.8.8.8",
        "20.23.212.159", # excessive ports, see TUWEL
        "84.115.238.131", # excessive ports
        "85.127.44.22", # excessive ports
]

PRELOADED_PEERS = {
    Peer("128.130.122.101", 18018), # lecturers node
    Peer("20.123.80.80", 18018),
    Peer("143.244.205.208", 18018),
    Peer("138.197.177.229", 18018),
    Peer("46.101.71.58", 18018),
    Peer("51.137.60.68", 18018),
}
