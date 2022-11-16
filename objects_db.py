from models.Object import Object
from typing import Iterable, Set

OBJECT_DB_FILE = "objects.txt"
objects = set()


def store_object(o):
    newobject = Object(o)
    with open(OBJECT_DB_FILE, 'r') as file:
        objects = file.readlines()
    if (newobject.objectid + " " + newobject.object + "\n") in objects:
        return False
    with open(OBJECT_DB_FILE, 'a') as file:
        file.write(f"{newobject.objectid} {newobject.object}\n")
    print("[DEBUG] new object: ", newobject)
    return True


def get_object(get_objectid):
    with open(OBJECT_DB_FILE, 'r') as file:
        objects = file.readlines()
    for line in objects:
        objectid, object = line.split(' ')
        if objectid == get_objectid:
            return object  # the object string
    return None
