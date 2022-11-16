import hashlib


class Object:
    def __init__(self, o):
        self.object = str(o['object']).replace(" ", "").replace("\'", "\"")
        self.objectid = hashlib.sha256(self.object.encode("UTF-8")).hexdigest()

    def __str__(self) -> str:
        return f"{self.object}\n{self.objectid}"

    def __repr__(self):
        return f"{self.object}\n{self.objectid}"
