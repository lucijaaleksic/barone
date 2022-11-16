from abc import ABC, abstractproperty

"""
    Abstract class
"""
class MessageException(ABC, Exception):
    NETWORK_ERROR_MESSAGE = ""


class MsgParseException(MessageException):
    NETWORK_ERROR_MESSAGE = "Invalid exceptions received"


class MalformedMsgException(MessageException):
    NETWORK_ERROR_MESSAGE = "Malformed exceptions received"


class UnsupportedMsgException(MessageException):
    NETWORK_ERROR_MESSAGE = "Unsupported exceptions received"


class UnexpectedMsgException(MessageException):
    NETWORK_ERROR_MESSAGE = "Unexpected exceptions received"
