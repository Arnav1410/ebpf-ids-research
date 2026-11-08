"""Owned listening sockets, optionally inherited after privilege drop (Linux)."""
import socket


def reserve(address, port, service):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((address, port))
        listener.listen(64)
        return listener
    except OSError as error:
        listener.close()
        raise RuntimeError(f'{service} cannot listen on {address}:{port}: {error}. Existing listeners are never terminated.') from error


def inherited(fd, address, port):
    listener = socket.socket(fileno=fd)
    if (listener.family != socket.AF_INET or listener.type != socket.SOCK_STREAM
            or listener.getsockname() != (address, port)
            or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)):
        listener.close()
        raise ValueError('Inherited listener does not match configured TCP address/port')
    return listener
