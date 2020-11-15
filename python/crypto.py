#!/usr/bin/env python3
import ctypes
from . import dll


# Constants
CHANNEL_SUCCESS = 0
CHANNEL_ERROR = -1
CHANNEL_READ_WAIT = -2
CHANNEL_WRITE_WAIT = -3


# Types
private_key_t = ctypes.c_ubyte * 32
private_key_p = ctypes.POINTER(private_key_t)
public_key_t = ctypes.c_ubyte * 32
public_key_p = ctypes.POINTER(private_key_t)
crypto_channel_p = ctypes.c_void_p
buffer_p = ctypes.POINTER(ctypes.c_ubyte)


# C Functions
_crypto_generate_keys = dll.crypto_generate_keys
_crypto_generate_keys.restype = None
_crypto_generate_keys.argtypes = (public_key_p, private_key_p)

_crypto_generate_public_key = dll.crypto_generate_public_key
_crypto_generate_public_key.restype = None
_crypto_generate_public_key.argtypes = (public_key_p, private_key_p)

_crypto_channel_new = dll.crypto_channel_new
_crypto_channel_new.restype = crypto_channel_p
_crypto_channel_new.argtypes = (ctypes.c_int, private_key_p, public_key_p)

_crypto_channel_free = dll.crypto_channel_free
_crypto_channel_free.restype = None
_crypto_channel_free.argtypes = (crypto_channel_p,)

_crypto_channel_init = dll.crypto_channel_init
_crypto_channel_init.restype = None
_crypto_channel_init.argtypes = (crypto_channel_p, ctypes.c_int, private_key_p, public_key_p)

_crypto_channel_connect = dll.crypto_channel_connect
_crypto_channel_connect.restype = ctypes.c_int
_crypto_channel_connect.argtypes = (crypto_channel_p, public_key_p)

_crypto_channel_fini = dll.crypto_channel_fini
_crypto_channel_fini.restype = None
_crypto_channel_fini.argtypes = (crypto_channel_p,)

_crypto_channel_write = dll.crypto_channel_write
_crypto_channel_write.restype = ctypes.c_int
_crypto_channel_write.argtypes = (crypto_channel_p, buffer_p, ctypes.c_size_t)

_crypto_channel_read = dll.crypto_channel_read
_crypto_channel_read.restype = ctypes.c_int
_crypto_channel_read.argtypes = (crypto_channel_p, buffer_p, ctypes.c_size_t)

_crypto_channel_continue = dll.crypto_channel_continue
_crypto_channel_continue.restype = ctypes.c_int
_crypto_channel_continue.argtypes = (crypto_channel_p,)


# Python Wrappers
import asyncio
import os
import socket
from typing import Tuple


def generate_keys() -> Tuple[bytes, bytes]:
    """
    @return A tuple containing the remote key and the local key.
    """
    public_key = public_key_t()
    private_key = private_key_t()
    _crypto_generate_keys(public_key, private_key)
    return bytes(public_key), bytes(private_key)


def generate_public_key(private_key: bytes) -> bytes:
    """
    @return A public key generated using the private key.
    """
    public_key = public_key_t()
    _crypto_generate_public_key(public_key, private_key)
    return bytes(public_key)


class CryptoChannel:
    def __init__(self, fd, private_key: bytes = None, public_key: bytes = None):
        # Set cleanup attributes
        self._channel = None
        self.fd_owner = None
        self.fd = None
        # Set key attributes
        if private_key is None:
            self.public_key, self.private_key = generate_keys()
        elif public_key is None:
            self.private_key = private_key
            self.public_key = generate_public_key(private_key)
        else:
            self.private_key = private_key
            self.public_key = public_key
        # Validate key lengths
        if len(private_key) != private_key_t._length_:
            raise TypeError("local key must be {} bytes".format(private_key_t._length_))
        if len(public_key) != public_key_t._length_:
            raise TypeError("remote key must be {} bytes".format(public_key_t._length_))
        # Overwrite _channel and fd
        if hasattr(fd, 'fileno'):
            self.fd_owner = fd
            self.fd = fd.fileno()
        else:
            self.fd_owner = self
            self.fd = fd
        self._channel = _crypto_channel_new(self.fd, self.private_key, self.public_key)

    def __del__(self):
        self.close()

    def __enter__(self):
        return self
    
    def __exit__(self, type, value, traceback):
        self.close()

    def fileno(self):
        return self.fd

    def close(self):
        if self._channel is not None:
            _crypto_channel_free(self._channel)
            self._channel = None

        if self.fd is not None:
            if self.fd_owner is self:
                os.close(self.fd)
            else:
                self.fd_owner.close()
            self.fd = None
            self.fd_owner = None
    
    def connect(self, remote_public_key: bytes = None):
        status = _crypto_channel_connect(self._channel, remote_public_key)
        if status == CHANNEL_ERROR:
            raise IOError("CryptoChannel failed to exchange keys")
        elif status == CHANNEL_READ_WAIT or status == CHANNEL_WRITE_WAIT:
            raise IOError("CryptoChannel underlying fd cannot be nonblocking")
    
    def read(self, count: int) -> bytes:
        if self._channel is None:
            raise IOError("CryptoChannel is closed")
        buffer = ctypes.c_buffer(count)
        status = _crypto_channel_read(self._channel, buffer, count)
        if status == CHANNEL_READ_WAIT:
            raise IOError("CryptoChannel underlying fd cannot be nonblocking")
        elif status != CHANNEL_SUCCESS:
            raise IOError("CryptoChannel read failed")
        return bytes(buffer)
    
    def write(self, data: bytes):
        if self._channel is None:
            raise IOError("CryptoChannel is closed")
        status = _crypto_channel_write(self._channel, data, len(data))
        if status == CHANNEL_WRITE_WAIT:
            raise IOError("CryptoChannel underlying fd cannot be nonblocking")
        elif status != CHANNEL_SUCCESS:
            raise IOError("CryptoChannel write failed")

    def read_str(self) -> str:
        message_length = int.from_bytes(self.read(4), 'big', signed=False)
        return self.read(message_length).decode('utf-8')

    def write_str(self, message: str):
        data = message.encode('utf-8')
        self.write(len(data).to_bytes(4, 'big', signed=False))
        self.write(data)

    recv = read
    send = write
    recv_str = read_str
    send_str = write_str


class AsyncCryptoChannel(CryptoChannel):
    def _connect_read_continue(self, future):
        # Attempt to continue
        loop = asyncio.get_running_loop()
        status = _crypto_channel_continue(self._channel)
        # If the connection is complete, set the future to done
        if status == CHANNEL_SUCCESS:
            loop.remove_reader(self.fd)
            future.set_result(None)
        # If the connection failed, raise an exception
        elif status == CHANNEL_ERROR:
            loop.remove_reader(self.fd)
            future.set_exception(IOError("AsyncCryptoChannel key exchange failed"))
        # If the connect is waiting to write, switch watcher type
        elif status == CHANNEL_WRITE_WAIT:
            loop.remove_reader(self.fd)
            loop.add_writer(self.fd, self._connect_write_continue, future)
        # If the connect is waiting to read, let the callback run again
        else:
            pass

    def _connect_write_continue(self, future):
        # Attempt to continue
        loop = asyncio.get_running_loop()
        status = _crypto_channel_continue(self._channel)
        # If the connection is complete, set the future to done
        if status == CHANNEL_SUCCESS:
            loop.remove_writer(self.fd)
            future.set_result(None)
        # If the connection failed, raise an exception
        elif status == CHANNEL_ERROR:
            loop.remove_writer(self.fd)
            future.set_exception(IOError("AsyncCryptoChannel key exchange failed"))
        # If the connect is waiting to read, switch watcher type
        elif status == CHANNEL_READ_WAIT:
            loop.remove_writer(self.fd)
            loop.add_reader(self.fd, self._connect_read_continue, future)
        # If the connect is waiting to write, let the callback run again
        else:
            pass

    def _read_continue(self, future, buffer):
        status = _crypto_channel_continue(self._channel)
        if status == CHANNEL_SUCCESS:
            asyncio.get_running_loop().remove_reader(self.fd)
            future.set_result(bytes(buffer))
        elif status == CHANNEL_ERROR:
            asyncio.get_running_loop().remove_reader(self.fd)
            future.set_exception(IOError("AsyncCryptoChannel read failed"))

    def _write_continue(self, future):
        status = _crypto_channel_continue(self._channel)
        if status == CHANNEL_SUCCESS:
            asyncio.get_running_loop().remove_writer(self.fd)
            future.set_result(None)
        elif status == CHANNEL_ERROR:
            asyncio.get_running_loop().remove_writer(self.fd)
            future.set_exception(IOError("AsyncCryptoChannel write failed"))

    async def connect(self, remote_public_key: bytes = None):
        # Begin connect
        status = _crypto_channel_connect(self._channel, remote_public_key)
        if status == CHANNEL_ERROR:
            raise IOError("CryptoChannel failed to exchange keys")
        elif status == CHANNEL_SUCCESS:
            return

        # Create future object
        loop = asyncio.get_running_loop()
        crypto_connect_future = loop.create_future()

        # Wait until the fd is readable/writeable to call continue
        if status == CHANNEL_READ_WAIT:
            loop.add_reader(self.fd, self._connect_read_continue, crypto_connect_future)
        elif status == CHANNEL_WRITE_WAIT:
            loop.add_writer(self.fd, self._connect_write_continue, crypto_connect_future)

        # Wait for future result
        await crypto_connect_future

    async def read(self, count: int) -> bytes:
        # Begin read
        crypto_read_buffer = ctypes.c_buffer(count)
        status = _crypto_channel_read(self._channel, crypto_read_buffer, count)
        if status == CHANNEL_SUCCESS:
            return bytes(crypto_read_buffer)
        elif status == CHANNEL_ERROR:
            raise IOError("AsyncCryptoChannel read failed")

        # Create future object
        loop = asyncio.get_running_loop()
        crypto_read_future = loop.create_future()

        # Wait until the fd is readable to call continue
        loop.add_reader(self.fd, self._read_continue, crypto_read_future, crypto_read_buffer)

        # Wait for future result
        return await crypto_read_future

    async def write(self, data: bytes):
        # Begin write
        status = _crypto_channel_write(self._channel, data, len(data))
        if status == CHANNEL_SUCCESS:
            return
        elif status == CHANNEL_ERROR:
            raise IOError("AsyncCryptoChannel write failed")

        # Create future object
        loop = asyncio.get_running_loop()
        crypto_write_future = loop.create_future()
        
        # Wait until the fd is writeable to call continue
        loop.add_writer(self.fd, self._write_continue, crypto_write_future)

        # Wait for future result
        return await crypto_write_future

    async def read_str(self) -> str:
        message_length = int.from_bytes(await self.read(4), 'big', signed=False)
        return await self.read(message_length).decode('utf-8')

    async def write_str(self, message: str):
        data = message.encode('utf-8')
        await self.write(len(data).to_bytes(4, 'big', signed=False))
        await self.write(data)

    recv = read
    send = write
    recv_str = read_str
    send_str = write_str


def connect(host: str, port: int,
            *,
            private_key: bytes = None,
            local_public_key: bytes = None,
            remote_public_key: bytes = None):
    sock = socket.socket()
    sock.connect((host, port))
    channel = CryptoChannel(sock, private_key, local_public_key)
    channel.connect(remote_public_key)
    return channel


def wrap_socket(sock,
                *,
                private_key: bytes = None,
                local_public_key: bytes = None,
                remote_public_key: bytes = None):
    channel = CryptoChannel(sock, private_key, local_public_key)
    channel.connect(remote_public_key)
    return channel


async def async_connect(host: str, port: int,
                        *,
                        private_key: bytes = None,
                        local_public_key: bytes = None,
                        remote_public_key: bytes = None):
    loop = asyncio.get_running_loop()
    sock = socket.socket()
    sock.setblocking(False)
    await loop.sock_connect(sock, (host, port))
    channel = AsyncCryptoChannel(sock, private_key, local_public_key)
    await channel.connect(remote_public_key)
    return channel


async def async_wrap_socket(sock,
                            *,
                            private_key: bytes = None,
                            local_public_key: bytes = None,
                            remote_public_key: bytes = None):
    sock.setblocking(False)
    channel = AsyncCryptoChannel(sock, private_key, local_public_key)
    await channel.connect(remote_public_key)
    return channel
