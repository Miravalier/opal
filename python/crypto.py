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

_crypto_channel_connect = dll.crypto_channel_init
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
        self._channel = _crypto_channel_new(self.fd, private_key, public_key)

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
    
    def read(self, count: int):
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


class AsyncCryptoChannel(CryptoChannel):
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

    async def read(self, count: int):
        # Create future object
        loop = asyncio.get_running_loop()
        crypto_read_future = loop.create_future()

        # Begin read
        crypto_read_buffer = ctypes.c_buffer(count)
        status = _crypto_channel_read(self._channel, crypto_read_buffer, count)
        if status == CHANNEL_SUCCESS:
            return bytes(crypto_read_buffer)
        elif status == CHANNEL_ERROR:
            raise IOError("AsyncCryptoChannel read failed")

        # Wait until the fd is readable to call continue
        loop.add_reader(self.fd, self._read_continue, crypto_read_future, crypto_read_buffer)

        # Wait for future result
        return await crypto_read_future

    async def write(self, data: bytes):
        # Create future object
        loop = asyncio.get_running_loop()
        crypto_write_future = loop.create_future()

        # Begin write
        status = _crypto_channel_write(self._channel, data, len(data))
        if status == CHANNEL_SUCCESS:
            return
        elif status == CHANNEL_ERROR:
            raise IOError("AsyncCryptoChannel write failed")
        
        # Wait until the fd is writeable to call continue
        loop.add_writer(self.fd, self._write_continue, crypto_write_future)

        # Wait for future result
        return await crypto_write_future
