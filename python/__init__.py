# Open DLL
import ctypes
dll = ctypes.cdll.LoadLibrary("libopal.so")

# Import package modules
from . import crypto
