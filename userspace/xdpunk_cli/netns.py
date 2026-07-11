"""Helpers de network namespace (ctypes, sem subprocess).

Resolucao de nome/indice/MAC de interface sempre DENTRO do namespace do
switch: ifindex e namespace-specific, e o socket usado pelos ioctls e
criado ja dentro do namespace alvo.
"""

import ctypes
import ctypes.util
import fcntl
import os
import socket
import struct
import sys

CLONE_NEWNET = 0x40000000
SIOCGIFHWADDR = 0x8927

_libc = None


def _get_libc():
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    return _libc


def _setns(fd: int, nstype: int):
    if _get_libc().setns(fd, nstype) == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))


def _enter_netns(netns: str):
    """Enter a network namespace. Returns the fd of the *original* netns."""
    orig_fd = os.open("/proc/self/ns/net", os.O_RDONLY)
    try:
        target_fd = os.open(f"/var/run/netns/{netns}", os.O_RDONLY)
    except OSError:
        os.close(orig_fd)
        raise
    try:
        _setns(target_fd, CLONE_NEWNET)
    finally:
        os.close(target_fd)
    return orig_fd


def _restore_netns(orig_fd: int):
    """Restore the original network namespace."""
    try:
        _setns(orig_fd, CLONE_NEWNET)
    finally:
        os.close(orig_fd)


def get_ifindex(iface: str, netns: str) -> int:
    """Resolve interface name -> ifindex inside *netns*."""
    orig_fd = _enter_netns(netns)
    try:
        return socket.if_nametoindex(iface)
    except OSError:
        print(
            f"Erro: interface '{iface}' nao encontrada no namespace '{netns}'.",
            file=sys.stderr,
        )
        sys.exit(1)
    finally:
        _restore_netns(orig_fd)


def get_ifname(ifindex: int, netns: str) -> str:
    """Resolve ifindex -> interface name inside *netns*."""
    orig_fd = _enter_netns(netns)
    try:
        return socket.if_indextoname(ifindex)
    except OSError:
        return f"?(ifindex={ifindex})"
    finally:
        _restore_netns(orig_fd)


def get_mac(iface: str, netns: str) -> bytes:
    """MAC (6 bytes) de *iface* dentro de *netns*, via ioctl SIOCGIFHWADDR."""
    orig_fd = _enter_netns(netns)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            info = fcntl.ioctl(
                s.fileno(),
                SIOCGIFHWADDR,
                struct.pack("256s", iface.encode()[:15]),
            )
            return info[18:24]
        finally:
            s.close()
    except OSError:
        print(
            f"Erro: nao foi possivel obter o MAC de '{iface}' no namespace "
            f"'{netns}'.",
            file=sys.stderr,
        )
        sys.exit(1)
    finally:
        _restore_netns(orig_fd)
