"""list_listening_ports — Phase 8's production capability (read-only, P1).

Lists the TCP and UDP sockets listening on the local host, with the owning
PID and the process's executable base name where the OS reveals them.

Output (``ToolResult.output``)::

    {"ports": [{"protocol": "tcp"|"udp", "port": int, "local_address": str,
                "pid": int (optional), "process": str (optional)}, ...]}

Entries are de-duplicated and sorted, so identical host state gives
identical output.

How the data is read (stdlib only; no child process, no shell, no network):

- **Linux:** the four kernel socket tables ``/proc/net/{tcp,tcp6,udp,udp6}``.
  PIDs come from matching socket inodes in ``/proc/<pid>/fd`` links, and
  the process name from ``/proc/<pid>/comm`` (the kernel's short task
  name). Nothing else under ``/proc/<pid>`` is read.
- **Windows:** ``GetExtendedTcpTable``/``GetExtendedUdpTable``
  (``iphlpapi``, via ``ctypes``) with the owner-PID table classes. These
  return binary tables, so no localized text is parsed. The process name
  is the base name of ``QueryFullProcessImageNameW``; the directory part
  is discarded.
- **Anything else:** ``UnsupportedPlatformError``. The executor turns it
  into a ``ToolResult`` error.

Security posture:

- Collects no process arguments and no process environment block, and
  reads no environment variables. The only per-process fact is the
  executable base name.
- Process names are host-controlled, untrusted text. They are kept as
  ordinary string data (never interpreted), and a name longer than
  ``MAX_PROCESS_NAME_LENGTH`` is omitted rather than cut.
- Parsing is strict. A row that does not match the expected format fails
  the whole call with ``SocketTableParseError``; rows are never skipped,
  repaired or guessed, since silently dropping a listener would make the
  evidence misleading.
- Every step is bounded: files and tables are read up to fixed byte
  limits, the Windows size negotiation retries a fixed number of times,
  and nothing waits on another process or the network. (The Runtime's
  timeout check is not preemptive, so this capability must not block.)
- Output larger than ``MAX_OUTPUT_BYTES`` (canonical JSON) raises
  ``OutputTooLargeError``. It is never truncated.
"""
from __future__ import annotations

import json
import ntpath
import os
import posixpath
import re
import socket
import struct
import sys
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from chanakya.contracts.target import Target

#: Must match the ``capability`` of the production ``RegistryEntry``
#: (``chanakya.registry.bootstrap.LIST_LISTENING_PORTS_CAPABILITY``).
CAPABILITY_ID = "list_listening_ports"

_SUPPORTED_TARGET_TYPES: Sequence[str] = ("local_host",)

#: Canonical JSON size limit for the output. Kept below the Evidence
#: Store's 65,536-byte payload limit so a successful result always fits
#: the evidence record (which wraps the output with a few more keys).
MAX_OUTPUT_BYTES = 60000

#: Longer process names are omitted (the entry keeps pid, drops process).
MAX_PROCESS_NAME_LENGTH = 256

#: Upper bound on bytes read from one kernel socket table (file or buffer).
MAX_TABLE_BYTES = 16 * 1024 * 1024

_PROTOCOLS = ("tcp", "udp")


class ListeningPortsError(Exception):
    """Base class for this capability's failures."""


class UnsupportedPlatformError(ListeningPortsError):
    """No reader exists for this operating system."""


class SocketTableParseError(ListeningPortsError):
    """A socket table did not have the expected format. Messages name the
    table and row number only, never row content."""


class OutputTooLargeError(ListeningPortsError):
    """The output would exceed ``MAX_OUTPUT_BYTES``."""


@dataclass(frozen=True)
class ListeningSocket:
    protocol: str
    local_address: str
    port: int
    pid: Optional[int] = None
    process: Optional[str] = None


def _canonical_size(value: Any) -> int:
    return len(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))


def _clean_process_name(name: Optional[str]) -> Optional[str]:
    if not isinstance(name, str) or not name or len(name) > MAX_PROCESS_NAME_LENGTH:
        return None
    return name


def _check_port(port: int, where: str) -> int:
    if not 1 <= port <= 65535:
        raise SocketTableParseError(f"{where}: port out of range")
    return port


# =============================================================================
# Linux: /proc/net/{tcp,tcp6,udp,udp6}
# =============================================================================

_LINUX_TABLES = (("tcp", "tcp", False), ("tcp6", "tcp", True), ("udp", "udp", False), ("udp6", "udp", True))
_TCP_LISTEN = "0A"
_UDP_UNCONNECTED = "07"
_SL = re.compile(r"^\d+:$")
_ADDR4 = re.compile(r"^([0-9A-Fa-f]{8}):([0-9A-Fa-f]{4})$")
_ADDR6 = re.compile(r"^([0-9A-Fa-f]{32}):([0-9A-Fa-f]{4})$")
_STATE = re.compile(r"^[0-9A-Fa-f]{2}$")
_DECIMAL = re.compile(r"^\d+$")
_SOCKET_LINK = re.compile(r"^socket:\[(\d+)\]$")


def _decode_proc_address(hex_address: str, ipv6: bool) -> str:
    """The kernel prints each 32-bit word of the address in host (little-
    endian) byte order."""
    words = [hex_address[i : i + 8] for i in range(0, len(hex_address), 8)]
    raw = b"".join(struct.pack("<I", int(word, 16)) for word in words)
    return socket.inet_ntop(socket.AF_INET6 if ipv6 else socket.AF_INET, raw)


def parse_proc_net_table(text: str, *, table: str, protocol: str, ipv6: bool) -> List[Tuple[ListeningSocket, int]]:
    """Parses one ``/proc/net`` table. Returns ``(socket, inode)`` for each
    listening TCP socket (state ``0A``) or unconnected UDP socket (state
    ``07``, remote port 0). Any malformed row fails the whole table."""
    if protocol not in _PROTOCOLS:
        raise ValueError("protocol must be 'tcp' or 'udp'")
    lines = text.splitlines()
    if not lines or not lines[0].strip().startswith("sl"):
        raise SocketTableParseError(f"{table}: missing header row")
    address_pattern = _ADDR6 if ipv6 else _ADDR4
    results = []
    for number, line in enumerate(lines[1:], start=2):
        if not line.strip():
            continue
        fields = line.split()
        where = f"{table} row {number}"
        if len(fields) < 10 or not _SL.match(fields[0]):
            raise SocketTableParseError(f"{where}: unexpected row format")
        local = address_pattern.match(fields[1])
        remote = address_pattern.match(fields[2])
        if local is None or remote is None:
            raise SocketTableParseError(f"{where}: invalid address")
        if not _STATE.match(fields[3]) or not _DECIMAL.match(fields[9]):
            raise SocketTableParseError(f"{where}: invalid state or inode")
        state = fields[3].upper()
        if protocol == "tcp" and state != _TCP_LISTEN:
            continue
        if protocol == "udp" and (state != _UDP_UNCONNECTED or int(remote.group(2), 16) != 0):
            continue
        port = _check_port(int(local.group(2), 16), where)
        try:
            address = _decode_proc_address(local.group(1), ipv6)
        except (OSError, ValueError, struct.error):
            raise SocketTableParseError(f"{where}: invalid address") from None
        results.append((ListeningSocket(protocol=protocol, local_address=address, port=port), int(fields[9])))
    return results


class LinuxSocketReader:
    """Reads the kernel socket tables and maps inodes to PIDs. File access
    functions are injectable for tests."""

    def __init__(
        self,
        proc_root: str = "/proc",
        *,
        read_text: Optional[Callable[[str], str]] = None,
        list_dir: Optional[Callable[[str], List[str]]] = None,
        read_link: Optional[Callable[[str], str]] = None,
    ) -> None:
        self._root = proc_root
        self._read_text = read_text or self._default_read_text
        self._list_dir = list_dir or os.listdir
        self._read_link = read_link or os.readlink

    @staticmethod
    def _default_read_text(path: str) -> str:
        with open(path, "rb") as handle:
            data = handle.read(MAX_TABLE_BYTES + 1)
        if len(data) > MAX_TABLE_BYTES:
            raise SocketTableParseError(f"{posixpath.basename(path)}: table exceeds {MAX_TABLE_BYTES} bytes")
        return data.decode("utf-8", errors="backslashreplace")

    def read(self) -> List[ListeningSocket]:
        found: List[Tuple[ListeningSocket, int]] = []
        for name, protocol, ipv6 in _LINUX_TABLES:
            path = posixpath.join(self._root, "net", name)
            try:
                text = self._read_text(path)
            except FileNotFoundError:
                if ipv6:
                    continue  # IPv6 disabled: the table does not exist
                raise SocketTableParseError(f"{name}: table not found") from None
            found.extend(parse_proc_net_table(text, table=name, protocol=protocol, ipv6=ipv6))
        owners = self._owners({inode for _, inode in found if inode})
        result = []
        for sock, inode in found:
            owner = owners.get(inode)
            if owner is None:
                result.append(sock)
            else:
                pid, process = owner
                result.append(ListeningSocket(sock.protocol, sock.local_address, sock.port, pid, process))
        return result

    def _owners(self, inodes: Iterable[int]) -> Dict[int, Tuple[int, Optional[str]]]:
        wanted = set(inodes)
        owners: Dict[int, Tuple[int, Optional[str]]] = {}
        if not wanted:
            return owners
        try:
            entries = self._list_dir(self._root)
        except OSError:
            return owners
        for entry in sorted((e for e in entries if e.isdigit()), key=int):
            pid = int(entry)
            fd_dir = posixpath.join(self._root, entry, "fd")
            try:
                fds = self._list_dir(fd_dir)
            except OSError:
                continue  # another user's process, or it exited
            process: Optional[str] = None
            named = False
            for fd in fds:
                try:
                    link = self._read_link(posixpath.join(fd_dir, fd))
                except OSError:
                    continue
                match = _SOCKET_LINK.match(link)
                if match is None:
                    continue
                inode = int(match.group(1))
                if inode not in wanted or inode in owners:
                    continue
                if not named:
                    process, named = self._process_name(entry), True
                owners[inode] = (pid, process)
        return owners

    def _process_name(self, pid_entry: str) -> Optional[str]:
        try:
            name = self._read_text(posixpath.join(self._root, pid_entry, "comm"))
        except OSError:
            return None
        return _clean_process_name(name.rstrip("\n"))


# =============================================================================
# Windows: GetExtendedTcpTable / GetExtendedUdpTable
# =============================================================================

_AF_INET = 2
_AF_INET6 = 23
_TCP_TABLE_OWNER_PID_LISTENER = 3
_UDP_TABLE_OWNER_PID = 1
_MIB_TCP_STATE_LISTEN = 2
_NO_ERROR = 0
_ERROR_INSUFFICIENT_BUFFER = 122
_MAX_TABLE_ATTEMPTS = 5

#: (row size, parser) per table, following the MIB_*ROW_OWNER_PID layouts.
_TCP4_ROW = 24  # state, local addr, local port, remote addr, remote port, pid
_TCP6_ROW = 56  # local addr[16], scope, local port, remote addr[16], scope, remote port, state, pid
_UDP4_ROW = 12  # local addr, local port, pid
_UDP6_ROW = 28  # local addr[16], scope, local port, pid


def _windows_port(buffer: bytes, offset: int, where: str) -> int:
    # dwLocalPort: port in network byte order in the low 16 bits; the high
    # 16 bits must be zero.
    port = struct.unpack_from(">H", buffer, offset)[0]
    if struct.unpack_from("<H", buffer, offset + 2)[0] != 0:
        raise SocketTableParseError(f"{where}: invalid port field")
    return _check_port(port, where)


def _windows_rows(buffer: bytes, row_size: int, table: str) -> Iterable[Tuple[int, str]]:
    if len(buffer) < 4:
        raise SocketTableParseError(f"{table}: truncated table")
    count = struct.unpack_from("<I", buffer, 0)[0]
    if 4 + count * row_size > len(buffer):
        raise SocketTableParseError(f"{table}: row count exceeds table size")
    for index in range(count):
        yield 4 + index * row_size, f"{table} row {index + 1}"


def parse_windows_tcp4_table(buffer: bytes) -> List[ListeningSocket]:
    result = []
    for offset, where in _windows_rows(buffer, _TCP4_ROW, "tcp4"):
        state, = struct.unpack_from("<I", buffer, offset)
        if state != _MIB_TCP_STATE_LISTEN:
            raise SocketTableParseError(f"{where}: not a listening row")
        address = socket.inet_ntop(socket.AF_INET, buffer[offset + 4 : offset + 8])
        port = _windows_port(buffer, offset + 8, where)
        pid, = struct.unpack_from("<I", buffer, offset + 20)
        result.append(ListeningSocket("tcp", address, port, pid))
    return result


def parse_windows_tcp6_table(buffer: bytes) -> List[ListeningSocket]:
    result = []
    for offset, where in _windows_rows(buffer, _TCP6_ROW, "tcp6"):
        state, pid = struct.unpack_from("<II", buffer, offset + 48)
        if state != _MIB_TCP_STATE_LISTEN:
            raise SocketTableParseError(f"{where}: not a listening row")
        address = socket.inet_ntop(socket.AF_INET6, buffer[offset : offset + 16])
        port = _windows_port(buffer, offset + 20, where)
        result.append(ListeningSocket("tcp", address, port, pid))
    return result


def parse_windows_udp4_table(buffer: bytes) -> List[ListeningSocket]:
    result = []
    for offset, where in _windows_rows(buffer, _UDP4_ROW, "udp4"):
        address = socket.inet_ntop(socket.AF_INET, buffer[offset : offset + 4])
        port = _windows_port(buffer, offset + 4, where)
        pid, = struct.unpack_from("<I", buffer, offset + 8)
        result.append(ListeningSocket("udp", address, port, pid))
    return result


def parse_windows_udp6_table(buffer: bytes) -> List[ListeningSocket]:
    result = []
    for offset, where in _windows_rows(buffer, _UDP6_ROW, "udp6"):
        address = socket.inet_ntop(socket.AF_INET6, buffer[offset : offset + 16])
        port = _windows_port(buffer, offset + 20, where)
        pid, = struct.unpack_from("<I", buffer, offset + 24)
        result.append(ListeningSocket("udp", address, port, pid))
    return result


_WINDOWS_TABLES = (
    ("tcp", _AF_INET, parse_windows_tcp4_table),
    ("tcp", _AF_INET6, parse_windows_tcp6_table),
    ("udp", _AF_INET, parse_windows_udp4_table),
    ("udp", _AF_INET6, parse_windows_udp6_table),
)


def _fetch_windows_table(protocol: str, family: int) -> bytes:  # pragma: no cover - needs Windows APIs
    import ctypes
    from ctypes import wintypes

    iphlpapi = ctypes.WinDLL("iphlpapi")
    if protocol == "tcp":
        function, table_class = iphlpapi.GetExtendedTcpTable, _TCP_TABLE_OWNER_PID_LISTENER
    else:
        function, table_class = iphlpapi.GetExtendedUdpTable, _UDP_TABLE_OWNER_PID
    function.restype = wintypes.DWORD
    function.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL, wintypes.ULONG, ctypes.c_int, wintypes.ULONG
    ]
    size = wintypes.DWORD(0)
    for _ in range(_MAX_TABLE_ATTEMPTS):
        if size.value > MAX_TABLE_BYTES:
            raise SocketTableParseError(f"{protocol} table exceeds {MAX_TABLE_BYTES} bytes")
        buffer = ctypes.create_string_buffer(max(size.value, 4))
        status = function(buffer, ctypes.byref(size), False, family, table_class, 0)
        if status == _NO_ERROR:
            return buffer.raw[: size.value]
        if status != _ERROR_INSUFFICIENT_BUFFER:
            raise SocketTableParseError(f"{protocol} table query failed (status {status})")
    raise SocketTableParseError(f"{protocol} table kept growing; gave up after {_MAX_TABLE_ATTEMPTS} attempts")


def _windows_process_name(pid: int) -> Optional[str]:  # pragma: no cover - needs Windows APIs
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)
    ]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return None  # system process, or another user's process
    try:
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return None
        return buffer.value  # full image path; the reader keeps only the base name
    finally:
        kernel32.CloseHandle(handle)


class WindowsSocketReader:
    """Reads the four owner-PID socket tables. The table fetch and the
    process image lookup (which may return a full path) are injectable for
    tests; only the base name is kept."""

    def __init__(
        self,
        *,
        fetch_table: Callable[[str, int], bytes] = _fetch_windows_table,
        process_name: Callable[[int], Optional[str]] = _windows_process_name,
    ) -> None:
        self._fetch_table = fetch_table
        self._process_name = process_name

    def read(self) -> List[ListeningSocket]:
        sockets: List[ListeningSocket] = []
        for protocol, family, parse in _WINDOWS_TABLES:
            buffer = self._fetch_table(protocol, family)
            if len(buffer) > MAX_TABLE_BYTES:
                raise SocketTableParseError(f"{protocol} table exceeds {MAX_TABLE_BYTES} bytes")
            sockets.extend(parse(buffer))
        names: Dict[int, Optional[str]] = {}
        result = []
        for sock in sockets:
            if sock.pid not in names:
                try:
                    image = self._process_name(sock.pid)
                except OSError:
                    image = None
                # Only the executable's base name leaves this reader.
                names[sock.pid] = _clean_process_name(ntpath.basename(image)) if isinstance(image, str) else None
            result.append(ListeningSocket(sock.protocol, sock.local_address, sock.port, sock.pid, names[sock.pid]))
        return result


# =============================================================================
# Handler
# =============================================================================


def _default_reader(platform: str):
    if platform.startswith("linux"):
        return LinuxSocketReader()
    if platform == "win32":
        return WindowsSocketReader()
    raise UnsupportedPlatformError(f"list_listening_ports is not supported on platform {platform!r}")


def build_output(sockets: Iterable[ListeningSocket]) -> Dict[str, Any]:
    """Normalized, de-duplicated, sorted output; enforces ``MAX_OUTPUT_BYTES``."""
    entries = set()
    for sock in sockets:
        if not isinstance(sock, ListeningSocket) or sock.protocol not in _PROTOCOLS:
            raise SocketTableParseError("reader returned an invalid socket record")
        _check_port(sock.port, "reader")
        entries.add((sock.protocol, sock.port, sock.local_address, sock.pid, _clean_process_name(sock.process)))
    ports = []
    for protocol, port, address, pid, process in sorted(entries, key=lambda e: (e[0], e[1], e[2], e[3] if e[3] is not None else -1, e[4] or "")):
        entry: Dict[str, Any] = {"protocol": protocol, "port": port, "local_address": address}
        if pid is not None:
            entry["pid"] = pid
        if process is not None:
            entry["process"] = process
        ports.append(entry)
    output = {"ports": ports}
    size = _canonical_size(output)
    if size > MAX_OUTPUT_BYTES:
        raise OutputTooLargeError(f"output is {size} bytes; the limit is {MAX_OUTPUT_BYTES} (not truncated)")
    return output


class ListeningPortsHandler:
    """``CapabilityHandler`` for ``list_listening_ports``. ``reader`` (an
    object with ``read() -> list[ListeningSocket]``) and ``platform`` are
    injectable for tests; by default the reader matches ``sys.platform``."""

    supported_target_types = _SUPPORTED_TARGET_TYPES

    def __init__(self, reader: Optional[Any] = None, *, platform: Optional[str] = None) -> None:
        self._reader = reader
        self._platform = platform if platform is not None else sys.platform

    def run(self, target: Target, parameters: Mapping[str, Any]) -> Mapping[str, Any]:
        if parameters:
            raise ValueError("list_listening_ports takes no parameters")
        reader = self._reader if self._reader is not None else _default_reader(self._platform)
        return build_output(reader.read())


__all__ = [
    "CAPABILITY_ID",
    "MAX_OUTPUT_BYTES",
    "MAX_PROCESS_NAME_LENGTH",
    "ListeningPortsError",
    "ListeningPortsHandler",
    "ListeningSocket",
    "LinuxSocketReader",
    "OutputTooLargeError",
    "SocketTableParseError",
    "UnsupportedPlatformError",
    "WindowsSocketReader",
    "build_output",
    "parse_proc_net_table",
    "parse_windows_tcp4_table",
    "parse_windows_tcp6_table",
    "parse_windows_udp4_table",
    "parse_windows_udp6_table",
]
