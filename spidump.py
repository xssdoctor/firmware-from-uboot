#!/usr/bin/env python3
"""Read firmware from SPI flash through an authorized U-Boot serial console.

The script supports two read-only U-Boot transports:

* ``sf``: standard U-Boot ``sf probe`` / ``sf read`` plus ``md.b``
* ``spi``: vendor consoles whose ``spi read <offset> <length>`` prints bytes

It autodetects the serial port (when there is only one plausible adapter),
prompt, transport, flash size, and RAM load address. Every value can still be
overridden for unusual boards.

Examples:
  uv run --with pyserial spidump.py --out full_flash.bin
  uv run --with pyserial spidump.py --port /dev/cu.usbserial-ABC \
      --out full_flash.bin
  uv run --with pyserial spidump.py --backend spi --end 0x1000000 \
      --start 0x400000 --out firmware.bin

Existing output is resumed only after bytes at its beginning and end are read
back from the target and compared. No flash write/erase/save command is used.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import time
from pathlib import Path
from typing import Protocol

import serial
from serial.tools import list_ports

ANSI_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
PROMPT_END_RE = re.compile(r"(?:=>|[#>$])\s*$")
MISSING_COMMAND_RE = re.compile(
    r"unknown command|command not found|not recognized|not supported", re.IGNORECASE
)
COMMAND_ERROR_RE = re.compile(
    r"(?:^|\b)(?:error|failed|failure|invalid argument|no spi flash)(?:\b|:)",
    re.IGNORECASE,
)
UNIT_FACTORS = {
    "b": 1,
    "byte": 1,
    "bytes": 1,
    "kib": 1024,
    "kb": 1000,
    "mib": 1024**2,
    "mb": 1000**2,
    "gib": 1024**3,
    "gb": 1000**3,
    "tib": 1024**4,
    "tb": 1000**4,
}


class DumpError(RuntimeError):
    """A recoverable target, protocol, or dump validation error."""


def parse_int(value: str) -> int:
    """Parse a CLI integer, accepting decimal or a 0x-prefixed value."""
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value!r}") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must not be negative")
    return parsed


def clean_text(raw: bytes | str) -> str:
    text = raw.decode("ascii", "replace") if isinstance(raw, bytes) else raw
    return ANSI_RE.sub("", text).replace("\r\n", "\n").replace("\r", "\n")


def strip_command_echo(text: str, command: str) -> str:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == command.strip():
            del lines[index]
            break
        if line.strip():
            break
    return "\n".join(lines)


def detect_prompt(raw: bytes) -> bytes:
    """Return the final prompt-looking line from a quiet console response."""
    lines = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n")
    for line in reversed(lines):
        if not line.strip():
            continue
        visible = clean_text(line)
        if len(visible) <= 160 and PROMPT_END_RE.search(visible):
            return line
        break
    tail = clean_text(raw[-300:]).strip()
    raise DumpError(f"could not identify a U-Boot prompt; console tail: {tail!r}")


def _quantity(number: str, unit: str) -> int:
    return int(float(number) * UNIT_FACTORS[unit.lower()])


def parse_flash_size(text: str) -> int | None:
    """Extract total flash size without confusing it with page/erase sizes."""
    unit = r"(?:bytes?|[KMGT]i?B|B)"
    patterns = (
        rf"\btotal\s+(\d+(?:\.\d+)?)\s*({unit})\b",
        rf"\b(?:spi\s+)?flash\s+size\s*(?:is|=|:)\s*(\d+(?:\.\d+)?)\s*({unit})\b",
        rf"\bsize\s*(?:is|=|:)\s*(\d+(?:\.\d+)?)\s*({unit})\b",
    )
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return _quantity(match.group(1), match.group(2))

    # Common vendor form: ``find flash: W25Q128, size: 16777216``.
    match = re.search(
        rf"\bflash\b[^\n]{{0,120}}?,\s*size\s*(?:is|=|:)?\s*"
        rf"(0x[0-9a-f]+|\d+)\s*({unit})?\b",
        text,
        re.IGNORECASE,
    )
    if match:
        number, matched_unit = match.groups()
        if matched_unit:
            return _quantity(number, matched_unit)
        return int(number, 16 if number.lower().startswith("0x") else 10)

    # Older bdinfo prints hexadecimal values even when it omits the 0x prefix.
    match = re.search(r"\bflash\s*size\s*=\s*(?:0x)?([0-9a-f]+)\b", text, re.IGNORECASE)
    if not match:
        match = re.search(
            r"\bflashsize\s*=\s*(?:0x)?([0-9a-f]+)\b", text, re.IGNORECASE
        )
    return int(match.group(1), 16) if match else None


def parse_env_address(text: str) -> int | None:
    for name in ("loadaddr", "kernel_addr_r", "ramdisk_addr_r", "scriptaddr"):
        match = re.search(
            rf"(?m)^\s*{re.escape(name)}\s*=\s*(?:0x)?([0-9a-f]+)\s*$",
            text,
            re.IGNORECASE,
        )
        if match:
            return int(match.group(1), 16)
    return None


def parse_base_address(text: str) -> int:
    match = re.search(r"\bbase\s+address\s*:\s*(?:0x)?([0-9a-f]+)", text, re.IGNORECASE)
    return int(match.group(1), 16) if match else 0


def parse_direct_spi_dump(text: str, expected_length: int) -> bytes:
    """Parse the byte stream emitted by Ralink-style ``spi read`` commands."""
    match = re.search(
        r"read\s+len\s*:\s*(0x[0-9a-f]+|\d+)\s*\n(.*)", text, re.IGNORECASE | re.DOTALL
    )
    if not match:
        raise DumpError(f"unrecognized direct SPI response: {text[-300:]!r}")
    count_text = match.group(1)
    reported = int(count_text, 16 if count_text.lower().startswith("0x") else 10)
    tokens = match.group(2).split()
    if reported != expected_length:
        raise DumpError(f"target reported {reported} bytes, expected {expected_length}")
    if len(tokens) != expected_length or not all(
        re.fullmatch(r"[0-9a-fA-F]{1,2}", token) for token in tokens
    ):
        raise DumpError(
            f"direct SPI response contained {len(tokens)} byte tokens, "
            f"expected {expected_length}"
        )
    return bytes(int(token, 16) for token in tokens)


def parse_md_dump(text: str, expected_address: int, expected_length: int) -> bytes:
    """Parse standard U-Boot ``md.b`` output and validate address continuity."""
    data = bytearray()
    next_address = expected_address
    saw_line = False
    for line in text.splitlines():
        match = re.match(r"^\s*([0-9a-fA-F]{4,16}):\s+(.*)$", line)
        if not match:
            continue
        address = int(match.group(1), 16)
        hex_column = re.split(r"\s{2,}", match.group(2), maxsplit=1)[0]
        tokens = hex_column.split()
        if not tokens or not all(
            re.fullmatch(r"[0-9a-fA-F]{2}", item) for item in tokens
        ):
            continue
        if address != next_address:
            raise DumpError(
                f"non-contiguous md.b output: got {address:#x}, expected {next_address:#x}"
            )
        saw_line = True
        data.extend(int(item, 16) for item in tokens)
        next_address += len(tokens)

    if not saw_line or len(data) != expected_length:
        raise DumpError(f"md.b produced {len(data)} bytes, expected {expected_length}")
    return bytes(data)


def output_has_error(text: str) -> bool:
    return bool(MISSING_COMMAND_RE.search(text) or COMMAND_ERROR_RE.search(text))


def command_timeout(base_timeout: float, baud: int, expected_bytes: int) -> float:
    # Hex dumps use roughly 4-6 serial characters per byte. Ten serial bits
    # per character and a 2x margin handles slow console implementations.
    return max(base_timeout, 5.0 + (expected_bytes * 120.0 / max(baud, 1)))


class UBootConsole:
    def __init__(
        self,
        connection: serial.Serial,
        *,
        prompt: bytes | None,
        timeout: float,
    ) -> None:
        self.connection = connection
        self.prompt = prompt
        self.timeout = timeout

    def _write(self, value: bytes) -> None:
        self.connection.write(value)
        self.connection.flush()

    def _read_to_prompt(self, timeout: float) -> bytes:
        if self.prompt is None:
            raise DumpError("console prompt has not been detected")
        data = bytearray()
        deadline = time.monotonic() + timeout
        while True:
            prompt_start = len(data) - len(self.prompt)
            at_line_start = prompt_start == 0 or (
                prompt_start > 0 and data[prompt_start - 1] in (10, 13)
            )
            if data.endswith(self.prompt) and at_line_start:
                break
            chunk = self.connection.read(4096)
            if chunk:
                data.extend(chunk)
                continue
            if time.monotonic() >= deadline:
                tail = clean_text(bytes(data[-300:]))
                raise TimeoutError(
                    f"no prompt after {timeout:.1f}s; console tail: {tail!r}"
                )
        return bytes(data[: -len(self.prompt)])

    def _read_until_quiet(self, timeout: float, idle: float = 0.4) -> bytes:
        data = bytearray()
        deadline = time.monotonic() + timeout
        last_data: float | None = None
        while time.monotonic() < deadline:
            chunk = self.connection.read(4096)
            if chunk:
                data.extend(chunk)
                last_data = time.monotonic()
            elif (
                data and last_data is not None and time.monotonic() - last_data >= idle
            ):
                return bytes(data)
        tail = clean_text(bytes(data[-300:]))
        raise TimeoutError(
            f"console did not become idle after {timeout:.1f}s; tail: {tail!r}"
        )

    def sync(self) -> None:
        self.connection.reset_input_buffer()
        self._write(b"\r")
        if self.prompt is None:
            raw = self._read_until_quiet(self.timeout)
            self.prompt = detect_prompt(raw)
        else:
            self._read_to_prompt(self.timeout)

    def command(self, command: str, *, timeout: float | None = None) -> str:
        self.connection.reset_input_buffer()
        self._write(command.encode("ascii") + b"\r")
        raw = self._read_to_prompt(timeout or self.timeout)
        return strip_command_echo(clean_text(raw), command)


class FlashReader(Protocol):
    name: str
    detected_size: int | None

    def read(self, offset: int, length: int) -> bytes: ...


class StandardSfReader:
    name = "sf"

    def __init__(
        self,
        console: UBootConsole,
        *,
        ram_address: int,
        base_address: int,
        detected_size: int | None,
        baud: int,
        timeout: float,
    ) -> None:
        if ram_address < base_address:
            raise DumpError(
                f"RAM address {ram_address:#x} is below U-Boot md base {base_address:#x}"
            )
        self.console = console
        self.ram_address = ram_address
        self.md_address = ram_address - base_address
        self.detected_size = detected_size
        self.baud = baud
        self.timeout = timeout

    def read(self, offset: int, length: int) -> bytes:
        timeout = command_timeout(self.timeout, self.baud, length)
        response = self.console.command(
            f"sf read {self.ram_address:x} {offset:x} {length:x}", timeout=timeout
        )
        if output_has_error(response) or not re.search(
            r"\b(?:read|done|ok)\b", response, re.IGNORECASE
        ):
            raise DumpError(f"sf read failed at {offset:#x}: {response[-300:]!r}")
        response = self.console.command(
            f"md.b {self.md_address:x} {length:x}", timeout=timeout
        )
        return parse_md_dump(response, self.ram_address, length)


class DirectSpiReader:
    name = "spi"

    def __init__(
        self,
        console: UBootConsole,
        *,
        detected_size: int | None,
        baud: int,
        timeout: float,
    ) -> None:
        self.console = console
        self.detected_size = detected_size
        self.baud = baud
        self.timeout = timeout

    def read(self, offset: int, length: int) -> bytes:
        command = f"spi read {offset:x} {length:x}"
        response = self.console.command(
            command, timeout=command_timeout(self.timeout, self.baud, length)
        )
        return parse_direct_spi_dump(response, length)


def discover_ram_address(console: UBootConsole) -> int | None:
    response = console.command(
        "printenv loadaddr kernel_addr_r ramdisk_addr_r scriptaddr"
    )
    return parse_env_address(response)


def discover_direct_size(console: UBootConsole) -> int | None:
    for command in ("spi id", "spi info", "bdinfo"):
        try:
            response = console.command(command)
        except (DumpError, TimeoutError):
            continue
        size = parse_flash_size(response)
        if size:
            return size
    return None


def configure_sf_reader(
    console: UBootConsole,
    *,
    sf_probe_args: str,
    ram_address: int | None,
    baud: int,
    timeout: float,
) -> StandardSfReader:
    help_text = console.command("help sf")
    if MISSING_COMMAND_RE.search(help_text) or not re.search(
        r"\bsf\s+(?:probe|read)\b", help_text, re.IGNORECASE
    ):
        raise DumpError("standard U-Boot sf command is unavailable")

    probe_command = "sf probe" + (
        f" {sf_probe_args.strip()}" if sf_probe_args.strip() else ""
    )
    probe_text = console.command(probe_command, timeout=max(timeout, 20.0))
    if output_has_error(probe_text):
        raise DumpError(f"sf probe failed: {probe_text[-300:]!r}")
    detected_size = parse_flash_size(probe_text)

    selected_ram = (
        ram_address if ram_address is not None else discover_ram_address(console)
    )
    if selected_ram is None:
        raise DumpError(
            "could not discover a U-Boot load address; pass --ram-address explicitly"
        )
    base_address = parse_base_address(console.command("base"))
    return StandardSfReader(
        console,
        ram_address=selected_ram,
        base_address=base_address,
        detected_size=detected_size,
        baud=baud,
        timeout=timeout,
    )


def configure_direct_reader(
    console: UBootConsole, *, baud: int, timeout: float
) -> DirectSpiReader:
    help_text = console.command("help spi")
    if not re.search(r"\bspi\b[\s\S]{0,1000}\bread\b", help_text, re.IGNORECASE):
        # Some old vendor trees only show full usage when the command is bare.
        usage_text = console.command("spi")
        help_text += "\n" + usage_text
    if MISSING_COMMAND_RE.search(help_text) or not re.search(
        r"\bspi\b[\s\S]{0,1000}\bread\b", help_text, re.IGNORECASE
    ):
        raise DumpError("vendor direct-output spi read command is unavailable")
    return DirectSpiReader(
        console,
        detected_size=discover_direct_size(console),
        baud=baud,
        timeout=timeout,
    )


def configure_reader(
    console: UBootConsole,
    *,
    backend: str,
    sf_probe_args: str,
    ram_address: int | None,
    baud: int,
    timeout: float,
) -> FlashReader:
    failures: list[str] = []
    choices = ("sf", "spi") if backend == "auto" else (backend,)
    for choice in choices:
        try:
            if choice == "sf":
                return configure_sf_reader(
                    console,
                    sf_probe_args=sf_probe_args,
                    ram_address=ram_address,
                    baud=baud,
                    timeout=timeout,
                )
            return configure_direct_reader(console, baud=baud, timeout=timeout)
        except (DumpError, TimeoutError) as exc:
            failures.append(f"{choice}: {exc}")
            try:
                console.sync()
            except (DumpError, TimeoutError):
                pass
    raise DumpError("no usable SPI read backend found (" + "; ".join(failures) + ")")


def plausible_serial_ports() -> list:
    ports = list(list_ports.comports())
    likely = [
        port
        for port in ports
        if re.search(r"(?:usb|acm|wch|slab|serial)", port.device, re.IGNORECASE)
        and "bluetooth" not in port.device.lower()
    ]
    return likely or ports


def choose_port(requested: str | None) -> str:
    if requested:
        return requested
    ports = plausible_serial_ports()
    if len(ports) == 1:
        return ports[0].device
    if not ports:
        raise DumpError("no serial ports found; connect an adapter or pass --port")
    choices = ", ".join(
        f"{port.device} ({port.description or 'unknown'})" for port in ports
    )
    raise DumpError(f"multiple serial ports found; pass --port explicitly: {choices}")


def resolve_range(
    *, start: int, end: int | None, size: int | None, detected_size: int | None
) -> tuple[int, int]:
    if end is not None:
        selected_end = end
    elif size is not None:
        selected_end = start + size
    elif detected_size is not None:
        selected_end = detected_size
    else:
        raise DumpError(
            "flash size was not reported by U-Boot; pass --size or --end explicitly"
        )
    if selected_end <= start:
        raise DumpError(f"end address {selected_end:#x} must be above start {start:#x}")
    if detected_size is not None and selected_end > detected_size:
        raise DumpError(
            f"requested end {selected_end:#x} exceeds detected flash size {detected_size:#x}"
        )
    return start, selected_end


def verified_read(
    reader: FlashReader,
    console: UBootConsole,
    offset: int,
    length: int,
    *,
    retries: int,
) -> bytes:
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return reader.read(offset, length)
        except (DumpError, TimeoutError, serial.SerialException) as exc:
            last_error = exc
            if attempt < retries:
                print(
                    f"\n  retry {attempt + 1}/{retries} at {offset:#x}: {exc}",
                    file=sys.stderr,
                )
                try:
                    console.sync()
                except (DumpError, TimeoutError, serial.SerialException):
                    pass
    raise DumpError(f"read failed at {offset:#x}: {last_error}")


def verify_resume(
    path: Path,
    *,
    reader: FlashReader,
    console: UBootConsole,
    start: int,
    retries: int,
) -> int:
    done = path.stat().st_size
    if done == 0:
        return 0
    sample_size = min(256, done)
    samples = [(0, sample_size)]
    tail_position = done - sample_size
    if tail_position:
        samples.append((tail_position, sample_size))
    with path.open("rb") as existing:
        for file_offset, length in samples:
            existing.seek(file_offset)
            local = existing.read(length)
            remote = verified_read(
                reader,
                console,
                start + file_offset,
                length,
                retries=retries,
            )
            if local != remote:
                raise DumpError(
                    f"resume verification failed at flash offset {start + file_offset:#x}; "
                    "the output file does not match this target"
                )
    return done


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def dump_flash(
    *,
    reader: FlashReader,
    console: UBootConsole,
    output: Path,
    start: int,
    end: int,
    chunk_size: int,
    retries: int,
) -> None:
    total = end - start
    existing_size = output.stat().st_size if output.exists() else 0
    if existing_size > total:
        raise DumpError(
            f"existing output is {existing_size:#x} bytes, "
            f"larger than requested range {total:#x}"
        )
    done = (
        verify_resume(
            output, reader=reader, console=console, start=start, retries=retries
        )
        if existing_size
        else 0
    )
    if done == total:
        print(f"already complete: {output}")
        print(f"sha256: {sha256_file(output)}")
        return

    position = start + done
    action = "resuming" if done else "starting"
    print(f"{action} at {position:#x} -> {end:#x} ({total - done:,} bytes remaining)")
    started = time.monotonic()
    initial_position = position
    with output.open("ab") as handle:
        while position < end:
            length = min(chunk_size, end - position)
            data = verified_read(reader, console, position, length, retries=retries)
            handle.write(data)
            handle.flush()
            position += length
            elapsed = time.monotonic() - started
            rate = (position - initial_position) / elapsed if elapsed else 0.0
            eta = (end - position) / rate if rate else 0.0
            print(
                f"\r{position:#010x}  {rate / 1024:6.1f} KiB/s  "
                f"ETA {eta / 60:5.1f} min   ",
                end="",
                flush=True,
            )
    print(f"\ndone: {output}")
    print(f"sha256: {sha256_file(output)}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read SPI flash through an authorized U-Boot serial console."
    )
    parser.add_argument(
        "--port", help="serial device; autodetected when exactly one adapter is present"
    )
    parser.add_argument("--baud", type=parse_int, default=115200)
    parser.add_argument(
        "--backend",
        choices=("auto", "sf", "spi"),
        default="auto",
        help="U-Boot read command family (default: auto)",
    )
    parser.add_argument(
        "--prompt", help="exact prompt override, for example 'MT7628 # '"
    )
    parser.add_argument("--start", type=parse_int, default=0)
    boundary = parser.add_mutually_exclusive_group()
    boundary.add_argument("--end", type=parse_int, help="exclusive flash end offset")
    boundary.add_argument("--size", type=parse_int, help="number of bytes to dump")
    parser.add_argument("--chunk", type=parse_int, default=0x1000)
    parser.add_argument("--out", type=Path)
    parser.add_argument(
        "--ram-address",
        type=parse_int,
        help="RAM scratch address for sf reads (default: U-Boot loadaddr)",
    )
    parser.add_argument(
        "--sf-probe-args",
        default="",
        help="optional bus/chip-select/frequency/mode arguments passed to sf probe",
    )
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--retries",
        type=parse_int,
        default=3,
        help="retries after the initial read attempt (default: 3)",
    )
    parser.add_argument(
        "--probe-only",
        action="store_true",
        help="detect the console and flash without creating an output file",
    )
    parser.add_argument(
        "--list-ports", action="store_true", help="list serial ports and exit"
    )
    return parser


def print_ports() -> None:
    ports = list(list_ports.comports())
    if not ports:
        print("no serial ports found")
        return
    for port in ports:
        print(f"{port.device}\t{port.description or 'unknown'}\t{port.hwid or ''}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.list_ports:
        print_ports()
        return 0
    if not args.probe_only and args.out is None:
        parser.error("--out is required unless --probe-only or --list-ports is used")
    if args.chunk <= 0:
        parser.error("--chunk must be greater than zero")
    if args.baud <= 0:
        parser.error("--baud must be greater than zero")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    try:
        port = choose_port(args.port)
        print(f"serial: {port} @ {args.baud}")
        prompt = args.prompt.encode("ascii") if args.prompt is not None else None
        with serial.Serial(
            port,
            args.baud,
            timeout=0.1,
            write_timeout=max(args.timeout, 1.0),
        ) as connection:
            console = UBootConsole(connection, prompt=prompt, timeout=args.timeout)
            console.sync()
            print(f"prompt: {clean_text(console.prompt or b'')!r}")

            version = console.command("version")
            if not re.search(r"\bU-Boot\b", version, re.IGNORECASE):
                raise DumpError(
                    f"console did not identify as U-Boot; "
                    f"version response: {version[-300:]!r}"
                )
            version_line = next(
                (line.strip() for line in version.splitlines() if "U-Boot" in line),
                version.strip(),
            )
            print(f"target: {version_line}")

            reader = configure_reader(
                console,
                backend=args.backend,
                sf_probe_args=args.sf_probe_args,
                ram_address=args.ram_address,
                baud=args.baud,
                timeout=args.timeout,
            )
            size_description = (
                f"{reader.detected_size:#x} ({reader.detected_size:,} bytes)"
                if reader.detected_size is not None
                else "not reported"
            )
            print(f"backend: {reader.name}")
            print(f"detected flash size: {size_description}")
            if isinstance(reader, StandardSfReader):
                print(f"RAM scratch address: {reader.ram_address:#x}")
            if args.probe_only:
                if (
                    args.end is not None
                    or args.size is not None
                    or reader.detected_size
                ):
                    start, end = resolve_range(
                        start=args.start,
                        end=args.end,
                        size=args.size,
                        detected_size=reader.detected_size,
                    )
                    print(f"range: {start:#x}..{end:#x} ({end - start:,} bytes)")
                else:
                    print("range: unavailable until --size or --end is supplied")
                return 0

            start, end = resolve_range(
                start=args.start,
                end=args.end,
                size=args.size,
                detected_size=reader.detected_size,
            )
            print(f"range: {start:#x}..{end:#x} ({end - start:,} bytes)")

            dump_flash(
                reader=reader,
                console=console,
                output=args.out,
                start=start,
                end=end,
                chunk_size=args.chunk,
                retries=args.retries,
            )
        return 0
    except KeyboardInterrupt:
        print(
            "\ninterrupted; rerun the same command to verify and resume",
            file=sys.stderr,
        )
        return 130
    except (DumpError, TimeoutError, serial.SerialException, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
