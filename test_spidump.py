import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import spidump


class ParsingTests(unittest.TestCase):
    def test_detects_common_prompts(self):
        self.assertEqual(spidump.detect_prompt(b"\r\nMT7628 # "), b"MT7628 # ")
        self.assertEqual(spidump.detect_prompt(b"\r\n=> "), b"=> ")

    def test_flash_size_prefers_total_over_erase_size(self):
        output = (
            "SF: Detected w25q128 with page size 256 Bytes, "
            "erase size 64 KiB, total 16 MiB"
        )
        self.assertEqual(spidump.parse_flash_size(output), 16 * 1024 * 1024)

    def test_flash_size_from_old_bdinfo(self):
        self.assertEqual(
            spidump.parse_flash_size("flashstart = 0xbc000000\nflashsize = 0x01000000"),
            0x01000000,
        )

    def test_flash_size_from_vendor_spi_id(self):
        self.assertEqual(
            spidump.parse_flash_size("find flash: W25Q128BV, size: 16777216"),
            16 * 1024 * 1024,
        )

    def test_environment_load_address(self):
        text = "baudrate=115200\nloadaddr=82000000\nkernel_addr_r=84000000\n"
        self.assertEqual(spidump.parse_env_address(text), 0x82000000)

    def test_direct_spi_parser(self):
        text = "read len: 4\n00 a5 0F ff\n"
        self.assertEqual(spidump.parse_direct_spi_dump(text, 4), b"\x00\xa5\x0f\xff")

    def test_md_byte_parser(self):
        text = (
            '82000000: 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff    .."3DUfw........\n'
            "82000010: de ad be ef                                        ....\n"
        )
        expected = bytes.fromhex(
            "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff de ad be ef"
        )
        self.assertEqual(spidump.parse_md_dump(text, 0x82000000, 20), expected)

    def test_md_parser_rejects_address_gap(self):
        text = '82000000: 00 11    ..\n82000003: 22    "\n'
        with self.assertRaises(spidump.DumpError):
            spidump.parse_md_dump(text, 0x82000000, 3)

    def test_resolve_range(self):
        self.assertEqual(
            spidump.resolve_range(
                start=0, end=None, size=None, detected_size=0x1000000
            ),
            (0, 0x1000000),
        )
        self.assertEqual(
            spidump.resolve_range(
                start=0x400000, end=None, size=0x1000, detected_size=None
            ),
            (0x400000, 0x401000),
        )


class FakeReader:
    name = "fake"
    detected_size = None

    def __init__(self, data: bytes):
        self.data = data

    def read(self, offset: int, length: int) -> bytes:
        return self.data[offset : offset + length]


class ResumeTests(unittest.TestCase):
    def test_resume_checks_head_and_tail(self):
        data = bytes(range(256)) * 4
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dump.bin"
            path.write_bytes(data[:700])
            done = spidump.verify_resume(
                path,
                reader=FakeReader(data),
                console=None,
                start=0,
                retries=0,
            )
            self.assertEqual(done, 700)

    def test_resume_rejects_wrong_target(self):
        data = bytes(range(256)) * 4
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dump.bin"
            path.write_bytes(b"X" + data[1:700])
            with self.assertRaises(spidump.DumpError):
                spidump.verify_resume(
                    path,
                    reader=FakeReader(data),
                    console=None,
                    start=0,
                    retries=0,
                )


class FakeConsole:
    def __init__(self, responses):
        self.responses = responses
        self.commands = []

    def command(self, command, **_kwargs):
        self.commands.append(command)
        response = self.responses[command]
        if isinstance(response, list):
            return response.pop(0)
        return response

    def sync(self):
        return None


class BackendTests(unittest.TestCase):
    def test_standard_sf_discovery_and_read(self):
        console = FakeConsole(
            {
                "help sf": "sf probe\nsf read <addr> <offset> <len>",
                "sf probe": (
                    "SF: Detected w25q128 with page size 256 Bytes, "
                    "erase size 64 KiB, total 16 MiB"
                ),
                "printenv loadaddr kernel_addr_r ramdisk_addr_r scriptaddr": (
                    "loadaddr=82000000"
                ),
                "base": "Base Address: 00000000",
                "sf read 82000000 1000 4": "SF: 4 bytes @ 0x1000 Read: OK",
                "md.b 82000000 4": "82000000: de ad be ef    ....",
            }
        )
        reader = spidump.configure_sf_reader(
            console,
            sf_probe_args="",
            ram_address=None,
            baud=115200,
            timeout=10,
        )
        self.assertEqual(reader.detected_size, 16 * 1024 * 1024)
        self.assertEqual(reader.read(0x1000, 4), bytes.fromhex("de ad be ef"))

    def test_direct_spi_discovery_and_read(self):
        console = FakeConsole(
            {
                "help spi": "spi read <offset> <len>",
                "spi id": "SPI flash size: 16 MiB",
                "spi read 2000 4": "read len: 4\n01 23 45 67",
            }
        )
        reader = spidump.configure_direct_reader(console, baud=115200, timeout=10)
        self.assertEqual(reader.detected_size, 16 * 1024 * 1024)
        self.assertEqual(reader.read(0x2000, 4), bytes.fromhex("01 23 45 67"))

    def test_prompt_reader_ignores_prompt_bytes_inside_output(self):
        class FakeSerial:
            def __init__(self):
                self.chunks = [b"82000000: 3d 3e 20    => ", b"data\r\n=> "]

            def read(self, _size):
                return self.chunks.pop(0) if self.chunks else b""

        console = spidump.UBootConsole(FakeSerial(), prompt=b"=> ", timeout=1)
        self.assertEqual(
            console._read_to_prompt(1), b"82000000: 3d 3e 20    => data\r\n"
        )


class CliTests(unittest.TestCase):
    @patch.object(spidump, "print_ports")
    def test_list_ports_does_not_require_output(self, print_ports):
        self.assertEqual(spidump.main(["--list-ports"]), 0)
        print_ports.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
