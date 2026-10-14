# firmware-from-uboot

Dump SPI NOR firmware through an authorized U-Boot serial console.

The tool automatically discovers the serial adapter when unambiguous, detects
the U-Boot prompt and flash-reading backend, determines the flash size when the
bootloader reports it, and resumes interrupted dumps safely.

It supports:

- Standard U-Boot: `sf probe` → `sf read` → `md.b`
- Vendor/Ralink-style consoles: `spi read <offset> <length>` with hex output

The commands are read-only with respect to flash. The standard `sf` backend
uses a small RAM scratch buffer obtained from U-Boot's `loadaddr` environment.

## Safety and scope

Use this only with devices you own or are explicitly authorized to assess.
Confirm UART voltage, ground, TX/RX wiring, and baud rate before connecting.
Incorrect electrical connections can damage the target or serial adapter.

The current backends target SPI NOR. NAND and eMMC need different handling for
bad blocks, page geometry, partitions, and block-addressed reads; the tool does
not guess those layouts.

## Requirements

- Python 3.10 or newer
- [`uv`](https://docs.astral.sh/uv/)
- A working UART adapter
- An interactive U-Boot prompt

Clone and prepare the project:

```bash
git clone git@github.com:xssdoctor/firmware-from-uboot.git
cd firmware-from-uboot
uv sync
```

## Correct serial handoff

Only one program can own a serial port. Do not run this tool while picocom,
screen, minicom, or another terminal still has the device open.

1. Open picocom:

   ```bash
   picocom --baud 115200 --flow n --noreset /dev/cu.usbserial-DEVICE
   ```

2. Power-cycle or reset the target.
3. Interrupt autoboot and wait for the U-Boot prompt, for example:

   ```text
   MT7628 #
   ```

4. Press Enter once and confirm the prompt returns.
5. Quit picocom without resetting the serial lines: press `Ctrl-A`, then
   `Ctrl-Q`.
6. Do **not** reboot the target. Run the dumper immediately.

If Linux kernel messages are already appearing, the autoboot window was missed.
Power-cycle the target, interrupt autoboot again, and repeat the handoff.

## Quick start

List available ports:

```bash
uv run firmware-from-uboot --list-ports
```

Probe the stopped U-Boot console without creating a dump:

```bash
uv run firmware-from-uboot --probe-only
```

Dump the complete detected SPI flash:

```bash
uv run firmware-from-uboot --out target-full-flash.bin
```

You can also run the source file directly:

```bash
uv run ./spidump.py --out target-full-flash.bin
```

## Overrides for unusual targets

Select the port explicitly:

```bash
uv run firmware-from-uboot \
  --port /dev/cu.usbserial-ABC123 \
  --out target-full-flash.bin
```

Force the legacy direct-output backend and specify a 16 MiB end offset:

```bash
uv run firmware-from-uboot \
  --backend spi \
  --end 0x1000000 \
  --out target-full-flash.bin
```

Dump only a selected range:

```bash
uv run firmware-from-uboot \
  --start 0x400000 \
  --end 0x1000000 \
  --out firmware-region.bin
```

Override the U-Boot RAM scratch address or SPI bus/chip-select arguments:

```bash
uv run firmware-from-uboot \
  --backend sf \
  --ram-address 0x82000000 \
  --sf-probe-args "0:0" \
  --out target-full-flash.bin
```

Run `uv run firmware-from-uboot --help` for every option.

## Resume and integrity behavior

When the output already exists, the tool:

1. Reads samples from the beginning and current end of the target region.
2. Compares them with the existing file.
3. Refuses to resume if they differ.
4. Continues at the first missing byte when they match.
5. Prints the completed file's SHA-256 digest.

This prevents silently appending data from a different device or flash image.

## Troubleshooting

### `Resource busy`

Another process owns the UART. Close the terminal program or identify it with:

```bash
lsof /dev/cu.usbserial-DEVICE
```

### `could not identify a U-Boot prompt`

- Kernel/OpenWrt output means autoboot was not interrupted.
- An empty console can mean the target already booted, the baud rate is wrong,
  or TX/RX/GND is disconnected.
- Stop at the U-Boot prompt before launching the tool.

### Flash size was not reported

Supply the known exclusive end offset or byte count:

```bash
uv run firmware-from-uboot --end 0x1000000 --out target-full-flash.bin
```

### No usable backend was found

Check `help sf` and `help spi` in U-Boot. The necessary flash and memory-display
commands may not have been compiled into that bootloader.

## Development

Run the deterministic parser, backend, prompt, and resume tests:

```bash
uv run python -m unittest -v
```

Run static checks:

```bash
uvx ruff check spidump.py test_spidump.py
uv run python -m py_compile spidump.py test_spidump.py
```
