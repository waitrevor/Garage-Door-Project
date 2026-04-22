#!/usr/bin/env python3
"""
Security+ 2.0 (.sub) Flipper Zero file decoder
Returns: PK1, PK2, Serial Number (Sn), Count (Cnt), Button (Btn)
"""

import sys
import re
from pathlib import Path


# ---------------------------------------------------------------------------
# Step 1 – Parse the RAW file and collect both RAW_Data lines
# ---------------------------------------------------------------------------
def parse_raw_file(path: str) -> list[list[int]]:
    raw_data_lines = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("RAW_Data:"):
                numbers = list(map(int, re.findall(r"-?\d+", line.split(":", 1)[1])))
                raw_data_lines.append(numbers)
    return raw_data_lines  # Only first two are needed (one full transmission)


# ---------------------------------------------------------------------------
# Step 2 – Convert OOK pulse/gap sequence → bitstream
#   250  = 1,  500  = 11
#  -250  = 0, -500  = 00
# ---------------------------------------------------------------------------
def raw_to_bits(raw: list[int]) -> str:
    bits = ""
    for val in raw:
        abs_val = abs(val)
        if abs_val <= 300:          # ~250 µs
            symbol = "1" if val > 0 else "0"
        elif abs_val <= 600:        # ~500 µs
            symbol = "11" if val > 0 else "00"
        else:
            symbol = ""             # long gap / silence – skip
        bits += symbol
    return bits


# ---------------------------------------------------------------------------
# Step 3 – Decode Manchester-like encoding: pairs → value bit
#   10 → 0,  01 → 1
# ---------------------------------------------------------------------------
def bits_to_manchester(bits: str) -> str:
    out = ""
    for i in range(0, len(bits) - 1, 2):
        pair = bits[i:i+2]
        if pair == "10":
            out += "0"
        elif pair == "01":
            out += "1"
        # elif pair == "11":
        #     out += "1"
        # elif pair == "00":
        #     out += "0"
        # invalid pairs are skipped (shouldn't appear in clean signal)
    return out


# ---------------------------------------------------------------------------
# Step 4 – Extract the 62 useful data bits (after the 16-bit preamble of 0s)
#   The preamble is 16 × '0' bits; data follows immediately.
# ---------------------------------------------------------------------------
def extract_data_bits(manchester: str) -> str:
    if len(manchester) < 46:
        raise ValueError(f"Bitstream too short: {len(manchester)} bits")
    return manchester[0:46]


# ---------------------------------------------------------------------------
# Steps 5-9 – Parse one 46-bit data word into p0, p1, p2, invert, order
#
#  Bit layout (MSB→LSB within the 46-bit word, 0-indexed from left):
#   [0..3]   order   (bits 3..0)
#   [4..7]   invert  (bits 3..0)
#   [8..17]  p2      (bits 9..0)
#   [18..27] p1      (bits 9..0)
#   [28..37] p0      (bits 9..0)
#   [38..45] padding/fixed header
#
#  NOTE: In the document the fields are shown right-to-left, so bit 0 of
#  each field is at the *rightmost* position of its slice.
# ---------------------------------------------------------------------------
def parse_packet_fields(data46: str):
    # Read fields from the 46-bit string (index 0 = leftmost = MSB)
    order_bits  = data46[0:4]    # 4 bits
    invert_bits = data46[4:8]    # 4 bits
    p2_bits     = data46[8:18]   # 10 bits
    p1_bits     = data46[18:28]  # 10 bits
    p0_bits     = data46[28:38]  # 10 bits

    order  = int(order_bits,  2)
    invert = int(invert_bits, 2)
    p2     = int(p2_bits,     2)
    p1     = int(p1_bits,     2)
    p0     = int(p0_bits,     2)

    return p0, p1, p2, invert, order


# ---------------------------------------------------------------------------
# Step 10 – Apply invert method  (subghz_protocol_secplus_v2_mix_invet)
#   Mask is a 3-bit value: bit0→invert p0, bit1→invert p1, bit2→invert p2
#   The 10-bit invert mask for each is 0x3FF (all bits flipped).
# ---------------------------------------------------------------------------
MASK10 = 0x3FF  # 10-bit all-ones mask

def apply_invert(p0: int, p1: int, p2: int, invert: int):
    if invert & 0x1:
        p0 ^= MASK10
    if invert & 0x2:
        p1 ^= MASK10
    if invert & 0x4:
        p2 ^= MASK10
    return p0, p1, p2


# ---------------------------------------------------------------------------
# Step 11 – Apply order method  (subghz_protocol_secplus_v2_mix_order_decode)
#   Encodes which two of the three values were swapped before transmission.
#   order nibble maps to the swap that was applied; we undo it.
# ---------------------------------------------------------------------------
def apply_order(p0: int, p1: int, p2: int, order: int):
    # Order nibble encodes (upper2 bits → first swap, lower2 bits → second swap)
    swap1 = (order >> 2) & 0x3
    swap2 =  order       & 0x3

    def do_swap(a, b, c, which):
        if   which == 0: return b, a, c   # swap p0,p1
        elif which == 1: return c, b, a   # swap p0,p2
        elif which == 2: return a, c, b   # swap p1,p2
        else:            return a, b, c   # no swap

    # Undo in reverse order
    p0, p1, p2 = do_swap(p0, p1, p2, swap2)
    p0, p1, p2 = do_swap(p0, p1, p2, swap1)
    return p0, p1, p2


# ---------------------------------------------------------------------------
# Steps 12-14 – Convert p2 and the invert/order nibbles to base-3 rolling digits
#   Each base-3 digit is extracted as pairs of bits from the value.
#   p2 contributes roll[8..4], invert/order contribute roll[3..0].
# ---------------------------------------------------------------------------
def to_base3_pair(val: int, bit_pos: int) -> int:
    """Extract a base-3 digit from bits [bit_pos+1 : bit_pos] of val."""
    return (val >> bit_pos) & 0x3   # value 0..3 (but valid base3 = 0,1,2)

def extract_rolling_digits(p2: int, invert: int, order: int) -> list[int]:
    # roll[8..4] from p2 (bits 9..0, pairs: 9:8, 7:6, 5:4, 3:2, 1:0)
    roll = []
    for bit in (8, 6, 4, 2, 0):
        roll.append(to_base3_pair(p2, bit))
    # roll[3..0] from invert[3:2], invert[1:0], order[3:2], order[1:0]
    roll.append(to_base3_pair(invert, 2))
    roll.append(to_base3_pair(invert, 0))
    roll.append(to_base3_pair(order,  2))
    roll.append(to_base3_pair(order,  0))
    return roll   # 9 digits: indices 8..0 in the list


# ---------------------------------------------------------------------------
# Step 15 – fixed1 / fixed2
# ---------------------------------------------------------------------------
def compute_fixed(p0: int, p1: int) -> int:
    return p0 * 1024 + p1


# ---------------------------------------------------------------------------
# Steps 16-20 – Combine rolling digits from both packets and decode count
#   Interleave: (rH2[8], rH1[8], rH2[7], rH1[7], … rH2[0], rH1[0])
#   That 18-digit base-3 number is converted to decimal, then bit-reversed
#   to get the 28-bit Count.
# ---------------------------------------------------------------------------
def interleave_rolling(rH1: list[int], rH2: list[int]) -> list[int]:
    result = []
    for i in range(8, -1, -1):
        result.append(rH2[8 - i])
        result.append(rH1[8 - i])
    return result   # 18 base-3 digits


def base3_to_int(digits: list[int]) -> int:
    val = 0
    for d in digits:
        val = val * 3 + d
    return val


def reverse_bits(n: int, width: int) -> int:
    result = 0
    for _ in range(width):
        result = (result << 1) | (n & 1)
        n >>= 1
    return result


# ---------------------------------------------------------------------------
# Steps 21-25 – Extract Button and Serial Number from fixed values
#   Btn  = fixed1[15:12]  (bits 15 down to 12 → 4 bits)
#   Sn   = fixed1[11:0] concatenated with fixed2[15:0]  (28 bits total)
# ---------------------------------------------------------------------------
def decode_btn_sn(fixed1: int, fixed2: int):
    btn = (fixed1 >> 12) & 0xF
    sn_hi = fixed1 & 0xFFF          # bits 11..0 of fixed1
    sn_lo = fixed2 & 0xFFFF         # bits 15..0 of fixed2
    sn = (sn_hi << 16) | sn_lo
    return btn, sn


# ---------------------------------------------------------------------------
# Top-level decode function
# ---------------------------------------------------------------------------
def decode_secplus_v2(filepath: str) -> dict:
    # --- Parse file ---
    raw_lines = parse_raw_file(filepath)

    packets = []
    for raw in raw_lines:
        bits       = raw_to_bits(raw)
        print('bits', bits)
        manchester = bits_to_manchester(bits)
        print('manchester', manchester)
        data46     = extract_data_bits(manchester)
        packets.append(data46)

    data_pk1, data_pk2 = packets[0], packets[1]

    # --- Decode packet 1 ---
    p0_1, p1_1, p2_1, inv1, ord1 = parse_packet_fields(data_pk1)
    p0_1, p1_1, p2_1 = apply_invert(p0_1, p1_1, p2_1, inv1)
    p0_1, p1_1, p2_1 = apply_order(p0_1, p1_1, p2_1, ord1)
    rH1   = extract_rolling_digits(p2_1, inv1, ord1)
    fixed1 = compute_fixed(p0_1, p1_1)

    # --- Decode packet 2 ---
    p0_2, p1_2, p2_2, inv2, ord2 = parse_packet_fields(data_pk2)
    p0_2, p1_2, p2_2 = apply_invert(p0_2, p1_2, p2_2, inv2)
    p0_2, p1_2, p2_2 = apply_order(p0_2, p1_2, p2_2, ord2)
    rH2    = extract_rolling_digits(p2_2, inv2, ord2)
    fixed2 = compute_fixed(p0_2, p1_2)

    # --- Reconstruct PK hex strings (before invert/order) for display ---
    pk1_hex = f"3C{fixed1:04X}{fixed2:04X}"   # approximate; shown as parsed
    pk2_hex = f"3D{fixed2:04X}{fixed1:04X}"

    # --- Combine rolling and compute Count ---
    combined = interleave_rolling(rH1, rH2)
    roll_int  = base3_to_int(combined)
    count     = reverse_bits(roll_int, 28)

    # --- Button and Serial Number ---
    btn, sn = decode_btn_sn(fixed1, fixed2)

    return {
        "PK1"   : data_pk1,
        "PK2"   : data_pk2,
        "fixed1": fixed1,
        "fixed2": fixed2,
        "Count" : count,
        "Button": btn,
        "Sn"    : sn,
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python decoder.py <path_to_.sub_file>")
        sys.exit(1)

    path = sys.argv[1]
    if not Path(path).exists():
        print(f"File not found: {path}")
        sys.exit(1)

    result = decode_secplus_v2(path)
    # print(result)

    print("\n=== Security+ 2.0 Decode Results ===")
    print(f"  PK1 (46-bit data) : {result['PK1']} ({hex(int(result['PK1'], 2))})")
    print(f"  PK2 (46-bit data) : {result['PK2']} ({hex(int(result['PK2'], 2))})")
    print(f"  fixed1            : {result['fixed1']} (0x{result['fixed1']:04X})")
    print(f"  fixed2            : {result['fixed2']} (0x{result['fixed2']:04X})")
    print(f"  Count (Cnt)       : {result['Count']} (0x{result['Count']:07X})")
    print(f"  Button (Btn)      : {result['Button']} (0x{result['Button']:X})")
    print(f"  Serial Number(Sn) : {result['Sn']} (0x{result['Sn']:07X})")


if __name__ == "__main__":
    main()