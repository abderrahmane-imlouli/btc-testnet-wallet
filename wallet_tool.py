import argparse, hashlib, os, json
import base58
import qrcode
from ecdsa import SigningKey, SECP256k1

# -----------------------------
# HASH FUNCTIONS
# -----------------------------
def sha256(b): return hashlib.sha256(b).digest()

def ripemd160(b):
    h = hashlib.new("ripemd160")
    h.update(b)
    return h.digest()

# -----------------------------
# PUBLIC KEY
# -----------------------------
def privkey_to_pubkey(priv, compressed=True):
    sk = SigningKey.from_string(priv, curve=SECP256k1)
    vk = sk.verifying_key

    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()

    if compressed:
        return (b"\x02" if y % 2 == 0 else b"\x03") + x.to_bytes(32, "big")
    else:
        return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")

# -----------------------------
# LEGACY ADDRESS (P2PKH)
# -----------------------------
def pubkey_to_legacy(pubkey):
    h = ripemd160(sha256(pubkey))
    # vh = b"\x00" + h
    vh = b"\x6f" + h
    chk = sha256(sha256(vh))[:4]
    return base58.b58encode(vh + chk).decode()

# -----------------------------
# SEGWIT (bc1) - BECH32
# -----------------------------
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def create_checksum(hrp, data):
    values = hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0,0,0,0,0,0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data):
    combined = data + create_checksum(hrp, data)
    return hrp + "1" + "".join([CHARSET[d] for d in combined])

def convert_bits(data, from_bits, to_bits):
    acc = 0
    bits = 0
    result = []
    maxv = (1 << to_bits) - 1

    for value in data:
        acc = (acc << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            result.append((acc >> bits) & maxv)

    if bits:
        result.append((acc << (to_bits - bits)) & maxv)

    return result

def pubkey_to_segwit(pubkey):
    h = ripemd160(sha256(pubkey))
    data = [0] + convert_bits(h, 8, 5)
    return bech32_encode("tb", data)

# -----------------------------
# WIF
# -----------------------------
def priv_to_wif(priv):
    # extended = b"\x80" + priv
    extended = b"\xef" + priv + b"\x01"
    chk = sha256(sha256(extended))[:4]
    return base58.b58encode(extended + chk).decode()

# -----------------------------
# QR
# -----------------------------
def make_qr(text, out):
    qrcode.make(text).save(out)

# -----------------------------
# -----------------------------
# validate segwit address (BIP173 / BIP350)
# -----------------------------
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp, data):
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1


def bech32_decode(bech):
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1:
        raise ValueError("Invalid Bech32 format")

    hrp = bech[:pos]

    data = [CHARSET.index(c) for c in bech[pos + 1:]]

    if not bech32_verify_checksum(hrp, data):
        raise ValueError("Invalid checksum")

    return hrp, data[:-6]

def validate_segwit_address(addr):
    try:
        hrp, data = bech32_decode(addr)

        # 1. check HRP (testnet only)
        if hrp != "tb":
            return False

        # 2. witness version
        witver = data[0]

        # 3. program (convert 5-bit -> 8-bit)
        prog = bytes(convertbits(data[1:], 5, 8, False))

        # 4. rules (BIP173 / BIP350)
        if witver < 0 or witver > 16:
            return False

        if len(prog) < 2 or len(prog) > 40:
            return False

        # only support v0 (P2WPKH / P2WSH)
        if witver == 0 and len(prog) not in (20, 32):
            return False

        return True

    except Exception:
        return False
    
def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1

    for value in data:
        acc = (acc << frombits) | value
        bits += frombits

        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)

    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)

    return ret
# -----------------------------
# VALIDATE (LEGACY + SEGWIT)
# -----------------------------
def validate_address(addr):
    try:
        if addr.startswith("1") or addr.startswith("m") or addr.startswith("n"):
            raw = base58.b58decode(addr)
            body, chk = raw[:-4], raw[-4:]
            return sha256(sha256(body))[:4] == chk

        elif addr.startswith("tb1") or addr.startswith("bc1"):
            return validate_segwit_address(addr)

        else:
            return False
    except:
        return False

# -----------------------------
# GENERATE WALLET
# -----------------------------
def generate_wallet():
    priv = os.urandom(32)
    pub = privkey_to_pubkey(priv)

    wallet = {
        "private_key_hex": priv.hex(),
        "wif": priv_to_wif(priv),
        "public_key": pub.hex(),
        "legacy_address": pubkey_to_legacy(pub),
        "segwit_address": pubkey_to_segwit(pub)
    }

    with open("wallet.json", "w") as f:
        json.dump(wallet, f, indent=4)

    return wallet

# -----------------------------
# CLI
# -----------------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("gen")

    v = sub.add_parser("validate")
    v.add_argument("address")

    q = sub.add_parser("qr")
    q.add_argument("text")
    q.add_argument("--out", default="qr.png")

    args = ap.parse_args()

    if args.cmd == "gen":
        w = generate_wallet()
        print("\n=== WALLET (DUAL SUPPORT) ===")
        for k, v in w.items():
            print(f"{k}: {v}")

    elif args.cmd == "validate":
        print("VALID" if validate_address(args.address) else "INVALID")

    elif args.cmd == "qr":
        make_qr(args.text, args.out)
        print("QR saved:", args.out)