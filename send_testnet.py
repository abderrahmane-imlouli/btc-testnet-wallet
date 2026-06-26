"""
Bitcoin Testnet Transaction Builder & Broadcaster
---------------------------------------------------
Supports:
  - Legacy P2PKH addresses (m/n...)
  - Native SegWit P2WPKH addresses (tb1...)

Only standard library + ecdsa + base58 + requests are used.
"""

import requests
import hashlib
import struct
import base58
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der_canonize

API = "https://blockstream.info/testnet/api"
SIGHASH_ALL = 1

# ============================================================
# Hash helpers
# ============================================================
def sha256(b): return hashlib.sha256(b).digest()
def hash256(b): return sha256(sha256(b))

def hash160(b):
    h = hashlib.new('ripemd160')
    h.update(sha256(b))
    return h.digest()

def varint(n):
    if n < 0xfd:
        return n.to_bytes(1, 'little')
    if n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    if n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, 'little')
    return b'\xff' + n.to_bytes(8, 'little')

def push_data(data):
    n = len(data)
    if n < 0x4c:
        return bytes([n]) + data
    elif n <= 0xff:
        return b'\x4c' + bytes([n]) + data
    elif n <= 0xffff:
        return b'\x4d' + n.to_bytes(2, 'little') + data
    else:
        return b'\x4e' + n.to_bytes(4, 'little') + data

# ============================================================
# Bech32 (BIP173) reference implementation — self-contained,
# no dependency on the external `bech32` package.
# ============================================================
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
    try:
        data = [CHARSET.index(c) for c in bech[pos + 1:]]
    except ValueError:
        raise ValueError("Invalid character in Bech32 address")
    if not bech32_verify_checksum(hrp, data):
        raise ValueError("Invalid checksum for Bech32 address")
    return hrp, data[:-6]

def convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret = 0, 0, []
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

def decode_segwit_address(addr):
    hrp, data = bech32_decode(addr)
    witver = data[0]
    prog = bytes(convertbits(data[1:], 5, 8, False))
    return witver, prog

# ============================================================
# Keys
# ============================================================
def wif_to_privkey(wif):
    raw = base58.b58decode_check(wif)
    payload = raw[1:]
    compressed = len(payload) == 33
    if compressed:
        payload = payload[:-1]
    return payload, compressed

def privkey_to_pubkey(priv, compressed=True):
    sk = SigningKey.from_string(priv, curve=SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    if compressed:
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        return prefix + x.to_bytes(32, 'big')
    return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

# ============================================================
# Address helpers
# ============================================================
def is_segwit_addr(addr):
    return addr.startswith('tb1')

def addr_to_script(addr):
    """Builds the scriptPubKey for a given address (legacy or segwit)."""
    if is_segwit_addr(addr):
        witver, prog = decode_segwit_address(addr)
        if witver != 0 or len(prog) != 20:
            raise ValueError("Only P2WPKH (v0, 20 bytes) is supported in this code")
        return b'\x00\x14' + prog
    else:
        h = base58.b58decode_check(addr)[1:]
        return b'\x76\xa9\x14' + h + b'\x88\xac'

# ============================================================
# Network
# ============================================================
def get_utxos(addr):
    r = requests.get(f"{API}/address/{addr}/utxo", timeout=15)
    r.raise_for_status()
    return r.json()

def broadcast(raw_hex):
    r = requests.post(f"{API}/tx", data=raw_hex, timeout=15)
    return r.status_code, r.text

# ============================================================
# Signing
# ============================================================
def der_sign(priv_bytes, sighash):
    sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
    sig = sk.sign_digest(sighash, sigencode=sigencode_der_canonize)
    return sig + bytes([SIGHASH_ALL])

# ============================================================
# Build & sign the raw transaction
# ============================================================
def build_and_sign(priv, pubkey, utxos, outputs, is_segwit):
    """
    utxos:   list of dicts {txid, vout, value, hash160}
    outputs: list of (script_bytes, value_satoshis)
    """
    version = struct.pack('<I', 1)
    locktime = struct.pack('<I', 0)
    sequence = struct.pack('<I', 0xffffffff)
    n_inputs = len(utxos)

    # outputs_no_count: used for BIP143 hashOutputs (NO leading count varint)
    outputs_no_count = b''
    for script, value in outputs:
        outputs_no_count += struct.pack('<Q', value) + varint(len(script)) + script

    # outputs_ser: used in the actual raw transaction (DOES need the count varint)
    outputs_ser = varint(len(outputs)) + outputs_no_count

    if not is_segwit:
        # ---- Legacy P2PKH classic signing algorithm ----
        final_inputs = []
        for i, u in enumerate(utxos):
            script_pubkey = b'\x76\xa9\x14' + u['hash160'] + b'\x88\xac'

            tmp = version + varint(n_inputs)
            for j, u2 in enumerate(utxos):
                t_txid = bytes.fromhex(u2['txid'])[::-1]
                t_vout = struct.pack('<I', u2['vout'])
                if i == j:
                    tmp += t_txid + t_vout + varint(len(script_pubkey)) + script_pubkey + sequence
                else:
                    tmp += t_txid + t_vout + varint(0) + sequence
            tmp += outputs_ser + locktime + struct.pack('<I', SIGHASH_ALL)

            sighash = hash256(tmp)
            sig = der_sign(priv, sighash)
            script_sig = push_data(sig) + push_data(pubkey)

            txid_le = bytes.fromhex(u['txid'])[::-1]
            vout = struct.pack('<I', u['vout'])
            final_inputs.append((txid_le, vout, script_sig))

        raw = version + varint(n_inputs)
        for txid_le, vout, script_sig in final_inputs:
            raw += txid_le + vout + varint(len(script_sig)) + script_sig + sequence
        raw += outputs_ser + locktime
        return raw.hex()

    else:
        # ---- Native SegWit P2WPKH signing (BIP143) ----
        prevouts = b''.join(
            bytes.fromhex(u['txid'])[::-1] + struct.pack('<I', u['vout']) for u in utxos
        )
        sequences = b''.join(sequence for _ in utxos)
        hash_prevouts = hash256(prevouts)
        hash_sequence = hash256(sequences)
        hash_outputs = hash256(outputs_no_count)

        witnesses = []
        for u in utxos:
            outpoint = bytes.fromhex(u['txid'])[::-1] + struct.pack('<I', u['vout'])
            script_code = b'\x19' + b'\x76\xa9\x14' + u['hash160'] + b'\x88\xac'
            preimage = (
                version + hash_prevouts + hash_sequence + outpoint +
                script_code + struct.pack('<Q', u['value']) + sequence +
                hash_outputs + locktime + struct.pack('<I', SIGHASH_ALL)
            )
            sighash = hash256(preimage)
            sig = der_sign(priv, sighash)
            witnesses.append((sig, pubkey))

        raw = version + b'\x00\x01' + varint(n_inputs)   # marker + flag
        for u in utxos:
            txid_le = bytes.fromhex(u['txid'])[::-1]
            vout = struct.pack('<I', u['vout'])
            raw += txid_le + vout + varint(0) + sequence  # empty scriptSig

        raw += outputs_ser

        for sig, pk in witnesses:
            raw += varint(2) + varint(len(sig)) + sig + varint(len(pk)) + pk

        raw += locktime
        return raw.hex()

# ============================================================
# High-level send()
# ============================================================
def send(wif, from_addr, to_addr, amount_sat, fee_sat=500):
    priv, compressed = wif_to_privkey(wif)
    if not compressed:
        raise ValueError("use WIF  compressed")

    pubkey = privkey_to_pubkey(priv, compressed=True)
    pub_hash = hash160(pubkey)
    segwit = is_segwit_addr(from_addr)

    raw_utxos = get_utxos(from_addr)
    if not raw_utxos:
        raise Exception("No unspent outputs found at this address UTXOs")

    utxos, total = [], 0
    for u in raw_utxos:
        utxos.append({
            'txid': u['txid'], 'vout': u['vout'],
            'value': u['value'], 'hash160': pub_hash,
        })
        total += u['value']

    change = total - amount_sat - fee_sat
    if change < 0:
        raise Exception(f"الرصيد غير كافٍ: متوفر {total}, مطلوب {amount_sat + fee_sat}")

    outputs = [(addr_to_script(to_addr), amount_sat)]
    if change > 0:
        outputs.append((addr_to_script(from_addr), change))

    raw_hex = build_and_sign(priv, pubkey, utxos, outputs, segwit)
    print("RAW TX HEX:\n", raw_hex)

    status, resp = broadcast(raw_hex)
    print("\nBROADCAST STATUS:", status)
    print("RESPONSE:", resp)
    return raw_hex


if __name__ == "__main__":
    import sys
    wif = sys.argv[1]
    to_addr = sys.argv[2]
    amount = int(sys.argv[3])
    from_addr = input("Enter your address (Legacy m/n or SegWit tb1): ").strip()
    send(wif, from_addr, to_addr, amount)