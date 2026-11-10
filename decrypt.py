#!/usr/bin/env python3
# Offline decryption iterator for the captured CV2 secure session.
# Host nonce + IV are deterministic (patched bipdll RNG -> 00 01 02 ...).
import hashlib
from Crypto.Cipher import AES

def h(s): return bytes.fromhex(s)

# frames (payload after 44-byte CV header unless noted)
f193 = h("01000000440000002300410002000000000000000000000000000000000000000000000000000000180000001d6cae996100fd8fa9a7ad3201d2015ef930e16300000000")
f198 = h("010000006c01000023004101020000008c9b0114000000000000000000000000000000000000000040010000ed293a1096daa86cd496d5befa40a17361db9ef31184573a74265efff0d8b232803a6d26bfd828e5e68a2b88c2213500020c599f8d6efe703c7b24caa5516e88c5cd6f0f816eb033177a1f911ed73b4cea7ce387771d5f9cd8c81f1451b1ec5e1c05e0251aa683e5377c0c3e89c27e9481cbd729f46663c6f1fd8ccf97c3ae4d7f7c79de0c6c988adebc01ad2aaee7a8b61c3d67da3d398cd3297bddf9843b5ac36037ac75451012a12010286cd38ed698a818f83c878f48c2ff4dfe9c503af2a75f7faafacbc2d0d9e8b588b24b2ab239d15cb90694f0822ad2447bc9145887dcf7821ada47ad41b2e1d458acbba35d67497cc0cc2229300fb77a4539ba68a85f545355435f4853550a31303030303030363a444443535f4853550a30303030303030303a5645527c82f0ce29fe58070aa6919dd0c7809661b2e17700000000")
f211 = h("010000007c00000002004102020000008c9b011400000000000102030405060708090a0b0c0d0e0f240000007e5520bb631a2d7424faad3e85f154203a6a58f89380d5cd45811f5b731f32f36c49345da61e61dd449f0790fe3d99206e4114043a1b297df9dae91456208f8e7da811cea194e1be7e6667b17e18fe62")

# known deterministic values (from patched RNG)
host20 = bytes(range(20))          # 00..13  host nonce
IV16   = bytes(range(16))          # 00..0f  CBC IV

# 0x23 request 20-byte field (plaintext, host->chip)
field20 = f193[0x2c:0x2c+20]
# 0x23 response param: modulus(256) + info + trailing 20B (chip nonce?) + 00000000
resp = f198[0x2c:]
modulus = resp[:256]
chip_tail = resp[-24:-4]           # last 20 bytes before trailing 0
# #211 encrypted command layout: [hdr 0x18][IV 16 @0x18][inner_len 4 @0x28][CBC 48 @0x2c][HMAC 32]
IVc      = f211[0x18:0x28]
innerlen = int.from_bytes(f211[0x28:0x2c],'little')
encdata  = f211[0x2c:0x2c+48]       # 48B ciphertext (36 plaintext + PKCS7 pad to 48)
hmac_tag = f211[0x2c+48:]           # 32B trailing (HMAC?)
assert IVc==IV16, IVc.hex()
print("IV=%s innerlen=0x%x ct=%dB tag=%dB" % (IVc.hex(), innerlen, len(encdata), len(hmac_tag)))
print("field20   =", field20.hex())
print("chip_tail =", chip_tail.hex())
print()

def sha1(*xs):
    m=hashlib.sha1()
    for x in xs: m.update(x)
    return m.digest()
def sha256(*xs):
    m=hashlib.sha256()
    for x in xs: m.update(x)
    return m.digest()

cands = {}
for nm,a,b in [
    ("host",host20,None),("field",field20,None),("chiptail",chip_tail,None),
    ("field|host",field20,host20),("host|field",host20,field20),
    ("chiptail|host",chip_tail,host20),("host|chiptail",host20,chip_tail),
    ("chiptail|field",chip_tail,field20),("field|chiptail",field20,chip_tail),
    ("mod20|host",modulus[:20],host20),("host|mod20",host20,modulus[:20]),
    ("mod20|field",modulus[:20],field20),("field|mod20",field20,modulus[:20]),
]:
    inp = a+(b or b"")
    cands["SHA1("+nm+")"]   = sha1(inp)[:16]
    cands["SHA256("+nm+")"] = sha256(inp)[:16]
cands["raw host[:16]"] = host20[:16]
cands["raw field[:16]"] = field20[:16]

def printable(b):
    return sum(32<=c<127 or c in (0,) for c in b)
best=[]
for nm,key in cands.items():
    try:
        pt = AES.new(key, AES.MODE_CBC, IV16).decrypt(encdata)
    except Exception as e:
        continue
    score = printable(pt)
    # heuristic: valid PKCS7 pad OR many low/structured bytes
    pad = pt[-1]
    padok = 1<=pad<=16 and pt[-pad:]==bytes([pad])*pad
    best.append((score,padok,nm,pt))
best.sort(key=lambda x:(-x[1],-x[0]))
for score,padok,nm,pt in best[:8]:
    print("%-22s pad=%s score=%2d  %s" % (nm, padok, score, pt.hex()))
    print(" "*22, "ascii:", ''.join(chr(c) if 32<=c<127 else '.' for c in pt))
