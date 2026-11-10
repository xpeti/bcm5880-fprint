#!/usr/bin/env python3
# End-to-end CV2 secure-session test on the real chip (ONE careful run, always closes).
import sys, struct, hashlib, hmac
import usb.core, usb.util
from Crypto.Cipher import AES

VID,PID=0x0a5c,0x5834
EP_OUT,EP_IN,EP_ST=0x01,0x81,0x85
HK=hashlib.sha1(b"CV secure session blob\x00").digest()
host_nonce=bytes(range(20))                   # deterministic for debugging

def pkcs7(b): p=16-(len(b)%16); return b+bytes([p])*p

dev=usb.core.find(idVendor=VID,idProduct=PID)
if dev is None: sys.exit("device not found (stop pcscd/fprintd, run as root)")
for cfg in dev:
    for intf in cfg:
        if dev.is_kernel_driver_active(intf.bInterfaceNumber):
            try: dev.detach_kernel_driver(intf.bInterfaceNumber)
            except Exception: pass
usb.util.claim_interface(dev,0)

def cv(cmd_bytes,name):
    dev.write(EP_OUT,cmd_bytes,2000)
    st=bytes(dev.read(EP_ST,16,2000))
    status=int.from_bytes(st[0:4],'little'); ln=int.from_bytes(st[4:8],'little')
    print(f"  {name}: status=0x{status:x} len={ln}")
    data=bytes(dev.read(EP_IN,ln,3000)) if ln else b""
    return status,data

def mkhdr(cmd,flags,handle,plen,iv=None,outer=None):
    h=bytearray(0x2c); h[0:4]=b"\x01\x00\x00\x00"
    h[4:8]=struct.pack("<I",outer); h[8:10]=struct.pack("<H",cmd)
    h[0x0a:0x0c]=struct.pack("<H",flags); h[0x0c:0x10]=b"\x02\x00\x00\x00"
    h[0x10:0x14]=handle; h[0x28:0x2c]=struct.pack("<I",plen)
    if iv: h[0x18:0x28]=iv
    return bytes(h)

try:
    CMD39=bytes.fromhex("010000003800000039004004020000000000000000000000000000000000000000000000000000000c000000000000000400000000000000")
    CMD82=bytes.fromhex("010000003800000082004000010000000000000000000000000000000000000000000000000000000c000000000000000400000000000000")
    cv(CMD39,"0x39"); cv(CMD82,"0x82")
    # 0x23 get pubkey (selector 0 = RSA)
    p=bytes.fromhex("0100000044000000230041000200000000000000000000000000000000000000000000000000000018000000")+bytes(range(20))+b"\x00\x00\x00\x00"
    st,r=cv(p,"0x23");
    handle=r[0x10:0x14]; param=r[0x2c:]; modulus=param[:256]; chip_nonce=param[-24:-4]
    print("  handle=%s chip_nonce=%s"%(handle.hex(),chip_nonce.hex()))
    n=int.from_bytes(modulus,'little')   # chip returns modulus in LITTLE-endian (CryptoAPI blob order)
    # PKCS1 v1.5 pad (type 2) then RSA, CryptoAPI reverses the ciphertext
    import os
    ps=bytes((b or 1) for b in os.urandom(256-3-20))
    padded=b"\x00\x02"+ps+b"\x00"+host_nonce
    c=pow(int.from_bytes(padded,'big'),0x10001,n)
    blk=c.to_bytes(256,'big')[::-1]
    cmd24=mkhdr(0x24,0x0041,handle,256,outer=0x2c+256)+blk
    st,r=cv(cmd24,"0x24 (RSA key transport)")
    # derive keys
    ENC=hashlib.sha1(chip_nonce+host_nonce).digest()[:16]
    print("  ENC key=%s"%ENC.hex())
    # send one encrypted command: the captured 0x02 body
    body=bytes.fromhex("00000000040000004d000000010000000000000001000000000000000100000000000000")
    iv=bytes(range(16)); counter=0; flags=0x0241
    outer=0x2c+len(pkcs7(body+b"\x00"*28))
    hdr=mkhdr(0x02,flags,handle,len(body),iv=iv,outer=outer)
    mac=hmac.new(HK,hdr+body+struct.pack("<I",counter),hashlib.sha1).digest()
    ct=AES.new(ENC,AES.MODE_CBC,iv).encrypt(pkcs7(body+mac+b"\x00"*8))
    st,r=cv(hdr+ct,"0x02 ENCRYPTED cmd")
    if st==0 and len(r)>0x2c:
        riv=r[0x18:0x28]; rlen=int.from_bytes(r[0x28:0x2c],'little')
        dec=AES.new(ENC,AES.MODE_CBC,riv).decrypt(r[0x2c:])
        print("  >>> RESPONSE DECRYPTED:",dec[:rlen+20].hex())
        print("  *** SESSION WORKS ON THE CHIP ***")
    else:
        print("  response status=0x%x (session not established / cmd rejected)"%st)
finally:
    try:
        close=mkhdr(0x04,0x0040,b"\x00\x00\x00\x00",4,outer=0x3c)[:0x2c]
        close=bytes.fromhex("010000003800000004004004020000000000000000000000000000000000000000000000000000000c0000000000000004000000")+handle
        cv(close,"0x04 close")
    except Exception as e: print("  close err",e)
    usb.util.release_interface(dev,0)
print("cip stav zkontroluj: lsusb -d 0a5c:5834")
