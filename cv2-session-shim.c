// cv2-session-shim.c — LD_PRELOAD shim that adds the ControlVault 2 secure session
// to the stock (CV3) libfprint broadcom driver, so fprintd works on 0a5c:5834.
//
// It intercepts the driver's libusb traffic on interface 0, establishes the CV2
// secure session once (0x39/0x82/0x23/0x24), then transparently AES-128-CBC+HMAC-SHA1
// encrypts outgoing session commands and decrypts incoming responses. The stock
// driver drives the whole enrollment; this only supplies the crypto it lacks.
//
// Build:  cc -shared -fPIC -o cv2-session-shim.so cv2-session-shim.c -ldl -lcrypto
// Use:    sudo systemctl stop fprintd
//         sudo LD_PRELOAD=$PWD/cv2-session-shim.so /usr/libexec/fprintd   (or fprintd-enroll via the daemon)
//
// NOTE: WORK IN PROGRESS — the crypto is validated (see session_test.py / docs), the
// interception/response-buffering path still needs testing against a live enroll.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <libusb-1.0/libusb.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#define EP_OUT 0x01
#define EP_IN  0x81
#define EP_ST  0x85

#define SHIMLOG(...) do{ fprintf(stderr,"[cv2-shim] " __VA_ARGS__); fflush(stderr); }while(0)

static int (*real_bulk)(libusb_device_handle*,unsigned char,unsigned char*,int,int*,unsigned int);
static int (*real_intr)(libusb_device_handle*,unsigned char,unsigned char*,int,int*,unsigned int);

static void init_syms(void){
    if(!real_bulk) real_bulk=dlsym(RTLD_NEXT,"libusb_bulk_transfer");
    if(!real_intr) real_intr=dlsym(RTLD_NEXT,"libusb_interrupt_transfer");
}

// --- session state (single device assumed) ---
static int      sess_ready=0;
static unsigned char ENC[16], HMACK[20], HANDLE[4];
static uint32_t COUNTER=0;
// buffered plaintext reply to feed back to the stock driver
static unsigned char buf_status[8];
static unsigned char buf_body[8192]; static int buf_body_len=0; static int buf_have=0;

static uint32_t le32(const unsigned char*p){return p[0]|p[1]<<8|p[2]<<16|(uint32_t)p[3]<<24;}
static void put32(unsigned char*p,uint32_t v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}

static const unsigned char CMD39[]={1,0,0,0,0x38,0,0,0,0x39,0,0x40,4,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x0c,0,0,0,0,0,0,0,4,0,0,0,0,0,0,0};
static const unsigned char CMD82[]={1,0,0,0,0x38,0,0,0,0x82,0,0x40,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x0c,0,0,0,0,0,0,0,4,0,0,0,0,0,0,0};

// raw CV transfer via the REAL libusb; returns body length or -status
static int cv_raw(libusb_device_handle*h,const unsigned char*cmd,int clen,unsigned char*resp,int rmax){
    int tr=0,e;
    e=real_bulk(h,EP_OUT,(unsigned char*)cmd,clen,&tr,3000);
    if(e){ SHIMLOG("  cv_raw OUT err=%d (%s)\n",e,libusb_error_name(e)); return -1; }
    unsigned char st[16]={0};
    e=real_intr(h,EP_ST,st,sizeof st,&tr,3000);
    if(e){ SHIMLOG("  cv_raw ST(ep85) err=%d (%s)\n",e,libusb_error_name(e)); return -1; }
    uint32_t status=le32(st),len=le32(st+4);
    if(status) return -(int)status;
    if((int)len>rmax) len=rmax;
    if(len && real_bulk(h,EP_IN,resp,len,&tr,3000)) return -1;
    return len?tr:0;
}

static void derive_keys(const unsigned char*chip_nonce,const unsigned char*host_nonce){
    unsigned char t[40]; memcpy(t,chip_nonce,20); memcpy(t+20,host_nonce,20);
    unsigned char d[20]; SHA1(t,40,d); memcpy(ENC,d,16);
    SHA1((const unsigned char*)"CV secure session blob\0",23,HMACK);
}

static int establish(libusb_device_handle*h){
    unsigned char r[1024]; int x;
    x=cv_raw(h,CMD39,sizeof CMD39,r,sizeof r); SHIMLOG("est: 0x39 -> %d\n",x); if(x<0) return -1;
    x=cv_raw(h,CMD82,sizeof CMD82,r,sizeof r); SHIMLOG("est: 0x82 -> %d\n",x); if(x<0) return -1;
    // 0x23 get-pubkey, selector 0 (RSA)
    unsigned char c23[0x44]; memset(c23,0,sizeof c23);
    c23[0]=1; c23[4]=0x44; c23[8]=0x23; c23[0x0a]=0x41; c23[0x0c]=2; c23[0x28]=0x18;
    for(int i=0;i<20;i++) c23[0x2c+i]=i;              // host field (unused for keys)
    int rl=cv_raw(h,c23,sizeof c23,r,sizeof r);
    SHIMLOG("est: 0x23 -> %d (need >=%d)\n",rl,0x2c+256+4);
    if(rl<0x2c+256+4) return -1;
    memcpy(HANDLE,r+0x10,4);
    unsigned char *param=r+0x2c; int plen=rl-0x2c;
    unsigned char modulus[256]; memcpy(modulus,param,256);
    unsigned char chip_nonce[20]; memcpy(chip_nonce,param+plen-24,20);
    unsigned char host_nonce[20]; RAND_bytes(host_nonce,20);
    // 0x24 = reverse(RSA-2048-PKCS1(modulus, host_nonce))
    BIGNUM*n=BN_bin2bn(modulus,256,NULL); BIGNUM*e=NULL; BN_dec2bn(&e,"65537");
    RSA*rsa=RSA_new(); RSA_set0_key(rsa,n,e,NULL);
    unsigned char blk[256];
    int ok=RSA_public_encrypt(20,host_nonce,blk,rsa,RSA_PKCS1_PADDING);
    RSA_free(rsa);
    if(ok!=256) return -1;
    for(int i=0;i<128;i++){unsigned char t=blk[i];blk[i]=blk[255-i];blk[255-i]=t;} // CryptoAPI byte-reverse
    unsigned char c24[0x2c+256]; memset(c24,0,0x2c);
    c24[0]=1; put32(c24+4,0x2c+256); c24[8]=0x24; c24[0x0a]=0x41; c24[0x0c]=2;
    memcpy(c24+0x10,HANDLE,4); put32(c24+0x28,256); memcpy(c24+0x2c,blk,256);
    if(cv_raw(h,c24,sizeof c24,r,sizeof r)<0) return -1;
    derive_keys(chip_nonce,host_nonce);
    COUNTER=0; sess_ready=1;
    SHIMLOG("secure session established: handle=%02x%02x%02x%02x\n",HANDLE[0],HANDLE[1],HANDLE[2],HANDLE[3]);
    return 0;
}

// should this command id be wrapped in the secure session?
static int needs_wrap(unsigned cmd){
    switch(cmd){case 0x39:case 0x82:case 0x04:case 0x23:case 0x24:return 0;default:return 1;}
}

// wrap the driver's plaintext command, send it, decrypt+buffer the reply
static int wrap_send(libusb_device_handle*h,const unsigned char*cmd,int clen){
    unsigned cmdid=cmd[8]|cmd[9]<<8, flags=cmd[0x0a]|cmd[0x0b]<<8;
    uint32_t bodylen=le32(cmd+0x28);
    const unsigned char*body=cmd+0x2c;
    unsigned char iv[16]; RAND_bytes(iv,16);
    // header
    int blob= bodylen+20+8; int pad=16-(blob%16); int ctlen=blob+pad;
    unsigned char hdr[0x2c]; memset(hdr,0,sizeof hdr);
    // CV2 encrypted flags: keep the command's low byte, set bit0 (encrypted),
    // force the high byte to 0x02 (CV2). CV3 uses 0x04. e.g. 0x0440->0x0241, 0x0442->0x0243.
    unsigned eflags = ((flags & 0xff) | 1) | 0x0200;
    hdr[0]=1; put32(hdr+4,0x2c+ctlen); hdr[8]=cmdid; hdr[9]=cmdid>>8;
    hdr[0x0a]=eflags; hdr[0x0b]=eflags>>8; hdr[0x0c]=2;
    memcpy(hdr+0x10,HANDLE,4); memcpy(hdr+0x18,iv,16); put32(hdr+0x28,bodylen);
    // HMAC over header[0:0x2c] || body || counter
    unsigned char macin[0x2c+8192+4]; int mi=0;
    memcpy(macin,hdr,0x2c); mi=0x2c; memcpy(macin+mi,body,bodylen); mi+=bodylen;
    put32(macin+mi,COUNTER); mi+=4;
    unsigned char mac[20]; unsigned int ml=20;
    HMAC(EVP_sha1(),HMACK,20,macin,mi,mac,&ml);
    // plaintext blob = body||mac||counter_u32||align, PKCS7 to ctlen
    unsigned char pt[8192]; int p=0;
    memcpy(pt,body,bodylen); p=bodylen; memcpy(pt+p,mac,20); p+=20;
    memset(pt+p,0,8); p+=8;
    for(int i=0;i<pad;i++) pt[p++]=pad;      // PKCS7
    // AES-128-CBC encrypt
    unsigned char frame[0x2c+8192]; memcpy(frame,hdr,0x2c);
    EVP_CIPHER_CTX*c=EVP_CIPHER_CTX_new(); int ol=0,fl=0;
    EVP_EncryptInit_ex(c,EVP_aes_128_cbc(),NULL,ENC,iv); EVP_CIPHER_CTX_set_padding(c,0);
    EVP_EncryptUpdate(c,frame+0x2c,&ol,pt,ctlen); EVP_EncryptFinal_ex(c,frame+0x2c+ol,&fl);
    EVP_CIPHER_CTX_free(c);
    COUNTER++;
    // send, read encrypted reply
    unsigned char rep[8192]; int rl=cv_raw(h,frame,0x2c+ctlen,rep,sizeof rep);
    if(rl<0){ buf_have=0; put32(buf_status,(uint32_t)(-rl)); put32(buf_status+4,0); return 0; }
    // decrypt reply body; present the driver a plaintext response = [header][body]
    if(rl>=0x2c){
        unsigned char*riv=rep+0x18; uint32_t rbl=le32(rep+0x28);
        memcpy(buf_body,rep,0x2c);                 // response header
        buf_body[0x0a]&=~1; buf_body[0x0b]&=~0x02;  // flags -> plaintext-ish (clear enc bit, 0x02->CV3)
        buf_body[0x0b]|=0x04;
        EVP_CIPHER_CTX*d=EVP_CIPHER_CTX_new(); int dl=0,dfl=0;
        EVP_DecryptInit_ex(d,EVP_aes_128_cbc(),NULL,ENC,riv); EVP_CIPHER_CTX_set_padding(d,0);
        EVP_DecryptUpdate(d,buf_body+0x2c,&dl,rep+0x2c,rl-0x2c); EVP_DecryptFinal_ex(d,buf_body+0x2c+dl,&dfl);
        buf_body_len=0x2c+rbl; put32(buf_status,0); put32(buf_status+4,0x2c+rbl); buf_have=1;
        SHIMLOG("  wrapped cmd 0x%02x -> chip ok, reply %u B\n",cmdid,rbl);
    } else { buf_have=0; put32(buf_status,0); put32(buf_status+4,0); }
    return 0;
}

// ---- interposed libusb entry points ----
int libusb_bulk_transfer(libusb_device_handle*h,unsigned char ep,unsigned char*data,int len,int*transferred,unsigned int to){
    init_syms();
    if(ep==EP_OUT && len>=0x2c && data[0]==1){
        unsigned cmd=data[8]|data[9]<<8;
        if(!sess_ready){ SHIMLOG("first OUT (cmd 0x%02x) -> establishing session\n",cmd); establish(h); }
        if(sess_ready && needs_wrap(cmd)){
            wrap_send(h,data,len);
            if(transferred)*transferred=len;
            return 0;
        }
        // passthrough handshake command, but buffer its reply
        int rl=cv_raw(h,data,len,buf_body,sizeof buf_body);
        if(rl>=0){ buf_body_len=rl; put32(buf_status,0); put32(buf_status+4,rl); buf_have=1; }
        if(transferred)*transferred=len; return 0;
    }
    if(ep==EP_IN && buf_have){
        int n=buf_body_len<len?buf_body_len:len;
        memcpy(data,buf_body,n); if(transferred)*transferred=n; return 0;
    }
    return real_bulk(h,ep,data,len,transferred,to);
}

int libusb_interrupt_transfer(libusb_device_handle*h,unsigned char ep,unsigned char*data,int len,int*transferred,unsigned int to){
    init_syms();
    if(ep==EP_ST && buf_have){
        int n=8<len?8:len; memcpy(data,buf_status,n); if(transferred)*transferred=n; return 0;
    }
    return real_intr(h,ep,data,len,transferred,to);
}
