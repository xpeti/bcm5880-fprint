// bcm5880-fprint — step 2: run the CV secure-session handshake far enough to
// pull THIS chip's public key:  0x39 (chipinfo) -> 0x82 (setup) -> 0x23 (GetCVPublicKey).
// Dumps the 0x23 response param = chip pubkey/cert (input to ephemeral P-256 ECDH).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libusb-1.0/libusb.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#define VID 0x0a5c
#define PID 0x5834
#define IFACE 0
#define EP_OUT 0x01
#define EP_IN  0x81
#define EP_ST  0x85

// Fixed CV commands captured from the stock CV2 driver on this chip:
static const char *CMD_39 = "010000003800000039004004020000000000000000000000000000000000000000000000000000000c000000000000000400000000000000";
static const char *CMD_82 = "010000003800000082004000010000000000000000000000000000000000000000000000000000000c000000000000000400000000000000";
// GetCVPublicKey (0x23): 44-byte header + 24-byte param [20B host-random][u32 selector=1=ECC].
// header: marker, len=0x44, cmd=0x23, flags=0x0041, libver=2, zeros, param_len=0x18 @ +0x28
static const char *CMD_23_HDR = "0100000044000000230041000200000000000000000000000000000000000000000000000000000018000000";
// close session: 0x04 + [param: u32 len=4][session handle] — last 4 bytes patched at runtime.
static const char *CMD_CLOSE = "010000003800000004004004020000000000000000000000000000000000000000000000000000000c00000000000000040000008c9b0114";

static int hexdecode(const char *h, unsigned char *out, int max) {
    int n = 0; while (h[0] && h[1] && n < max) { unsigned v; sscanf(h, "%2x", &v); out[n++]=(unsigned char)v; h+=2; } return n;
}
static void dump(const unsigned char *b, int n) {
    for (int i=0;i<n;i+=16){printf("%04x  ",i);for(int j=0;j<16;j++){if(i+j<n)printf("%02x ",b[i+j]);else printf("   ");}printf(" ");for(int j=0;j<16&&i+j<n;j++){int c=b[i+j];putchar((c>=32&&c<127)?c:'.');}printf("\n");}
}

static libusb_device_handle *H;

// send a CV command, read status (ep85) + response (ep81). returns response len or -1.
static int cv_cmd(const unsigned char *cmd, int clen, unsigned char *resp, int rmax, const char *name) {
    int tr=0, r;
    r = libusb_bulk_transfer(H, EP_OUT, (unsigned char*)cmd, clen, &tr, 3000);
    if (r){fprintf(stderr,"%s OUT: %s\n",name,libusb_error_name(r));return -1;}
    unsigned char st[16]={0};
    r = libusb_interrupt_transfer(H, EP_ST, st, sizeof st, &tr, 3000);
    if (r){fprintf(stderr,"%s ST: %s\n",name,libusb_error_name(r));return -1;}
    unsigned status=st[0]|st[1]<<8|st[2]<<16|st[3]<<24, len=st[4]|st[5]<<8|st[6]<<16|st[7]<<24;
    printf("  %s: status=0x%x resp_len=%u\n", name, status, len);
    if (status) return -1;
    if ((int)len>rmax) len=rmax;
    r = libusb_bulk_transfer(H, EP_IN, resp, len, &tr, 3000);
    if (r){fprintf(stderr,"%s IN: %s\n",name,libusb_error_name(r));return -1;}
    return tr;
}

// ephemeral P-256 ECDH with the chip pubkey (chip_xy = 64 bytes X||Y, big-endian).
// prints the shared secret and our host ephemeral pubkey (to be sent via 0x24).
static int ecdh(const unsigned char *chip_xy, unsigned char *host_xy_out) {
    int ok = 0;
    unsigned char point[65]; point[0]=0x04; memcpy(point+1, chip_xy, 64);
    OSSL_PARAM par[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,(char*)"prime256v1",0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, point, 65),
        OSSL_PARAM_END };
    EVP_PKEY *chip=NULL,*host=NULL; EVP_PKEY_CTX *c=NULL,*d=NULL;
    c = EVP_PKEY_CTX_new_from_name(NULL,"EC",NULL);
    if(!c||EVP_PKEY_fromdata_init(c)<=0||EVP_PKEY_fromdata(c,&chip,EVP_PKEY_PUBLIC_KEY,par)<=0){
        fprintf(stderr,"  ECDH: chip pubkey INVALID P-256 point (wrong offset/encoding)\n"); goto done; }
    printf("  ECDH: chip pubkey is a VALID P-256 point OK\n");
    host = EVP_PKEY_Q_keygen(NULL,NULL,"EC","prime256v1");
    if(!host){fprintf(stderr,"  keygen fail\n");goto done;}
    d = EVP_PKEY_CTX_new(host,NULL);
    size_t slen=0; unsigned char secret[80];
    if(EVP_PKEY_derive_init(d)<=0||EVP_PKEY_derive_set_peer(d,chip)<=0||
       EVP_PKEY_derive(d,NULL,&slen)<=0||EVP_PKEY_derive(d,secret,&slen)<=0){
        fprintf(stderr,"  derive fail\n");goto done;}
    printf("  ECDH shared secret (%zu B): ",slen);
    for(size_t i=0;i<slen;i++)printf("%02x",secret[i]); printf("\n");
    // export our host pubkey (uncompressed) for the 0x24 command
    unsigned char hp[128]; size_t hlen=sizeof hp;
    if(EVP_PKEY_get_octet_string_param(host,OSSL_PKEY_PARAM_PUB_KEY,hp,sizeof hp,&hlen)>0 && hlen==65){
        memcpy(host_xy_out, hp+1, 64);
        printf("  host ephemeral pubkey X||Y ready (64B)\n");
        ok=1;
    }
done:
    EVP_PKEY_free(chip);EVP_PKEY_free(host);EVP_PKEY_CTX_free(c);EVP_PKEY_CTX_free(d);
    return ok;
}

int main(void){
    libusb_context *ctx=NULL; if(libusb_init(&ctx)){fprintf(stderr,"init\n");return 1;}
    H=libusb_open_device_with_vid_pid(ctx,VID,PID);
    if(!H){fprintf(stderr,"device not found (run root / free from fprintd)\n");return 1;}
    libusb_set_auto_detach_kernel_driver(H,1);
    if(libusb_claim_interface(H,IFACE)){fprintf(stderr,"claim fail\n");return 1;}

    unsigned char cmd[256], resp[2048]; int n;

    n=hexdecode(CMD_39,cmd,sizeof cmd); cv_cmd(cmd,n,resp,sizeof resp,"0x39 chipinfo");
    n=hexdecode(CMD_82,cmd,sizeof cmd); cv_cmd(cmd,n,resp,sizeof resp,"0x82 setup");

    // build 0x23: header(44) + [20 random][u32 selector=1]
    n=hexdecode(CMD_23_HDR,cmd,sizeof cmd);  // 44 bytes
    for(int i=0;i<20;i++) cmd[n++]=(unsigned char)(0x11*i+7);   // deterministic "random" nonce
    cmd[n++]=0; cmd[n++]=0; cmd[n++]=0; cmd[n++]=0;             // selector=0 (RSA-2048 pubkey)
    int rl=cv_cmd(cmd,n,resp,sizeof resp,"0x23 GetCVPublicKey");
    if(rl>0){
        printf("\n=== 0x23 response %d bytes; header 44B then param=chip pubkey ===\n",rl);
        unsigned handle=resp[0x10]|resp[0x11]<<8|resp[0x12]<<16|resp[0x13]<<24;
        unsigned plen = resp[0x28]|resp[0x29]<<8|resp[0x2a]<<16|resp[0x2b]<<24;
        printf("session handle = 0x%08x   param_len = %u\n\n", handle, plen);
        printf("--- chip RSA-2048 pubkey/cert param (%d B) ---\n", rl-0x2c);
        dump(resp+0x2c, rl-0x2c);
        (void)ecdh;

        // ALWAYS close the session so we don't exhaust the chip's session slots.
        unsigned char cl[128]; int cn = hexdecode(CMD_CLOSE, cl, sizeof cl);
        memcpy(cl + cn - 4, resp + 0x10, 4);   // patch handle (LE) from 0x23 response
        unsigned char cresp[128];
        int cr = cv_cmd(cl, cn, cresp, sizeof cresp, "0x04 close-session");
        printf("  session 0x%08x closed (%s)\n", handle, cr>=0 ? "ok" : "err");
    }
    libusb_release_interface(H,IFACE); libusb_close(H); libusb_exit(ctx); return 0;
}
