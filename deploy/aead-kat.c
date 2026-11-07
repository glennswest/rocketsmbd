/* Independent AES-GCM/CCM known-answer vectors for src/crypto.rs (#23), from
 * OpenSSL EVP (not RustCrypto). SMB3 parameters: 16-byte tag, 12-byte GCM /
 * 11-byte CCM nonce. Run: sc-build 'cc -o $TMPDIR/kat deploy/aead-kat.c -lcrypto && $TMPDIR/kat' */
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
static void hex(const char *n, const unsigned char *b, int l){printf("%s=",n);for(int i=0;i<l;i++)printf("%02x",b[i]);printf("\n");}
static void run(const char *name, const EVP_CIPHER *c, int klen, int nlen, int ccm){
  unsigned char key[32], nonce[16], out[128], tag[16]; int l, ol=0;
  const unsigned char aad[]="smb2-transform-header-aad"; const unsigned char pt[]="the quick brown fox jumps over the lazy SMB share";
  int alen=strlen((const char*)aad), plen=strlen((const char*)pt);
  memset(key,0x11,klen); memset(nonce,0x22,nlen);
  EVP_CIPHER_CTX *x=EVP_CIPHER_CTX_new(); EVP_EncryptInit_ex(x,c,NULL,NULL,NULL);
  EVP_CIPHER_CTX_ctrl(x, ccm?EVP_CTRL_CCM_SET_IVLEN:EVP_CTRL_GCM_SET_IVLEN, nlen, NULL);
  if(ccm) EVP_CIPHER_CTX_ctrl(x,EVP_CTRL_CCM_SET_TAG,16,NULL);
  EVP_EncryptInit_ex(x,NULL,NULL,key,nonce);
  if(ccm) EVP_EncryptUpdate(x,NULL,&l,NULL,plen);
  EVP_EncryptUpdate(x,NULL,&l,aad,alen);
  EVP_EncryptUpdate(x,out,&l,pt,plen); ol=l; EVP_EncryptFinal_ex(x,out+ol,&l); ol+=l;
  EVP_CIPHER_CTX_ctrl(x, ccm?EVP_CTRL_CCM_GET_TAG:EVP_CTRL_GCM_GET_TAG,16,tag);
  printf("[%s] ptlen=%d\n",name,plen); hex("ct",out,ol); hex("tag",tag,16); EVP_CIPHER_CTX_free(x);
}
int main(){run("AES128_GCM",EVP_aes_128_gcm(),16,12,0);run("AES256_GCM",EVP_aes_256_gcm(),32,12,0);run("AES128_CCM",EVP_aes_128_ccm(),16,11,1);run("AES256_CCM",EVP_aes_256_ccm(),32,11,1);return 0;}
