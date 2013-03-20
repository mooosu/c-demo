#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
char *base64(const unsigned char *input, int length)
{
  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  char *buff = (char *)malloc(bptr->length);
  memcpy(buff, bptr->data, bptr->length-1);
  buff[bptr->length-1] = 0;

  BIO_free_all(b64);

  return buff;
}
int main(void)
{
    int docontinue = 1;
    char *data = "abcdefgh"; /* 明文 */
    int data_len;
    int data_rest;
    unsigned char ch;
    unsigned char *src = NULL; /* 补齐后的明文 */
    unsigned char *dst = NULL; /* 解密后的明文 */
    unsigned char *encryption= NULL; /* 解密后的明文 */
    int len;
    unsigned char tmp[8];
    unsigned char in[8];
    unsigned char out[8];
    char *k = "1234567890abcdefghijklmn"; /* 原始密钥 */
    int key_len;
    #define LEN_OF_KEY 24
    unsigned char key[LEN_OF_KEY]; /* 补齐后的密钥 */
    unsigned char block_key[9];
    DES_key_schedule ks,ks2,ks3;
    /* 构造补齐后的密钥 */
    key_len = strlen(k);
    memcpy(key, k, key_len);
    memset(key + key_len, 0x00, LEN_OF_KEY - key_len);
    /* 分析补齐明文所需空间及补齐填充数据 */
    data_len = strlen(data);
    data_rest = data_len % 8;
    len = data_len + (8 - data_rest);
    ch = 8 - data_rest;
    src = (unsigned char *)malloc(len);
    dst = (unsigned char *)malloc(len);
    encryption = (unsigned char *)malloc(len);
    if (NULL == src || NULL == dst)
    {
        docontinue = 0;
    }
    if (docontinue)
    {
        int count;
        int i;
        /* 构造补齐后的加密内容 */
        memset(src, 0, len);
        memcpy(src, data, data_len);
        memset(src + data_len, ch, 8 - data_rest);
        /* 密钥置换 */
        memset(block_key, 0, sizeof(block_key));
        memcpy(block_key, key + 0, 8);
        DES_set_key_unchecked((const_DES_cblock*)block_key, &ks);
        memcpy(block_key, key + 8, 8);
        DES_set_key_unchecked((const_DES_cblock*)block_key, &ks2);
        memcpy(block_key, key + 16, 8);
        DES_set_key_unchecked((const_DES_cblock*)block_key, &ks3);
        printf("before encrypt:\n%s\n",data);
        /* 循环加密/解密，每8字节一次 */
        count = len / 8;
        for (i = 0; i < count; i++)
        {
            memset(tmp, 0, 8);
            memset(in, 0, 8);
            memset(out, 0, 8);
            memcpy(tmp, src + 8 * i, 8);
            /* 加密 */
            DES_ecb3_encrypt((const_DES_cblock*)tmp, (DES_cblock*)in, &ks, &ks2, &ks3, DES_ENCRYPT);
            memcpy(encryption + 8 * i, in, 8);
            /* 解密 */
            DES_ecb3_encrypt((const_DES_cblock*)in, (DES_cblock*)out, &ks, &ks2, &ks3, DES_DECRYPT);
            /* 将解密的内容拷贝到解密后的明文 */
            memcpy(dst + 8 * i, out, 8);
        }
        printf("encryption :\n");
        for (i = 0; i < len; i++)
        {
            printf("0x%.2X ", *(encryption + i));
        }
	printf("\n%s\n",base64(encryption,len+1));
    }
    if (NULL != src)
    {
        free(src);
        src = NULL;
    }
    if (NULL != dst)
    {
        free(dst);
        dst = NULL;
    }
    return 0;
}
