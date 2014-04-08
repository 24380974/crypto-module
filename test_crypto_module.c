/* Модуль ядра для пробы crypto api ядра Linux */
/* Common headers */
#include "linux/init.h"
#include "linux/module.h"
#include "linux/kernel.h"
#include <linux/err.h>
/* crypto headers */
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>

#define AES_BLOCK_SIZE (16)
#define AES_IV_SIZE    (16)
#define AES_KEY_SIZE   (64) /*because we using XTS mode*/

typedef enum {
	ENCRYPT,
	DECRYPT
} cipher_mode;

static int crypt_data(u8 *key, u32 key_len, u8 *iv, u32 iv_len, u8 *dst, u32 dst_len, u8 *src, u8 src_len, cipher_mode mode)
{
	struct crypto_blkcipher * blk;
	struct blkcipher_desc desc;
	struct scatterlist sg[2];

    /*CRYPTO_ALG_TYPE_BLKCIPHER_MASK, CRYPTO_ALG_TYPE_BLKCIPHER*/
	blk = crypto_alloc_blkcipher("xts(aes)", 0, 0);
	if (IS_ERR(blk)) {
		printk(KERN_ALERT "Failed to initialize AES-XTS mode \n");
		return -1;
	} else {
		printk(KERN_ALERT "Initialized cipher: %s \n", crypto_blkcipher_name(blk));
		printk(KERN_ALERT "with IV size: %d \n", crypto_blkcipher_ivsize(blk));
		printk(KERN_ALERT "block size: %d \n", crypto_blkcipher_blocksize(blk));
	}

	if(crypto_blkcipher_setkey(blk, key, key_len)) {
		printk(KERN_ALERT "Failed to set key. \n");
		goto err;
	}

	crypto_blkcipher_set_iv(blk, iv, iv_len);

	sg_init_one(&sg[0],src,src_len);
	sg_init_one(&sg[1],dst,dst_len);

	/* do encryption */
	desc.tfm = blk;
	desc.flags = 0;

	if(mode == ENCRYPT) {
		if(crypto_blkcipher_encrypt(&desc, &sg[1], &sg[0], src_len)) {
			printk(KERN_ALERT "Failed to encrypt. \n");
		}
	} else {
		if(crypto_blkcipher_decrypt(&desc, &sg[1], &sg[0], src_len)) {
			printk(KERN_ALERT "Failed to encrypt. \n");
		}
	}
	

	crypto_free_blkcipher(blk);

	return 0;

err:
	
	crypto_free_blkcipher(blk);

	return -1;
}


static int aes_crypt_init(void)
{
	u8 key[AES_KEY_SIZE]; 
	u8 iv[AES_IV_SIZE];
	u8 src[AES_BLOCK_SIZE];
	u8 enc[AES_BLOCK_SIZE];
	u8 dec[AES_BLOCK_SIZE];
	int err = 0;

	printk(KERN_ALERT "AES crypto module start initialyzing. \n");

	err = crypt_data(key, AES_KEY_SIZE, iv, AES_IV_SIZE, enc, AES_BLOCK_SIZE, src, AES_BLOCK_SIZE, ENCRYPT);

	err = crypt_data(key, AES_KEY_SIZE, iv, AES_IV_SIZE, dec, AES_BLOCK_SIZE, enc, AES_BLOCK_SIZE, DECRYPT);

	if(memcmp(dec, src, AES_BLOCK_SIZE))
		printk(KERN_ALERT "Encrypt/Decrypt error. \n");
	else
		printk(KERN_ALERT "Test passed. \n");

	return err;
}

static void aes_crypt_exit(void)
{
	printk(KERN_ALERT "AES crypto module exiting. \n");
}

module_init(aes_crypt_init);
module_exit(aes_crypt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dmitry Falko");
MODULE_DESCRIPTION("Testing module crypto api for AES-XTS mode");