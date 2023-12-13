//AES加密文本之CBC模式
//openssl版本：3.0系列 ，win 32
#include <iostream>
#include<openssl/evp.h>
#include<openssl\rand.h>
using namespace std;
int main()
{
	EVP_CIPHER_CTX* ctx;
	int ciphertext_len; 
	int len;
	unsigned char key[32];
	RAND_bytes(key, 32);
	unsigned char iv[16];
	RAND_bytes(iv,16);
	unsigned char plaintext[] = "hellweqweol";//需要加密的文本
	unsigned char ciphertext[512];//加密后的文本
	if (!(ctx = EVP_CIPHER_CTX_new()))//创建一个加解密上下文
	{
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))//初始化加密
	{
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	int i_strLen = strlen((const char *)plaintext) + 1;
	/*将输入的明文数据块进行加密，并将加密结果输出到指定的输出缓冲区*/
	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, i_strLen))
	{
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}	
	ciphertext_len = len;
	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
	{
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	ciphertext_len += len;
	//解密
	// 重新初始化解密上下文
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
	{
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	unsigned char result[512];
	int strL;
	if (1 != EVP_DecryptUpdate(ctx, result, &strL, ciphertext, ciphertext_len))
	{
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	if (1 != EVP_DecryptFinal_ex(ctx, result + strL, &len))
	{
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}
