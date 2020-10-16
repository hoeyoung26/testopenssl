// testOpenSSL.cpp : 이 파일에는 'main' 함수가 포함됩니다. 거기서 프로그램 실행이 시작되고 종료됩니다.
//

#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/des.h>
#include <openssl/rand.h>

#include "openssl/evp.h"
#include "openssl/err.h"

#define BUFSIZE 1024

#ifdef _DEBUG
#pragma comment (lib, "libcryptoMDd.lib")
#pragma comment(lib, "libsslMDd.lib")
#else
#pragma comment (lib, "libcryptoMD.lib")
#pragma comment(lib, "libsslMD.lib")
#endif

int des_ecb() {
	unsigned char in[BUFSIZE], out[BUFSIZE], back[BUFSIZE];
	unsigned char *e = out;

	DES_cblock key;


	DES_cblock seed = { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
	DES_key_schedule keysched;

	memset(in, 0, sizeof(in));
	memset(out, 0, sizeof(out));
	memset(back, 0, sizeof(back));

	RAND_seed(seed, sizeof(DES_cblock));

	DES_random_key(&key);

	DES_set_key((DES_cblock *)key, &keysched);

	strcpy((char*)in, "HillTown");

	printf("Plain text : %s\n", in);

	DES_ecb_encrypt((DES_cblock *)in, (DES_cblock *)out, &keysched, DES_ENCRYPT);

	printf("Cipher text : ");
	while (*e) printf(" %02x", *e++);
	printf("\n");

	DES_ecb_encrypt((DES_cblock *)out, (DES_cblock *)back, &keysched, DES_DECRYPT);

	printf("Decrypted Text : %s\n", back);

	return 0;
}

int des_cbc() {
	unsigned char in[BUFSIZE], out[BUFSIZE], back[BUFSIZE];
	unsigned char *e = out;
	int len;

	DES_cblock key1, key2, key3;
	DES_cblock seed = { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
	DES_cblock ivsetup = { 0xE1, 0xE2, 0xE3, 0xD4, 0xD5, 0xC6, 0xC7, 0xA8 };
	DES_cblock ivec;
	DES_key_schedule ks1, ks2, ks3;

	memset(in, 0, sizeof(in));
	memset(out, 0, sizeof(out));
	memset(back, 0, sizeof(back));

	RAND_seed(seed, sizeof(DES_cblock));

	DES_random_key(&key1);
	DES_random_key(&key2);
	DES_random_key(&key3);

	DES_set_key((DES_cblock*)key1, &ks1);
	DES_set_key((DES_cblock*)key2, &ks2);
	DES_set_key((DES_cblock*)key3, &ks3);

	strcpy((char*)in, "HillTown");

	printf("Plaintext : %s\n", in);

	len = strlen((char*)in);
	memcpy(ivec, ivsetup, sizeof(ivsetup));
	DES_ede3_cbc_encrypt(in, out, len, &ks1, &ks2, &ks3, &ivec, DES_ENCRYPT);

	printf("Ciphertext:");
	while (*e) printf("%02x", *e++);
	printf("\n");

	len = strlen((char*)out);
	memcpy(ivec, ivsetup, sizeof(ivsetup));
	DES_ede3_cbc_encrypt(out, back, len, &ks1, &ks2, &ks3, &ivec, DES_DECRYPT);

	printf("Decrypted Text: %s\n", back);

	return 0;
}

int main()
{
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	des_cbc();

	return 0;
}

// 프로그램 실행: <Ctrl+F5> 또는 [디버그] > [디버깅하지 않고 시작] 메뉴
// 프로그램 디버그: <F5> 키 또는 [디버그] > [디버깅 시작] 메뉴

// 시작을 위한 팁: 
//   1. [솔루션 탐색기] 창을 사용하여 파일을 추가/관리합니다.
//   2. [팀 탐색기] 창을 사용하여 소스 제어에 연결합니다.
//   3. [출력] 창을 사용하여 빌드 출력 및 기타 메시지를 확인합니다.
//   4. [오류 목록] 창을 사용하여 오류를 봅니다.
//   5. [프로젝트] > [새 항목 추가]로 이동하여 새 코드 파일을 만들거나, [프로젝트] > [기존 항목 추가]로 이동하여 기존 코드 파일을 프로젝트에 추가합니다.
//   6. 나중에 이 프로젝트를 다시 열려면 [파일] > [열기] > [프로젝트]로 이동하고 .sln 파일을 선택합니다.
