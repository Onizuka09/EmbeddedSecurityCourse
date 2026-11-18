/* USER CODE BEGIN Header */
/**
 ******************************************************************************
 * @file           : main.c
 * @brief          : Main program body
 ******************************************************************************
 * @attention
 *
 * Copyright (c) 2026 STMicroelectronics.
 * All rights reserved.
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include<stdio.h>
#include<string.h>
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
CRYP_HandleTypeDef hcryp;


HASH_HandleTypeDef hhash;

PKA_HandleTypeDef hpka;

RNG_HandleTypeDef hrng;

UART_HandleTypeDef huart1;

/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_AES_Init(void);
static void MX_HASH_Init(void);
static void MX_RNG_Init(void);
static void MX_PKA_Init(void);
static void MX_USART1_UART_Init(void);
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
int __io_putchar(int ch) {
	HAL_UART_Transmit(&huart1, (uint8_t*) &ch, 1, 0xFFFF);
	return ch;
}
/* AES TEST  ---------------------------------------------------------*/
__ALIGN_BEGIN static const uint32_t pKeyAES[4] __ALIGN_END = { 0x2B7E1516,
		0x28AED2A6, 0xABF71588, 0x09CF4F3C };
uint32_t input_data[4] = { 0x6bc1bee2, 0x2e409f96, 0xe93d7e11, 0x7393172a };
uint32_t encrypted_data[4];
uint32_t decrypted_data[4];

__ALIGN_BEGIN static const uint32_t pKeyAES2[4] __ALIGN_END = { 0xdeadbeef,
		0xdeadbeef, 0xdeadbeef, 0xdeadbeef };
#define INPUT_DATA_2_SIZE 16
#define SECRET_MESSAGE "Hello World!"
#define SECRET_MESSAGE_LEN 12
uint8_t input_data2[INPUT_DATA_2_SIZE];
uint8_t encrypted_data2[INPUT_DATA_2_SIZE];
uint8_t decrypted_data2[INPUT_DATA_2_SIZE];
void Test_AES_ECB() {

	printf(
			"============= Testing 1 AES ECB 128 bit key ================== \n\r");

	hcryp.Instance = AES;
	hcryp.Init.DataType = CRYP_NO_SWAP;
	hcryp.Init.KeySize = CRYP_KEYSIZE_128B;
	hcryp.Init.pKey = (uint32_t*) pKeyAES;
	hcryp.Init.Algorithm = CRYP_AES_ECB;
	hcryp.Init.DataWidthUnit = CRYP_DATAWIDTHUNIT_WORD;
	hcryp.Init.KeyMode = CRYP_KEYMODE_NORMAL;
	if (HAL_CRYP_Init(&hcryp) != HAL_OK) {
		Error_Handler();
	}

	if (HAL_CRYP_Encrypt(&hcryp, (uint32_t*) input_data, sizeof(input_data),
			(uint32_t*) encrypted_data, 1000) != HAL_OK) {
		Error_Handler();
	}
	printf("Encrypted data: \n\r");
	for (int i = 0; i < 4; i++) {
		printf("0x%X\t", encrypted_data[i]);
	}
	printf("\n\r");
	if (HAL_CRYP_Decrypt(&hcryp, (uint32_t*) encrypted_data,
			sizeof(encrypted_data), (uint32_t*) decrypted_data, 1000)
			!= HAL_OK) {
		Error_Handler();
	}
	printf("Decrypted data: \n\r");
	for (int i = 0; i < 4; i++) {
		printf("0x%X\t", decrypted_data[i]);
	}
	printf("\n\r");
	printf(
			"============= Testing 2 AES ECB 128 bit key ================== \n\r");
	HAL_CRYP_DeInit(&hcryp);
	hcryp.Instance = AES;
	hcryp.Init.DataType = CRYP_BYTE_SWAP;
	hcryp.Init.KeySize = CRYP_KEYSIZE_128B;
	hcryp.Init.pKey = (uint32_t*) pKeyAES2;
	hcryp.Init.Algorithm = CRYP_AES_ECB;
	hcryp.Init.DataWidthUnit = CRYP_DATAWIDTHUNIT_BYTE;
	hcryp.Init.KeyMode = CRYP_KEYMODE_NORMAL;
	memset(input_data2, (INPUT_DATA_2_SIZE - SECRET_MESSAGE_LEN),
	INPUT_DATA_2_SIZE);
	memcpy(input_data2, SECRET_MESSAGE, SECRET_MESSAGE_LEN);
	if (HAL_CRYP_Init(&hcryp) != HAL_OK) {
		Error_Handler();
	}

	if (HAL_CRYP_Encrypt(&hcryp, (uint32_t*) input_data2, sizeof(input_data2),
			(uint32_t*) encrypted_data2, 1000) != HAL_OK) {
		Error_Handler();
	}
	printf("Encrypted data: \n\r"); //	5f9901a07619c4f782ddfb6db028f9ed

	printf("0x");
	for (int i = 0; i < 16; i++) {
		printf("%02X", encrypted_data2[i]);
	}
	printf("\n\r");
	if (HAL_CRYP_Decrypt(&hcryp, (uint32_t*) encrypted_data2,
			sizeof(encrypted_data2), (uint32_t*) decrypted_data2, 1000)
			!= HAL_OK) {
		Error_Handler();
	}
	printf("Decrypted data: \n\r");
	printf("0x");
	for (int i = 0; i < SECRET_MESSAGE_LEN; i++) {
		printf("%02X", decrypted_data2[i]);
	}
	printf("\n\r");
}
/* RSA modular exponent TEST  ---------------------------------------------------------*/
// we perform a encryption using public key
// we perform a decryption using private key
volatile uint8_t hal_pka_ErrorCallback = 0;
volatile uint8_t hal_pka_EndOfProcess = 0;


void HAL_PKA_ErrorCallback(PKA_HandleTypeDef *hpka) {
	hal_pka_ErrorCallback = 1;
	printf("pka operation error \n\r");

}
void HAL_PKA_OperationCpltCallback(PKA_HandleTypeDef *hpka) {
	hal_pka_EndOfProcess = 1;
	printf("pka operation completed \n\r");
}

#define RSA_LEN 256  // (2048/8)
const uint8_t public_exponent[3] = { 0x01, 0x00, 0x01 }; /* 65537 */
const uint8_t n[256] = { 0xe2, 0x9f, 0x82, 0x34, 0x03, 0x08, 0x25, 0x3b, 0x7b,
		0xe5, 0x73, 0xc3, 0x80, 0x9c, 0xb8, 0x2a, 0x99, 0x8c, 0x4d, 0xd2, 0x48,
		0xcf, 0x38, 0x2a, 0xa2, 0xd0, 0xa3, 0x65, 0x29, 0xc4, 0x13, 0x25, 0xbe,
		0xac, 0x3c, 0x1e, 0xd0, 0x0f, 0xf7, 0xf4, 0xdb, 0xab, 0x81, 0x59, 0x60,
		0x3f, 0x82, 0x98, 0x1b, 0xb8, 0x95, 0x45, 0x94, 0x05, 0xc6, 0x4e, 0xdc,
		0x66, 0x70, 0x3c, 0xc1, 0xd5, 0x4a, 0xbc, 0xa5, 0xfc, 0x0b, 0xbe, 0x5e,
		0x47, 0x0d, 0xaf, 0x44, 0xc1, 0xc7, 0x9a, 0x44, 0x4a, 0x08, 0xed, 0xfa,
		0x2a, 0xaa, 0xb3, 0x1a, 0x0c, 0xd6, 0x4a, 0x39, 0x7e, 0xdf, 0xf4, 0xa2,
		0xeb, 0x26, 0x5e, 0x78, 0x4e, 0x33, 0x0e, 0xba, 0x32, 0x8b, 0x91, 0x77,
		0x54, 0xb6, 0x05, 0x7b, 0x9d, 0x28, 0x82, 0x11, 0xfd, 0x9f, 0x6b, 0xd1,
		0x98, 0x1c, 0x33, 0xa4, 0xb5, 0x33, 0xf0, 0xbf, 0x64, 0x63, 0xd8, 0xdd,
		0x38, 0x69, 0x6e, 0x04, 0x78, 0x6f, 0xc2, 0xb1, 0xec, 0xb7, 0x56, 0xab,
		0xa8, 0xdb, 0x23, 0x7d, 0x63, 0xc5, 0x93, 0x33, 0xb2, 0x84, 0xe4, 0x93,
		0x1f, 0x6e, 0xc2, 0xf3, 0xe5, 0xa2, 0x03, 0x00, 0xa4, 0x55, 0xab, 0x39,
		0x5d, 0x7a, 0xd6, 0x7e, 0x68, 0x0c, 0xba, 0x32, 0x78, 0xb2, 0xbd, 0xf5,
		0x5d, 0x90, 0x43, 0x80, 0xb3, 0x31, 0x66, 0xc9, 0xcd, 0x60, 0xa4, 0x8d,
		0x1a, 0x25, 0xbc, 0x69, 0x85, 0x25, 0x61, 0x27, 0xe5, 0x35, 0x7d, 0x6a,
		0xdc, 0x74, 0x37, 0x88, 0x4a, 0x51, 0x20, 0x00, 0x8e, 0x80, 0x64, 0x8d,
		0xee, 0x7f, 0x48, 0x81, 0xae, 0x95, 0xbf, 0x05, 0x46, 0xe9, 0x5b, 0xca,
		0x9a, 0x94, 0xd3, 0x78, 0xd8, 0x4a, 0x1e, 0xbb, 0x01, 0x16, 0x90, 0x12,
		0x29, 0x6f, 0xfc, 0xe1, 0x44, 0x81, 0xa8, 0x16, 0x97, 0xb0, 0x4d, 0x26,
		0xa1, 0xdb, 0x35, 0xb9, 0x08, 0xb3, 0x6d };
const uint8_t private_exponent[] = { 0x42, 0x4F, 0xAB, 0x31, 0x1D, 0xEB, 0xFD,
		0xBD, 0x04, 0x99, 0x54, 0xC0, 0xD1, 0x7A, 0xCA, 0x16, 0xC8, 0xFC, 0x39,
		0x6F, 0x3D, 0x17, 0xC9, 0x57, 0x0C, 0x72, 0x21, 0x45, 0x82, 0x2D, 0x99,
		0xEE, 0xB2, 0xF6, 0xC1, 0xD6, 0xC0, 0x49, 0xD3, 0xE3, 0xA5, 0x7D, 0x6F,
		0x29, 0x60, 0x54, 0xE5, 0x19, 0x2E, 0x0F, 0x5A, 0x3A, 0x54, 0x40, 0x46,
		0x51, 0x20, 0x03, 0xA7, 0x76, 0xD7, 0xBE, 0xDA, 0x12, 0x0E, 0x3D, 0x8C,
		0x90, 0x25, 0x15, 0x04, 0x67, 0x93, 0x26, 0x62, 0x89, 0xFC, 0xCE, 0x6F,
		0x03, 0x77, 0x6E, 0x91, 0xA9, 0x3B, 0x87, 0xA3, 0x12, 0x6F, 0xF5, 0x74,
		0x81, 0xA8, 0x44, 0x47, 0x63, 0x60, 0x2F, 0x7D, 0x98, 0x23, 0x1A, 0x94,
		0x25, 0x39, 0xF6, 0x23, 0x16, 0xC2, 0x9F, 0x6F, 0x51, 0x74, 0x03, 0x32,
		0xE9, 0x41, 0x18, 0x91, 0xB3, 0xF8, 0xCF, 0x7E, 0xC5, 0xC4, 0xB3, 0x12,
		0xD5, 0xBE, 0x69, 0x61, 0x92, 0x21, 0x6B, 0x0E, 0x2C, 0xD7, 0x0A, 0x36,
		0x1D, 0xBD, 0x16, 0x4F, 0xAC, 0x4C, 0x12, 0x20, 0xB8, 0x3D, 0x27, 0x49,
		0x24, 0x26, 0x29, 0x56, 0x9E, 0xA3, 0xC7, 0x33, 0x76, 0x30, 0xFA, 0xB3,
		0x7B, 0x64, 0x5D, 0x5E, 0x90, 0x1D, 0xF0, 0x27, 0x2E, 0x55, 0x26, 0x0C,
		0x7D, 0x3D, 0xD6, 0xA0, 0x1F, 0xD0, 0xC9, 0xC7, 0x27, 0x6C, 0x82, 0xF0,
		0xFE, 0xD8, 0x04, 0xBB, 0x9E, 0xF1, 0xEB, 0x3A, 0xC2, 0x1B, 0xAE, 0xA9,
		0xBE, 0x60, 0x83, 0x6C, 0x1F, 0xAC, 0x51, 0x08, 0xA2, 0x1A, 0x19, 0x1D,
		0x29, 0x50, 0x33, 0x85, 0x04, 0x31, 0xD4, 0x12, 0x13, 0xFC, 0xF7, 0xE0,
		0xD6, 0x54, 0x7C, 0xA4, 0xAE, 0x7A, 0x21, 0x91, 0x10, 0x83, 0xAB, 0x4E,
		0x05, 0x38, 0x67, 0x1D, 0x68, 0x72, 0xD8, 0x75, 0xD7, 0x5B, 0x0E, 0xA1,
		0x96, 0x16, 0x3B, 0xFC, 0xF9, 0x8D, 0xB1, 0x01, 0x5F, };

#define RSA_MESSAGE "Hello World!"
#define RSA_MESSAGE_LEN 12
static uint8_t message[256];
__ALIGN_BEGIN static uint8_t rsa_c[RSA_LEN] __ALIGN_END;
__ALIGN_BEGIN static uint8_t rsa_d[RSA_LEN] __ALIGN_END;

void Test_RSA_Modular_exponent() {
	hpka.Instance = PKA;
	if (HAL_PKA_Init(&hpka) != HAL_OK) {
		Error_Handler();
	}
	memset(message, 0, 256);
	memcpy(&message[256 - RSA_MESSAGE_LEN], RSA_MESSAGE, RSA_MESSAGE_LEN);

	PKA_ModExpInTypeDef in = { 0 };
	printf("===== PKA: RSA-2048  =====\n\r");
	in.expSize = sizeof(public_exponent);
	in.OpSize = sizeof(message);
	in.pExp = public_exponent;
	in.pMod = n;
	in.pOp1 = message;
	HAL_PKA_ModExp_IT(&hpka, &in);
	while (hal_pka_EndOfProcess == 0) {

	}
	hal_pka_EndOfProcess = 0;
	HAL_PKA_ModExp_GetResult(&hpka, rsa_c);
	printf("Cipher RSA: \n\r");
	for (int i = 0; i < RSA_LEN; i++) {
		printf("%02X", rsa_c[i]);
	}
	fflush(0);
	printf("\n\r");
	// Decryption

	in.expSize = sizeof(private_exponent);
	in.OpSize = sizeof(rsa_c);
	in.pExp = private_exponent;
	in.pMod = n;
	in.pOp1 = rsa_c;
	HAL_PKA_ModExp_IT(&hpka, &in);
	while (hal_pka_EndOfProcess == 0) {

	}
	hal_pka_EndOfProcess = 0;
	HAL_PKA_ModExp_GetResult(&hpka, rsa_d);
	printf("Decryption RSA: \n\r");
	for (int i = 0; i < RSA_LEN; i++) {
		printf("%02X", rsa_d[i]);
	}
	fflush(0);
	printf("\n\r");
	printf("=> %s\n\r", rsa_d);
}
/* Hash-256------------------------------- */

volatile uint8_t hal_hash_EndOfProcess = 0;
void HAL_HASH_ErrorCallback(HASH_HandleTypeDef *hhash){
	printf("hash operation error \n\r");
}
void HAL_HASH_DgstCpltCallback(HASH_HandleTypeDef *hhash){
	hal_hash_EndOfProcess = 1;
	printf("hash operation complete \n\r");

}
uint8_t msg_to_hash[] = "Hello World!";
#define HASH_LEN 32
uint8_t hash[HASH_LEN];
void test_hash256(){
	printf(
			"============= Testing SHA256 ================== \n\r");
	if (HAL_HASHEx_SHA256_Start_IT(&hhash, (uint8_t*) msg_to_hash, strlen(msg_to_hash),
			hash) != HAL_OK) {
		printf("hash error \n\r");
	}
	while (hal_hash_EndOfProcess == 0) {
	}
//	HAL_HASHEx_SHA256_Finish(&hhash, msghash, 0xFF);
	hal_hash_EndOfProcess =0  ;
	printf("Message HASH \n\r");
	for (int i = 0; i < HASH_LEN; i++) {
		printf("%02X", hash[i]);
	}
	printf("\n\r");
// HMAC Testing
}

/* ECC Key Gen ------------------------------- */

#define EC_LEN 32
#define EC_COEF_SIGN 1  /* 1 = a is negative */

static const uint8_t P256_p[32] = { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, };

static const uint8_t P256_a_abs[32] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x03, };

static const uint8_t P256_b[32] = { 0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93,
		0xE7, 0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC, 0x65, 0x1D, 0x06,
		0xB0, 0xCC, 0x53, 0xB0, 0xF6, 0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60,
		0x4B, };

static const uint8_t P256_n[32] = { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00,
		0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA,
		0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25,
		0x51, };

static const uint8_t P256_Gx[32] = { 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42,
		0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D,
		0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2,
		0x96, };

static const uint8_t P256_Gy[32] = { 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F,
		0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33,
		0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51,
		0xF5, };
__ALIGN_BEGIN uint8_t d[EC_LEN] __ALIGN_END;
__ALIGN_BEGIN uint8_t Qx[EC_LEN] __ALIGN_END;
__ALIGN_BEGIN uint8_t Qy[EC_LEN] __ALIGN_END;
void ECC_PKA_key_gen() {
	printf("===== PKA: ECC P-256 key pair =====\n\r");
	if (HAL_PKA_Init(&hpka) != HAL_OK)
		Error_Handler();
	for (int i = 0; i < 32; i += 4) {
		uint32_t r;
		if (HAL_RNG_GenerateRandomNumber(&hrng, &r) != HAL_OK) {
			printf("HAL RNG Error \n\r");
		}
		d[i + 0] = r >> 24;
		d[i + 1] = r >> 16;
		d[i + 2] = r >> 8;
		d[i + 3] = r;
	}
	printf("private number:  \n\r");
	for (int i = 0; i < EC_LEN; i++) {
		printf("%02X", d[i]);
	}
	fflush(0);
	printf("\n\r");
	PKA_ECCMulInTypeDef in = { 0 };
	PKA_ECCMulOutTypeDef out = { 0 };
	in.scalarMulSize = EC_LEN;
	in.modulusSize = EC_LEN;
	in.scalarMul = d;
	in.modulus = P256_p;
	in.coefSign = EC_COEF_SIGN;
	in.coefA = P256_a_abs;
	in.coefB = P256_b;
	in.pointX = P256_Gx;
	in.pointY = P256_Gy;
	in.primeOrder = P256_n;

	out.ptX = Qx;
	out.ptY = Qy;

	HAL_PKA_ECCMul_IT(&hpka, &in);
	while (hal_pka_EndOfProcess == 0) {
	}
	HAL_PKA_ECCMul_GetResult(&hpka, &out);
	hal_pka_EndOfProcess = 0;
	printf("Public number Qx:  \n\r");
	for (int i = 0; i < EC_LEN; i++) {
		printf("%02X", Qx[i]);
	}
	fflush(0);
	printf("\n\r");
	printf("Public number Qy:  \n\r");
	for (int i = 0; i < EC_LEN; i++) {
		printf("%02X", Qy[i]);
	}
	fflush(0);
	printf("\n\r");

}
#define MSG_LEN 12
uint8_t msg_to_send[] = "Hello World!";
uint8_t msghash[32];
__ALIGN_BEGIN uint8_t R[EC_LEN] __ALIGN_END;
__ALIGN_BEGIN uint8_t S[EC_LEN] __ALIGN_END;
__ALIGN_BEGIN uint8_t k[EC_LEN] __ALIGN_END;

void ECC_DSA_test() {
// 1- calculate SHA-256
	printf("===== PKA: ECC DSA =====\n\r");

	if (HAL_HASHEx_SHA256_Start_IT(&hhash, (uint8_t*) msg_to_send, MSG_LEN,
			msghash) != HAL_OK) {
		printf("hash error \n\r");
	}
	while (hal_hash_EndOfProcess == 0) {
	}
//	HAL_HASHEx_SHA256_Finish(&hhash, msghash, 0xFF);
	hal_hash_EndOfProcess =0  ;
	printf("Message HASH \n\r");
	for (int i = 0; i < EC_LEN; i++) {
		printf("%02X", msghash[i]);
	}
	printf("\n\r");

	for (int i = 0; i < 32; i += 4) {
		uint32_t r;
		if (HAL_RNG_GenerateRandomNumber(&hrng, &r) != HAL_OK) {
			printf("HAL RNG Error \n\r");
		}
		k[i + 0] = r >> 24;
		k[i + 1] = r >> 16;
		k[i + 2] = r >> 8;
		k[i + 3] = r;
	}
	PKA_ECDSASignInTypeDef sin = { 0 };
	PKA_ECDSASignOutTypeDef sout = { 0 };
	sin.primeOrderSize = EC_LEN;
	sin.modulusSize = EC_LEN;
	sin.coefSign = 1;
	sin.coef = P256_a_abs;
	sin.coefB = P256_b;
	sin.modulus = P256_p;
	sin.primeOrder = P256_n;
	sin.integer = k;
	sin.basePointX = P256_Gx;
	sin.basePointY = P256_Gy;

	sin.hash = msghash;
	sin.privateKey = d;

	sout.RSign = R;
	sout.SSign = S;
	HAL_PKA_ECDSASign_IT(&hpka, &sin);
	while (hal_pka_EndOfProcess == 0) {
	}
	HAL_PKA_ECDSASign_GetResult(&hpka, &sout, NULL);
	hal_pka_EndOfProcess = 0;
	printf("Signature S:  \n\r");
	for (int i = 0; i < EC_LEN; i++) {
		printf("%02X", S[i]);
	}
	printf("\n\r");

	printf("Signature R:  \n\r");
	for (int i = 0; i < EC_LEN; i++) {
		printf("%02X", R[i]);
	}
	printf("\n\r");
	PKA_ECDSAVerifInTypeDef vin = { 0 };
	vin.primeOrderSize = EC_LEN;
	vin.modulus = P256_p;
	vin.coefSign = EC_COEF_SIGN;
	vin.coef = P256_a_abs;
	vin.basePointX = P256_Gx;
	vin.basePointX = P256_Gy;
	vin.pPubKeyCurvePtX = Qx;
	vin.pPubKeyCurvePtY = Qx;
	vin.RSign = R;
	vin.SSign = S;
	vin.hash = msghash;
	vin.primeOrder = P256_n;
	HAL_PKA_ECDSAVerif_IT(&hpka, &vin);
	while (hal_pka_EndOfProcess == 0) {
	}
	hal_pka_EndOfProcess = 0;
	if (HAL_PKA_ECDSAVerif_IsValidSignature(&hpka) == HAL_OK) {
		printf("Signature  is valid \n\r");
	} else {
		printf("Signature  is not valid \n\r");
	}

	printf("testing tampered signature \n\r");
	msghash[0] ^= 1;
	while (hal_pka_EndOfProcess == 0) {
	}
	hal_pka_EndOfProcess = 0;
	if (HAL_PKA_ECDSAVerif_IsValidSignature(&hpka) == HAL_OK) {
		printf("Signature  is valid \n\r");
	} else {
		printf("Signature  is not valid \n\r");
	}

}
/* Testing CryptoLib --------------------------------------------------*/

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_AES_Init();
  MX_HASH_Init();
  MX_RNG_Init();
  MX_PKA_Init();
  MX_USART1_UART_Init();
  /* USER CODE BEGIN 2 */

// Symmertric Encryption AES
// 1 - AES-ECB
// 2- AES-GCM
// RNG Generation
// 1- Generate a 32bit random number
// Asymmertric Encryption
// 1- RSA && key pair generation.
// 2- EC-DH
// 3- EC-DSA
// HASHING
// 1- SHA-256
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
	printf("hello Crypto world ... \n\r");
	Test_AES_ECB();
	Test_RSA_Modular_exponent();
	ECC_PKA_key_gen();
	ECC_DSA_test();
	while (1) {
//
//		printf("hello Crypto world ... \n\r");
//		HAL_Delay(1000);

    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
	}
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  if (HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI48|RCC_OSCILLATORTYPE_MSI;
  RCC_OscInitStruct.HSI48State = RCC_HSI48_ON;
  RCC_OscInitStruct.MSIState = RCC_MSI_ON;
  RCC_OscInitStruct.MSICalibrationValue = RCC_MSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.MSIClockRange = RCC_MSIRANGE_4;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_MSI;
  RCC_OscInitStruct.PLL.PLLMBOOST = RCC_PLLMBOOST_DIV1;
  RCC_OscInitStruct.PLL.PLLM = 1;
  RCC_OscInitStruct.PLL.PLLN = 80;
  RCC_OscInitStruct.PLL.PLLP = 2;
  RCC_OscInitStruct.PLL.PLLQ = 2;
  RCC_OscInitStruct.PLL.PLLR = 2;
  RCC_OscInitStruct.PLL.PLLRGE = RCC_PLLVCIRANGE_0;
  RCC_OscInitStruct.PLL.PLLFRACN = 0;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2
                              |RCC_CLOCKTYPE_PCLK3;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB3CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_4) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief AES Initialization Function
  * @param None
  * @retval None
  */
static void MX_AES_Init(void)
{

  /* USER CODE BEGIN AES_Init 0 */
//
  /* USER CODE END AES_Init 0 */

  /* USER CODE BEGIN AES_Init 1 */
//
  /* USER CODE END AES_Init 1 */
  hcryp.Instance = AES;
  hcryp.Init.DataType = CRYP_NO_SWAP;
  hcryp.Init.KeySize = CRYP_KEYSIZE_128B;
  hcryp.Init.pKey = (uint32_t *)pKeyAES;
  hcryp.Init.Algorithm = CRYP_AES_ECB;
  hcryp.Init.DataWidthUnit = CRYP_DATAWIDTHUNIT_WORD;
  hcryp.Init.HeaderWidthUnit = CRYP_HEADERWIDTHUNIT_WORD;
  hcryp.Init.KeyIVConfigSkip = CRYP_KEYIVCONFIG_ALWAYS;
  hcryp.Init.KeyMode = CRYP_KEYMODE_NORMAL;
  if (HAL_CRYP_Init(&hcryp) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN AES_Init 2 */
//
  /* USER CODE END AES_Init 2 */

}

/**
  * @brief HASH Initialization Function
  * @param None
  * @retval None
  */
static void MX_HASH_Init(void)
{

  /* USER CODE BEGIN HASH_Init 0 */

  /* USER CODE END HASH_Init 0 */

  /* USER CODE BEGIN HASH_Init 1 */

  /* USER CODE END HASH_Init 1 */
  hhash.Init.DataType = HASH_DATATYPE_8B;
  if (HAL_HASH_Init(&hhash) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN HASH_Init 2 */

  /* USER CODE END HASH_Init 2 */

}

/**
  * @brief PKA Initialization Function
  * @param None
  * @retval None
  */
static void MX_PKA_Init(void)
{

  /* USER CODE BEGIN PKA_Init 0 */

  /* USER CODE END PKA_Init 0 */

  /* USER CODE BEGIN PKA_Init 1 */

  /* USER CODE END PKA_Init 1 */
  hpka.Instance = PKA;
  if (HAL_PKA_Init(&hpka) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN PKA_Init 2 */

  /* USER CODE END PKA_Init 2 */

}

/**
  * @brief RNG Initialization Function
  * @param None
  * @retval None
  */
static void MX_RNG_Init(void)
{

  /* USER CODE BEGIN RNG_Init 0 */

  /* USER CODE END RNG_Init 0 */

  /* USER CODE BEGIN RNG_Init 1 */

  /* USER CODE END RNG_Init 1 */
  hrng.Instance = RNG;
  hrng.Init.ClockErrorDetection = RNG_CED_ENABLE;
  if (HAL_RNG_Init(&hrng) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN RNG_Init 2 */

  /* USER CODE END RNG_Init 2 */

}

/**
  * @brief USART1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART1_UART_Init(void)
{

  /* USER CODE BEGIN USART1_Init 0 */

  /* USER CODE END USART1_Init 0 */

  /* USER CODE BEGIN USART1_Init 1 */

  /* USER CODE END USART1_Init 1 */
  huart1.Instance = USART1;
  huart1.Init.BaudRate = 115200;
  huart1.Init.WordLength = UART_WORDLENGTH_8B;
  huart1.Init.StopBits = UART_STOPBITS_1;
  huart1.Init.Parity = UART_PARITY_NONE;
  huart1.Init.Mode = UART_MODE_TX_RX;
  huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart1.Init.OverSampling = UART_OVERSAMPLING_16;
  huart1.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart1.Init.ClockPrescaler = UART_PRESCALER_DIV1;
  huart1.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_UART_Init(&huart1) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_SetTxFifoThreshold(&huart1, UART_TXFIFO_THRESHOLD_1_8) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_SetRxFifoThreshold(&huart1, UART_RXFIFO_THRESHOLD_1_8) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_DisableFifoMode(&huart1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART1_Init 2 */

  /* USER CODE END USART1_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  /* USER CODE BEGIN MX_GPIO_Init_1 */

  /* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOA_CLK_ENABLE();

  /* USER CODE BEGIN MX_GPIO_Init_2 */

  /* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @param None
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
	/* User can add his own implementation to report the HAL error return state */
	__disable_irq();
	while (1) {
	}
  /* USER CODE END Error_Handler_Debug */
}
#ifdef USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
