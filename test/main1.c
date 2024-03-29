/*************************************************************************
        > File Name: main1.c
        > Author:ljm
        > Mail:
        > Created Time: 2024年04月26日 星期四 16时01分52秒
 ************************************************************************/

#include "../include/sdf.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
//基础密钥
#define ROOTKEY                                                                \
  "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"
#define DEVSN "besti_0000000000001"//设备序列号
#define MAX (4000)
//#define MAX (1536)
#define LOOP (1000)

//ECC公钥未加密
SGD_UCHAR pubKey[64] = {
    0x8B, 0x7F, 0xB9, 0x6C, 0x09, 0x53, 0x27, 0x19, 0xE4, 0xEB, 0x79,
    0x16, 0xC6, 0x2E, 0x20, 0xEA, 0x33, 0xCC, 0x98, 0x96, 0x43, 0xFA,
    0x45, 0x09, 0x0C, 0x98, 0x4E, 0xA5, 0xDF, 0x76, 0xA1, 0xD4, 0xC1,
    0xF8, 0x9C, 0x46, 0x67, 0x61, 0xCE, 0x07, 0x83, 0x26, 0xAF, 0x1C,
    0xA0, 0x81, 0xC5, 0x89, 0x4E, 0x0C, 0xD5, 0x29, 0x88, 0x40, 0x96,
    0x45, 0x50, 0xD9, 0x14, 0x17, 0xB7, 0x5C, 0xC5, 0x5E};

//ECC私钥未加密
SGD_UCHAR priKey[32] = {0x08, 0x3B, 0xD8, 0xEA, 0xC2, 0x20, 0xE8, 0xC5,
                        0x98, 0x89, 0x83, 0xB4, 0x3E, 0x07, 0x13, 0x67,
                        0xE3, 0x0C, 0x02, 0xCE, 0xA8, 0xB9, 0x19, 0x19,
                        0xDD, 0x7F, 0xE8, 0xB8, 0xE6, 0xDC, 0x02, 0x5B};

//ECC公钥加密
SGD_UCHAR pubKeyEnc[64] = {
    0x19, 0x0e, 0x9e, 0x10, 0x5a, 0x12, 0xd5, 0x9b, 0xd5, 0x59, 0x5d,
    0x7d, 0x06, 0xbe, 0xe0, 0x1b, 0x15, 0x44, 0xcc, 0x16, 0x1a, 0x34,
    0xcc, 0x36, 0xe0, 0xbd, 0xa6, 0x83, 0x03, 0x97, 0xb5, 0x2e, 0x7f,
    0xb5, 0x1a, 0xf6, 0x0e, 0xf9, 0xb7, 0x00, 0x88, 0x21, 0xdd, 0xda,
    0xca, 0x2a, 0x18, 0xe9, 0x57, 0x49, 0xce, 0x49, 0xdc, 0x5f, 0xb9,
    0x4d, 0xb8, 0xc8, 0x5c, 0xde, 0x96, 0xfb, 0x2b, 0x39,
};

//ECC私钥加密
SGD_UCHAR priKeyEnc[32] = {0x3a, 0x7e, 0xff, 0x53, 0x3d, 0x23, 0xd1, 0x3a,
                           0xde, 0x97, 0x4b, 0xc3, 0x65, 0x3c, 0xd1, 0x43,
                           0x20, 0x31, 0x98, 0xe4, 0x48, 0x7f, 0x5b, 0xc0,
                           0x01, 0xd7, 0xe9, 0x5e, 0x20, 0xfc, 0xa1, 0xc5};

SGD_UCHAR eccXYD[96] = {
    0x19, 0x0e, 0x9e, 0x10, 0x5a, 0x12, 0xd5, 0x9b, 0xd5, 0x59, 0x5d, 0x7d,
    0x06, 0xbe, 0xe0, 0x1b, 0x15, 0x44, 0xcc, 0x16, 0x1a, 0x34, 0xcc, 0x36,
    0xe0, 0xbd, 0xa6, 0x83, 0x03, 0x97, 0xb5, 0x2e, 0x7f, 0xb5, 0x1a, 0xf6,
    0x0e, 0xf9, 0xb7, 0x00, 0x88, 0x21, 0xdd, 0xda, 0xca, 0x2a, 0x18, 0xe9,
    0x57, 0x49, 0xce, 0x49, 0xdc, 0x5f, 0xb9, 0x4d, 0xb8, 0xc8, 0x5c, 0xde,
    0x96, 0xfb, 0x2b, 0x39, 0x3a, 0x7e, 0xff, 0x53, 0x3d, 0x23, 0xd1, 0x3a,
    0xde, 0x97, 0x4b, 0xc3, 0x65, 0x3c, 0xd1, 0x43, 0x20, 0x31, 0x98, 0xe4,
    0x48, 0x7f, 0x5b, 0xc0, 0x01, 0xd7, 0xe9, 0x5e, 0x20, 0xfc, 0xa1, 0xc5,
};

//eccXYD数据的哈希值
SGD_UCHAR eccXYDHash[32] = {0x2D, 0xEA, 0x71, 0x6F, 0x3C, 0x66, 0x21, 0xB8,
                            0xE8, 0x44, 0xF6, 0x49, 0x9F, 0xED, 0x44, 0x27,
                            0x21, 0x06, 0x76, 0xF7, 0xFC, 0xB7, 0xEB, 0x59,
                            0x09, 0x25, 0x6C, 0xB0, 0x47, 0xBC, 0xC7, 0x4E};

//存储哈希运算的结果
SGD_UINT8 sm3HashData[32];

void myprintf(SGD_UCHAR *pucData, SGD_UINT32 uiDataLen) {
  int i = 0;
  for (i = 0; i < uiDataLen; i++) {
    if (i != 0 && i % 4 == 0)
      printf(" ");
    if (i != 0 && i % 32 == 0)
      printf("\n");
    printf("%02x", pucData[i]);
  }
  printf("\n");
}

SGD_RV EccBackUpKeyPair(SGD_HANDLE phSessionHandle) {
  SGD_RV rv = SDR_OK;
  SGD_UCHAR eccKeyPair[2048] = {0};
  SGD_UINT32 eccKeyPairLen = 2048;
  rv = SDF_ECCBackUp(phSessionHandle, 1, eccKeyPair, &eccKeyPairLen);
  if (SDR_OK != rv) {
    printf("Ecc Back Up failed --- \n");
  }
  return rv;
}

SGD_RV ImportKeyPair(SGD_HANDLE phSessionHandle) {
  SGD_RV rv = SDR_OK;
  SGD_UCHAR eccKeyPairEnc[96] = {0};
  SGD_UINT32 eccKeyPairLen = 96;
  memcpy(eccKeyPairEnc, pubKeyEnc, 64);
  memcpy(eccKeyPairEnc + 64, priKeyEnc, 32);
  rv = SDF_ImportECCKeyPair(phSessionHandle, 1,
                            (const SGD_UCHAR *)eccKeyPairEnc);
  if (SDR_OK != rv) {
    return rv;
  }
  return rv;
}

SGD_RV SM1_ENC_DEC_ECB(SGD_HANDLE phSessionHandle, SGD_HANDLE phKeyHandle) {

  SGD_RV rv = SDR_OK;
  int loop = LOOP, i = 0;
  SGD_UCHAR pucIV[16] = {0};
  memset(pucIV, 1, 16);
  SGD_UCHAR *pucData = (SGD_UCHAR *)malloc(loop * MAX);
  SGD_UINT32 uiDataLength = loop * MAX;
  SGD_UCHAR *pucEncData = (SGD_UCHAR *)malloc(loop * MAX);
  SGD_UINT32 puiEncDataLength = loop * MAX;
  SGD_UCHAR pucKey[16];
  memset(pucKey, 2, 16);

  for (i = 0; i < loop * MAX; i++) {
    pucData[i] = i % 256;
  }

  unsigned long long L1, L2, L3, L4;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  L1 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;

  for (i = 0; i < loop; i++) {
    rv = SDF_Encrypt(phSessionHandle, pucKey, SGD_SM1_ECB, pucIV,
                     &pucData[i * MAX], MAX, &pucEncData[i * MAX],
                     &puiEncDataLength);
    if (SDR_OK != rv) {
      free(pucData);
      free(pucEncData);
      return rv;
    }
  }
  gettimeofday(&tv, NULL);
  L2 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
  printf("SGD_SM1_ECB Encrypt datasize: %d Bytes used time: %lld us\n",
         loop * MAX, L2 - L1);
  printf("SGD_SM1_ECB Encrypt average speed: %d bps\n",
         (int)((long long)MAX * loop * 8 * 1000000 / (L2 - L1)));

  SGD_UCHAR *pucTmpData = (SGD_UCHAR *)malloc(loop * MAX);
  memset(pucIV, 1, 16);
  gettimeofday(&tv, NULL);
  L3 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
  for (i = 0; i < loop; i++) {
    rv = SDF_Decrypt(phSessionHandle, pucKey, SGD_SM1_ECB, pucIV,
                     &pucEncData[i * MAX], MAX, &pucTmpData[i * MAX],
                     &puiEncDataLength);
    if (SDR_OK != rv) {
      free(pucData);
      free(pucEncData);
      free(pucTmpData);
      return rv;
    }
  }
  gettimeofday(&tv, NULL);
  L4 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;

  printf("SGD_SM1_ECB Decrypt datasize: %d Bytes used time: %lld us\n",
         loop * MAX, L4 - L3);
  printf("SGD_SM1_ECB Decrypt average speed: %d bps\n",
         (int)((long long)MAX * loop * 8 * 1000000 / (L4 - L3)));

  if (memcmp(pucData, pucTmpData, loop * MAX)) {
    free(pucData);
    free(pucEncData);
    free(pucTmpData);
    printf("memcmp    diff\n");
    return -1;
  }

  free(pucData);
  free(pucEncData);
  free(pucTmpData);
  return SDR_OK;
}
SGD_RV SM1_ENC_DEC_CBC(SGD_HANDLE phSessionHandle, SGD_HANDLE phKeyHandle) {

  SGD_RV rv = SDR_OK;
  int loop = LOOP, i = 0;
  SGD_UCHAR pucIV[16] = {0};
  memset(pucIV, 1, 16);
  SGD_UCHAR *pucData = (SGD_UCHAR *)malloc(loop * MAX);
  SGD_UINT32 uiDataLength = loop * MAX;
  SGD_UCHAR *pucEncData = (SGD_UCHAR *)malloc(loop * MAX);
  SGD_UINT32 puiEncDataLength = loop * MAX;
  SGD_UCHAR pucKey[16];
  memset(pucKey, 2, 16);

  for (i = 0; i < loop * MAX; i++) {
    pucData[i] = i % 256;
  }

  unsigned long long L1, L2, L3, L4;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  L1 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;

  for (i = 0; i < loop; i++) {
    rv = SDF_Encrypt(phSessionHandle, pucKey, SGD_SM1_CBC, pucIV,
                     &pucData[i * MAX], MAX, &pucEncData[i * MAX],
                     &puiEncDataLength);
    if (SDR_OK != rv) {
      free(pucData);
      free(pucEncData);
      return rv;
    }
  }
  gettimeofday(&tv, NULL);
  L2 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
  printf("SGD_SM1_CBC Encrypt datasize: %d Bytes used time: %lld us\n",
         loop * MAX, L2 - L1);
  printf("SGD_SM1_CBC Encrypt average speed: %d bps\n",
         (int)((long long)MAX * loop * 8 * 1000000 / (L2 - L1)));

  SGD_UCHAR *pucTmpData = (SGD_UCHAR *)malloc(loop * MAX);
  memset(pucIV, 1, 16);
  gettimeofday(&tv, NULL);
  L3 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
  for (i = 0; i < loop; i++) {
    rv = SDF_Decrypt(phSessionHandle, pucKey, SGD_SM1_CBC, pucIV,
                     &pucEncData[i * MAX], MAX, &pucTmpData[i * MAX],
                     &puiEncDataLength);
    if (SDR_OK != rv) {
      free(pucData);
      free(pucEncData);
      free(pucTmpData);
      return rv;
    }
  }
  gettimeofday(&tv, NULL);
  L4 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;

  printf("SGD_SM1_CBC Decrypt datasize: %d Bytes used time: %lld us\n",
         loop * MAX, L4 - L3);
  printf("SGD_SM1_CBC Decrypt average speed: %d bps\n",
         (int)((long long)MAX * loop * 8 * 1000000 / (L4 - L3)));

  if (memcmp(pucData, pucTmpData, loop * MAX)) {
    free(pucData);
    free(pucEncData);
    free(pucTmpData);
    printf("memcmp    diff\n");
    return -1;
  }

  free(pucData);
  free(pucEncData);
  free(pucTmpData);
  return SDR_OK;
}

SGD_RV SM1_ENC_DEC_OFB(SGD_HANDLE phSessionHandle, SGD_HANDLE phKeyHandle) {

  SGD_RV rv = SDR_OK;
  int loop = LOOP, i = 0;
  SGD_UCHAR pucIV[16] = {0};
  memset(pucIV, 1, 16);
  SGD_UCHAR *pucData = (SGD_UCHAR *)malloc(loop * MAX);
  SGD_UINT32 uiDataLength = loop * MAX;
  SGD_UCHAR *pucEncData = (SGD_UCHAR *)malloc(loop * MAX);
  SGD_UINT32 puiEncDataLength = loop * MAX;
  SGD_UCHAR pucKey[16];
  memset(pucKey, 2, 16);

  for (i = 0; i < loop * MAX; i++) {
    pucData[i] = i % 256;
  }

  unsigned long long L1, L2, L3, L4;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  L1 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;

  for (i = 0; i < loop; i++) {
    rv = SDF_Encrypt(phSessionHandle, pucKey, SGD_SM1_OFB, pucIV,
                     &pucData[i * MAX], MAX, &pucEncData[i * MAX],
                     &puiEncDataLength);
    if (SDR_OK != rv) {
      free(pucData);
      free(pucEncData);
      return rv;
    }
  }
  gettimeofday(&tv, NULL);
  L2 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
  printf("SGD_SM1_OFB Encrypt datasize: %d Bytes used time: %lld us\n",
         loop * MAX, L2 - L1);
  printf("SGD_SM1_OFB Encrypt average speed: %d bps\n",
         (int)((long long)MAX * loop * 8 * 1000000 / (L2 - L1)));

  SGD_UCHAR *pucTmpData = (SGD_UCHAR *)malloc(loop * MAX);
  memset(pucIV, 1, 16);
  gettimeofday(&tv, NULL);
  L3 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
  for (i = 0; i < loop; i++) {
    rv = SDF_Decrypt(phSessionHandle, pucKey, SGD_SM1_OFB, pucIV,
                     &pucEncData[i * MAX], MAX, &pucTmpData[i * MAX],
                     &puiEncDataLength);
    if (SDR_OK != rv) {
      free(pucData);
      free(pucEncData);
      free(pucTmpData);
      return rv;
    }
  }
  gettimeofday(&tv, NULL);
  L4 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;

  printf("SGD_SM1_OFB Decrypt datasize: %d Bytes used time: %lld us\n",
         loop * MAX, L4 - L3);
  printf("SGD_SM1_OFB Decrypt average speed: %d bps\n",
         (int)((long long)MAX * loop * 8 * 1000000 / (L4 - L3)));

  if (memcmp(pucData, pucTmpData, loop * MAX)) {
    free(pucData);
    free(pucEncData);
    free(pucTmpData);
    printf("memcmp    diff\n");
    return -1;
  }

  free(pucData);
  free(pucEncData);
  free(pucTmpData);
  return SDR_OK;
}
SGD_RV SM4_ENC_DEC_ECB(SGD_HANDLE phSessionHandle, SGD_HANDLE phKeyHandle) {

  SGD_RV rv = SDR_OK;
  int loop = LOOP, i = 0;
  SGD_UCHAR pucIV[16] = {0};
  memset(pucIV, 1, 16);
  SGD_UCHAR *pucData = (SGD_UCHAR *)malloc(loop * MAX);
  SGD_UINT32 uiDataLength = loop * MAX;
  SGD_UCHAR *pucEncData = (SGD_UCHAR *)malloc(loop * MAX);
  SGD_UINT32 puiEncDataLength = loop * MAX;
  SGD_UCHAR pucKey[16];
  memset(pucKey, 2, 16);
  int count = loop;

  for (i = 0; i < loop * MAX; i++) {
    pucData[i] = i % 256;
  }

  unsigned long long L1, L2, L3, L4;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  L1 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;

  for (i = 0; i < loop; i++) {
    rv = SDF_Encrypt(phSessionHandle, pucKey, SGD_SM4_ECB, pucIV,
                     &pucData[i * MAX], MAX, &pucEncData[i * MAX],
                     &puiEncDataLength);
    if (SDR_OK != rv) {
      free(pucData);
      free(pucEncData);
      return rv;
    }
  }
  gettimeofday(&tv, NULL);
  L2 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
  printf("SGD_SM4_ECB Encrypt datasize: %d Bytes used time: %lld us\n",
         loop * MAX, L2 - L1);
  printf("SGD_SM4_ECB Encrypt average speed: %d bps\n",
         (int)((long long)MAX * loop * 8 * 1000000 / (L2 - L1)));

  SGD_UCHAR *pucTmpData = (SGD_UCHAR *)malloc(loop * MAX);
  memset(pucIV, 1, 16);
  gettimeofday(&tv, NULL);
  L3 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
  for (i = 0; i < loop; i++) {
    rv = SDF_Decrypt(phSessionHandle, pucKey, SGD_SM4_ECB, pucIV,
                     &pucEncData[i * MAX], MAX, &pucTmpData[i * MAX],
                     &puiEncDataLength);
    if (SDR_OK != rv) {
      free(pucData);
      free(pucEncData);
      free(pucTmpData);
      return rv;
    }
  }
  gettimeofday(&tv, NULL);
  L4 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;

  printf("SGD_SM4_ECB Decrypt datasize: %d Bytes used time: %lld us\n",
         loop * MAX, L4 - L3);
  printf("SGD_SM4_ECB Decrypt average speed: %d bps\n",
         (int)((long long)MAX * loop * 8 * 1000000 / (L4 - L3)));

  if (memcmp(pucData, pucTmpData, loop * MAX)) {
    free(pucData);
    free(pucEncData);
    free(pucTmpData);
    printf("memcmp    diff\n");
    return -1;
  }
  free(pucData);
  free(pucEncData);
  free(pucTmpData);
  return SDR_OK;
}
SGD_RV SM4_ENC_DEC_CBC(SGD_HANDLE phSessionHandle, SGD_HANDLE phKeyHandle) {

  SGD_RV rv = SDR_OK;
  int loop = LOOP, i = 0;
  SGD_UCHAR pucIV[16] = {0};
  memset(pucIV, 1, 16);
  SGD_UCHAR *pucData = (SGD_UCHAR *)malloc(loop * MAX);
  SGD_UINT32 uiDataLength = loop * MAX;
  SGD_UCHAR *pucEncData = (SGD_UCHAR *)malloc(loop * MAX);
  SGD_UINT32 puiEncDataLength = loop * MAX;
  SGD_UCHAR pucKey[16];
  memset(pucKey, 2, 16);
  int count = loop;

  for (i = 0; i < loop * MAX; i++) {
    pucData[i] = i % 256;
  }

  unsigned long long L1, L2, L3, L4;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  L1 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;

  for (i = 0; i < loop; i++) {
    rv = SDF_Encrypt(phSessionHandle, pucKey, SGD_SM4_CBC, pucIV,
                     &pucData[i * MAX], MAX, &pucEncData[i * MAX],
                     &puiEncDataLength);
    if (SDR_OK != rv) {
      free(pucData);
      free(pucEncData);
      return rv;
    }
  }
  gettimeofday(&tv, NULL);
  L2 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
  printf("SGD_SM4_CBC Encrypt datasize: %d Bytes used time: %lld us\n",
         loop * MAX, L2 - L1);
  printf("SGD_SM4_CBC Encrypt average speed: %d bps\n",
         (int)((long long)MAX * loop * 8 * 1000000 / (L2 - L1)));

  SGD_UCHAR *pucTmpData = (SGD_UCHAR *)malloc(loop * MAX);
  memset(pucIV, 1, 16);
  gettimeofday(&tv, NULL);
  L3 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
  for (i = 0; i < loop; i++) {
    rv = SDF_Decrypt(phSessionHandle, pucKey, SGD_SM4_CBC, pucIV,
                     &pucEncData[i * MAX], MAX, &pucTmpData[i * MAX],
                     &puiEncDataLength);
    if (SDR_OK != rv) {
      free(pucData);
      free(pucEncData);
      free(pucTmpData);
      return rv;
    }
  }
  gettimeofday(&tv, NULL);
  L4 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;

  printf("SGD_SM4_CBC Decrypt datasize: %d Bytes used time: %lld us\n",
         loop * MAX, L4 - L3);
  printf("SGD_SM4_CBC Decrypt average speed: %d bps\n",
         (int)((long long)MAX * loop * 8 * 1000000 / (L4 - L3)));

  if (memcmp(pucData, pucTmpData, loop * MAX)) {
    free(pucData);
    free(pucEncData);
    free(pucTmpData);
    printf("memcmp    diff\n");
    return -1;
  }
  free(pucData);
  free(pucEncData);
  free(pucTmpData);
  return SDR_OK;
}
SGD_RV SM4_ENC_DEC_OFB(SGD_HANDLE phSessionHandle, SGD_HANDLE phKeyHandle) {

  SGD_RV rv = SDR_OK;
  int loop = LOOP, i = 0;
  SGD_UCHAR pucIV[16] = {0};
  memset(pucIV, 1, 16);
  SGD_UCHAR *pucData = (SGD_UCHAR *)malloc(loop * MAX);
  SGD_UINT32 uiDataLength = loop * MAX;
  SGD_UCHAR *pucEncData = (SGD_UCHAR *)malloc(loop * MAX);
  SGD_UINT32 puiEncDataLength = loop * MAX;
  SGD_UCHAR pucKey[16];
  memset(pucKey, 2, 16);
  int count = loop;

  for (i = 0; i < loop * MAX; i++) {
    pucData[i] = i % 256;
  }

  unsigned long long L1, L2, L3, L4;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  L1 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;

  for (i = 0; i < loop; i++) {
    rv = SDF_Encrypt(phSessionHandle, pucKey, SGD_SM4_OFB, pucIV,
                     &pucData[i * MAX], MAX, &pucEncData[i * MAX],
                     &puiEncDataLength);
    if (SDR_OK != rv) {
      free(pucData);
      free(pucEncData);
      return rv;
    }
  }
  gettimeofday(&tv, NULL);
  L2 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
  printf("SGD_SM4_OFB Encrypt datasize: %d Bytes used time: %lld us\n",
         loop * MAX, L2 - L1);
  printf("SGD_SM4_OFB Encrypt average speed: %d bps\n",
         (int)((long long)MAX * loop * 8 * 1000000 / (L2 - L1)));

  SGD_UCHAR *pucTmpData = (SGD_UCHAR *)malloc(loop * MAX);
  memset(pucIV, 1, 16);
  gettimeofday(&tv, NULL);
  L3 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
  for (i = 0; i < loop; i++) {
    rv = SDF_Decrypt(phSessionHandle, pucKey, SGD_SM4_OFB, pucIV,
                     &pucEncData[i * MAX], MAX, &pucTmpData[i * MAX],
                     &puiEncDataLength);
    if (SDR_OK != rv) {
      free(pucData);
      free(pucEncData);
      free(pucTmpData);
      return rv;
    }
  }
  gettimeofday(&tv, NULL);
  L4 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;

  printf("SGD_SM4_OFB Decrypt datasize: %d Bytes used time: %lld us\n",
         loop * MAX, L4 - L3);
  printf("SGD_SM4_OFB Decrypt average speed: %d bps\n",
         (int)((long long)MAX * loop * 8 * 1000000 / (L4 - L3)));

  if (memcmp(pucData, pucTmpData, loop * MAX)) {
    free(pucData);
    free(pucEncData);
    free(pucTmpData);
    printf("memcmp    diff\n");
    return -1;
  }
  free(pucData);
  free(pucEncData);
  free(pucTmpData);
  return SDR_OK;
}

/*
SGD_RV SM1_ENC_DEC_IPSEC(SGD_HANDLE phSessionHandle, SGD_HANDLE phKeyHandle) {
  SGD_RV rv = SDR_OK;
  int loop = LOOP, i = 0;
  SGD_UCHAR pucIV[16] = {0};
  memset(pucIV, 1, 16);
  SGD_UCHAR HMACKey[32] = {0};
  memset(HMACKey, 3, 32);
  SGD_UINT32 HMACKeyLen = 32;
  SGD_UCHAR *pucData = (SGD_UCHAR *)malloc(loop * MAX);
  SGD_UINT32 uiDataLength = loop * MAX;
  SGD_UCHAR *pucEncData = (SGD_UCHAR *)malloc(loop * MAX);
  SGD_UINT32 puiEncDataLength = loop * MAX;
  SGD_UCHAR *pucMacData = (SGD_UCHAR *)malloc(loop * 32);
  SGD_UINT32 puiMacDataLength = loop * 32;

  SGD_UCHAR pucKey[16];
  memset(pucKey, 2, 16);
  SGD_UCHAR sendTmpbuf[5000] = {0};
  SGD_UINT32 sendTmpbufLen = 5000;
  SGD_UCHAR recvTmpbuf[5000] = {0};
  SGD_UINT32 recvTmpbufLen = 5000;

  int count = loop;

  memset(sendTmpbuf, 4, 24);

  for (i = 0; i < loop * MAX; i++) {
    pucData[i] = i % 256;
  }

  unsigned long long L1, L2, L3, L4;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  L1 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;

  for (i = 0; i < loop; i++) {
    memcpy(sendTmpbuf + 24, pucData + i * MAX, MAX);
    rv = SDF_Encrypt_IPSEC(phSessionHandle, pucKey, SGD_IPSEC_SM1, pucIV,
                           HMACKey, HMACKeyLen, sendTmpbuf, 24 + MAX,
                           recvTmpbuf, &recvTmpbufLen);

    if (SDR_OK != rv) {
      free(pucData);
      free(pucEncData);
      free(pucMacData);
      return rv;
    }
    memcpy(pucEncData + i * MAX, recvTmpbuf + 24, MAX);
    memcpy(pucMacData + i * 32, recvTmpbuf + 24 + MAX, 32);
  }
  gettimeofday(&tv, NULL);
  L2 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
  printf("SGD_IPSEC_SM1 Encrypt datasize: %d Bytes used time: %lld us\n",
         count * (MAX + 24), L2 - L1);
  printf("SGD_IPSEC_SM1 Encrypt average speed: %d bps\n",
         (int)((long long)(MAX + 24) * count * 8 * 1000000 / (L2 - L1)));

  SGD_UCHAR *pucTmpData = (SGD_UCHAR *)malloc(loop * MAX);
  SGD_UCHAR *pucTmpMacData = (SGD_UCHAR *)malloc(loop * 32);

  memset(pucIV, 1, 16);

  loop = count;
  gettimeofday(&tv, NULL);
  L3 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
  for (i = 0; i < loop; i++) {
    memcpy(sendTmpbuf + 24, pucEncData + i * MAX, MAX);
    rv = SDF_Decrypt_IPSEC(phSessionHandle, pucKey, SGD_IPSEC_SM1, pucIV,
                           HMACKey, HMACKeyLen, sendTmpbuf, 24 + MAX,
                           recvTmpbuf, &recvTmpbufLen);
    if (SDR_OK != rv) {
      free(pucData);
      free(pucEncData);
      free(pucMacData);
      free(pucTmpData);
      free(pucTmpMacData);
      return rv;
    }
    memcpy(pucTmpData + i * MAX, recvTmpbuf + 24, MAX);
    memcpy(pucTmpMacData + i * 32, recvTmpbuf + 24 + MAX, 32);
  }
  gettimeofday(&tv, NULL);
  L4 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;

  printf("SGD_IPSEC_SM1 Decrypt datasize: %d Bytes used time: %lld us\n",
         count * (MAX + 24), L4 - L3);
  printf("SGD_IPSEC_SM1 Decrypt average speed: %d bps\n",
         (int)((long long)(MAX + 24) * count * 8 * 1000000 / (L4 - L3)));

  if (memcmp(pucData, pucTmpData, count * MAX)) {
    free(pucData);
    free(pucEncData);
    free(pucMacData);
    free(pucTmpData);
    free(pucTmpMacData);
    printf("pucData pucTmpData  memcmp diff\n");
    return -1;
  }
  if (memcmp(pucMacData, pucTmpMacData, count * 32)) {
    free(pucData);
    free(pucEncData);
    free(pucMacData);
    free(pucTmpData);
    free(pucTmpMacData);
    printf("pucMacData pucTmpMacData memcmp diff\n");
    return -1;
  }

  free(pucData);
  free(pucEncData);
  free(pucMacData);
  free(pucTmpData);
  free(pucTmpMacData);
  return SDR_OK;
}
*/

SGD_RV SM4_ENC_DEC_IPSEC(SGD_HANDLE phSessionHandle,SGD_HANDLE phKeyHandle)
{
        SGD_RV rv = SDR_OK;
        int loop = LOOP, i = 0;
        SGD_UCHAR pucIV[16] ={0};
        memset(pucIV, 1, 16);
        SGD_UCHAR HMACKey[32] ={0};
        memset(HMACKey, 3, 32);
        SGD_UINT32 HMACKeyLen = 32;
        SGD_UCHAR *pucData = (SGD_UCHAR*)malloc(loop * MAX);
        SGD_UINT32 uiDataLength = loop * MAX;
        SGD_UCHAR *pucEncData = (SGD_UCHAR*)malloc(loop * MAX);
        SGD_UINT32 puiEncDataLength = loop * MAX;
        SGD_UCHAR *pucMacData = (SGD_UCHAR*)malloc(loop * 32);
        SGD_UINT32 puiMacDataLength = loop * 32;

    SGD_UCHAR pucKey[16];
        memset(pucKey,2,16);
        SGD_UCHAR sendTmpbuf[5000] = {0};
        SGD_UINT32 sendTmpbufLen = 5000;
        SGD_UCHAR recvTmpbuf[5000] = {0};
        SGD_UINT32 recvTmpbufLen = 5000;

        int count = loop;

        memset(sendTmpbuf, 4, 24);

        for(i = 0; i < loop * MAX; i++)
        {
                pucData[i] = i / 256;
        }

        unsigned long long L1,L2,L3, L4;
        struct timeval tv;
        gettimeofday(&tv, NULL);
        L1 = tv.tv_sec*1000*1000 + tv.tv_usec;

        for(i = 0; i < loop; i++)
        {
                memcpy(sendTmpbuf + 24, pucData + i * MAX, MAX);
                rv = SDF_Encrypt_IPSEC( phSessionHandle,pucKey, SGD_IPSEC_SM4,
pucIV, HMACKey, HMACKeyLen, sendTmpbuf, 24 + MAX, recvTmpbuf, &recvTmpbufLen);
                if(SDR_OK != rv)
                {
                        free(pucData);
                        free(pucEncData);
                        free(pucMacData);
                        return rv;
                }
                memcpy(pucEncData + i * MAX, recvTmpbuf + 24, MAX);
                memcpy(pucMacData + i * 32, recvTmpbuf + 24 + MAX, 32);
        }

        gettimeofday(&tv, NULL);
        L2 = tv.tv_sec*1000*1000 + tv.tv_usec;
        printf("SGD_IPSEC_SM4 Encrypt datasize: %d Bytes used time: %lld us\n", count * (MAX + 24), L2 - L1);
	printf("SGD_IPSEC_SM4 Encrypt average speed: %d bps\n", (int)((long long)(MAX + 24) * count * 8 * 1000000 / (L2 - L1)));

        SGD_UCHAR *pucTmpData = (SGD_UCHAR*)malloc(loop * MAX);
        SGD_UCHAR *pucTmpMacData = (SGD_UCHAR*)malloc(loop * 32);

        memset(pucIV,1,16);

        loop = count;
        gettimeofday(&tv, NULL);
        L3 = tv.tv_sec*1000*1000 + tv.tv_usec;
        for(i = 0; i < loop; i++)
        {
                memcpy(sendTmpbuf + 24, pucEncData + i * MAX, MAX);
                rv = SDF_Decrypt_IPSEC(phSessionHandle,pucKey, SGD_IPSEC_SM4,
pucIV, HMACKey, HMACKeyLen, sendTmpbuf, 24 + MAX, recvTmpbuf, &recvTmpbufLen);
                if(SDR_OK != rv)
                {
                        free(pucData);
                        free(pucEncData);
                        free(pucMacData);
                        free(pucTmpData);
                        free(pucTmpMacData);
                        return rv;
                }
                memcpy(pucTmpData + i * MAX, recvTmpbuf + 24, MAX);
                memcpy(pucTmpMacData + i * 32, recvTmpbuf + 24 + MAX, 32);
        }
        gettimeofday(&tv, NULL);
        L4 = tv.tv_sec*1000*1000 + tv.tv_usec;

       printf("SGD_IPSEC_SM4 Decrypt datasize: %d Bytes used time: %lld us\n", count * (MAX + 24), L4 - L3);
	printf("SGD_IPSEC_SM4 Decrypt average speed: %d bps\n", (int)((long long)(MAX + 24) * count * 8 * 1000000 / (L4 - L3)));
        if(memcmp(pucData,pucTmpData,count * MAX))
        {
                free(pucData);
                free(pucEncData);
                free(pucMacData);
                free(pucTmpData);
                free(pucTmpMacData);
                printf("pucData pucTmpData  memcmp diff\n");
                return -1;
        }
        if(memcmp(pucMacData,pucTmpMacData,count * 32))
        {
                free(pucData);
                free(pucEncData);
                free(pucMacData);
                free(pucTmpData);
                free(pucTmpMacData);
                printf("pucMacData pucTmpMacData memcmp diff\n");
                return -1;
        }

        free(pucData);
        free(pucEncData);
        free(pucMacData);
        free(pucTmpData);
        free(pucTmpMacData);
        return SDR_OK;
}


SGD_RV SGD_SM3Hash(SGD_HANDLE phSessionHandle) {

  printf("Entering SGD_SM3Hash\n");
  SGD_RV rv = SDR_OK;
  ECCrefPublicKey phPubKey;
  memcpy(phPubKey.x, pubKey, 32);
  memcpy(phPubKey.y, pubKey + 32, 32);

// 哈希过程中使用的数据和ID
  SGD_UCHAR pucID[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  SGD_UINT32 uiIDLen = 16;

  SGD_UINT8 pucData[16] = {0};
  memset(pucData, 0x05, 16);
  SGD_UINT32 uiPucDateLen = 16;// 哈希过程中使用的数据和ID

    // 初始化哈希运算，这里示例为不使用公钥和ID的初始化方式
  // rv = SDF_HashInit(phSessionHandle,SGD_SM3,&phPubKey,pucID,uiIDLen);
  rv = SDF_HashInit(phSessionHandle, SGD_SM3, NULL, NULL, 0);
  if (SDR_OK != rv) {
    return rv;
  }

    // 对数据进行哈希更新
  rv = SDF_HashUpdate(phSessionHandle, pucData, uiPucDateLen);
  if (SDR_OK != rv) {
    return rv;
  }
  uiPucDateLen = 32;

    // 完成哈希运算，获取最终的哈希值
  rv = SDF_HashFinal(phSessionHandle, sm3HashData, &uiPucDateLen);
  if (SDR_OK != rv) {
    return rv;
  }
  
      // 输出原文和哈希值
    printf("原文: ");
    for (int i = 0; i < uiIDLen; i++) {
        printf("%02x", pucID[i]);
    }
    printf("\n");

    printf("哈希值: ");
    for (int i = 0; i < uiPucDateLen; i++) {
        printf("%02x", sm3HashData[i]);
    }
    printf("\n");

  return SDR_OK;
}






SGD_RV SGD_SM4EncDec(SGD_HANDLE phSessionHandle) {
	SGD_RV rv = SDR_OK;
	printf("Entering SGD_SM4EncDec\n");
    const SGD_UCHAR key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                               0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    SGD_UCHAR pucID[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                           0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    printf("Original text: ");
    for (int i = 0; i < sizeof(pucID); i++) {
        printf("%02x", pucID[i]);
    }
    printf("\n");

    SGD_UCHAR ciphertext[64];
    SGD_UCHAR decryptedtext[64];
    int decryptedtext_len;

    rv = sm4_encrypt(phSessionHandle,pucID, sizeof(pucID), key, ciphertext);

    int ciphertext_len = rv;
    
    printf("Encrypted text: ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    rv = sm4_decrypt(phSessionHandle,ciphertext, ciphertext_len, key, decryptedtext, &decryptedtext_len);
    if (SDR_OK != rv) {
    return rv;
  }

    printf("Decrypted text: ");
    for (int i = 0; i < decryptedtext_len; i++) {
        printf("%02x", decryptedtext[i]);
    }
    printf("\n");

    // Check if the decrypted text is the same as the original
    if (decryptedtext_len == sizeof(pucID) && memcmp(pucID, decryptedtext, sizeof(pucID)) == 0) {
        printf("The decrypted text is the same as the original text.\n");
    } else {
        printf("The decrypted text is NOT the same as the original text.\n");

    }
    return SDR_OK;
}







// SM2加解密函数
SGD_RV SM2EncDec(SGD_HANDLE phSessionHandle) {
  SGD_RV rv = SDR_OK;

  SGD_UCHAR pucData[32] = {0};
  SGD_UINT32 uiDataLen = sizeof(pucData);
  memset(pucData, 0x05, sizeof(pucData));
  ECCCipher Cipher;

  //SM2加密
  rv = SDF_InternalEncrypt_ECC(phSessionHandle, 1, SGD_SM2_3, pucData,
                               uiDataLen, &Cipher);
  if (SDR_OK != rv) {
    printf("SDF_InternalEncrypt_ECC failed rv = %08x\n", rv);
    return rv;
  }

  SGD_UCHAR pucDecData[32] = {0};
  SGD_UINT32 uiDecDataLen = sizeof(pucDecData);

  //SM2解密
  rv = SDF_InternalDecrypt_ECC(phSessionHandle, 1, SGD_SM2_3, &Cipher,
                               pucDecData, &uiDecDataLen);
  if (SDR_OK != rv) {
    printf("SDF_InternalDecrypt_ECC failed rv = %08x\n", rv);
    return rv;
  }
   // 比较原始数据和解密后的数据是否一致
  if (memcmp(pucData, pucDecData, uiDecDataLen)) {
    printf("memcpy diff \n");
    return -1;
  }

    
  return SDR_OK;
}

SGD_RV SM2SignVer(SGD_HANDLE phSessionHandle) {
  SGD_RV rv = SDR_OK;
#define COUNT 100
  ECCSignature Signature;
  int i = 0;

  unsigned long long L1, L2, L3, L4;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  L1 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;

  for (i = 0; i < COUNT; i++) {
    rv = SDF_InternalSign_ECC(phSessionHandle, 1, sm3HashData, 32, &Signature);
    if (SDR_OK != rv) {
      printf("SDF_InternalSign_ECC failed rv = 0x%08x\n", rv);
      return rv;
    }
  }

  gettimeofday(&tv, NULL);
  L2 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
  printf("SM2-Sign Times: %d 次;	Spent time: %lld us\n", COUNT, L2 - L1);
  printf("SM2-Sign average speed: %d us/次\n",
         (int)((L2 - L1) / (long long)COUNT));

  gettimeofday(&tv, NULL);
  L3 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;

  for (i = 0; i < COUNT; i++) {
    rv =
        SDF_InternalVerify_ECC(phSessionHandle, 1, sm3HashData, 32, &Signature);
    if (SDR_OK != rv) {
      printf("SDF_InternalVerify_ECC failed rv = 0x%08x\n", rv);
      return rv;
    }
  }
  gettimeofday(&tv, NULL);
  L4 = tv.tv_sec * 1000 * 1000 + tv.tv_usec;
  printf("SM2-Verify Times: %d 次;	Spent time: %lld us\n", COUNT, L4 - L3);
  printf("SM2-Verify average speed: %d us/次\n",
         (int)((L4 - L3) / (long long)COUNT));

  return SDR_OK;
}

SGD_RV ExportKeyPair(SGD_HANDLE phSessionHandle) {
  SGD_RV rv = SDR_OK;
  SGD_UCHAR pucPubKey[64];

  // 导出公钥并检查操作是否成功
  rv = SDF_ExportECCPubKey(phSessionHandle, 1, pucPubKey);
  if (SDR_OK != rv) {
    return rv;
  }

  // 导出公钥并检查操作是否成功
  if (memcmp(pucPubKey, pubKey, 64)) {
    printf("pubKey1 diff \n");
    return -1;
  }

  // 导出私钥并检查操作是否成功
  SGD_UCHAR pucPriKey[32];
  rv = SDF_ExportECCPriKey(phSessionHandle, 1, pucPriKey);
  if (SDR_OK != rv) {
    return rv;
  }

  SGD_UCHAR pucIV[16] = {0};
  memset(pucIV, 0, 16);
  SGD_UCHAR pucEncData[100] = {0};
  SGD_UINT32 puiEncDataLength = 100;

  // 使用ROOTKEY对私钥进行加密
  rv = SDF_Encrypt(phSessionHandle, (SGD_UINT8 *)ROOTKEY, SGD_SM1_CBC, pucIV,
                   priKey, 32, pucEncData, &puiEncDataLength);
  if (SDR_OK != rv) {
    return rv;
  }

  if (memcmp(pucPriKey, pucEncData, 32)) {
    printf("priKey2 diff \n");
    return -1;
  }

  return SDR_OK;
}

SGD_RV SM1_CBC(SGD_HANDLE phSessionHandle, SGD_HANDLE phKeyHandle) {

  SGD_RV rv = SDR_OK;
  SGD_UCHAR pucIV[16] = {0};
  memset(pucIV, 0, 16);
  SGD_UCHAR pucData[64] = {
      0x8B, 0x7F, 0xB9, 0x6C, 0x09, 0x53, 0x27, 0x19, 0xE4, 0xEB, 0x79,
      0x16, 0xC6, 0x2E, 0x20, 0xEA, 0x33, 0xCC, 0x98, 0x96, 0x43, 0xFA,
      0x45, 0x09, 0x0C, 0x98, 0x4E, 0xA5, 0xDF, 0x76, 0xA1, 0xD4, 0xC1,
      0xF8, 0x9C, 0x46, 0x67, 0x61, 0xCE, 0x07, 0x83, 0x26, 0xAF, 0x1C,
      0xA0, 0x81, 0xC5, 0x89, 0x4E, 0x0C, 0xD5, 0x29, 0x88, 0x40, 0x96,
      0x45, 0x50, 0xD9, 0x14, 0x17, 0xB7, 0x5C, 0xC5, 0x5E};
  SGD_UINT32 uiDataLength = sizeof(pucData);
  SGD_UCHAR pucEncData[64] = {0};
  SGD_UINT32 puiEncDataLength = sizeof(pucEncData);
  SGD_UCHAR pucKey[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                          0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

  rv = SDF_Encrypt(phSessionHandle, pucKey, SGD_SM1_CBC, pucIV, pucData,
                   uiDataLength, pucEncData, &puiEncDataLength);
  if (SDR_OK != rv) {
    return rv;
  }
  printf("pucEncData:\n");
  myprintf(pucEncData, puiEncDataLength);

  SGD_UCHAR pucTmpData[64] = {0};
  memset(pucIV, 0, 16);
  rv = SDF_Decrypt(phSessionHandle, pucKey, SGD_SM1_CBC, pucIV, pucEncData,
                   puiEncDataLength, pucTmpData, &puiEncDataLength);
  if (SDR_OK != rv) {
    return rv;
  }

  if (memcmp(pucData, pucTmpData, 64)) {
    printf("memcmp    diff\n");
    return -1;
  }

  return SDR_OK;
}

// 测试获取设备信息的函数
SGD_RV Test_GetDeviceInfo(SGD_HANDLE phSessionHandle) {
  DEVICEINFO deviceInfo;
  SGD_RV rv = SDF_GetDeviceInfo(phSessionHandle, &deviceInfo);
  if (rv != SDR_OK) {
    printf("Failed to get device info with error code: %08x\n", rv);
  } else {
    printf("Device Info:\n");                                    //设备信息
    printf("IssuerName: %s\n", deviceInfo.IssuerName);           //用户名
    printf("DeviceName: %s\n", deviceInfo.DeviceName);           //设备名
    printf("DeviceSerial: %s\n", deviceInfo.DeviceSerial);       //设备系列
    printf("DeviceVersion: %u\n", deviceInfo.DeviceVersion);     //设备版本
    printf("StandardVersion: %u\n", deviceInfo.StandardVersion); //标准版
    printf("AsymAlgAbility: %u, %u\n", deviceInfo.AsymAlgAbility[0],
           deviceInfo.AsymAlgAbility[1]); //不对称算术能力
    printf("SymAlgAbility: %u\n", deviceInfo.SymAlgAbility); //符号运算能力
    printf("HashAlgAbility: %u\n", deviceInfo.HashAlgAbility); //哈希代数能力
    printf("BufferSize: %u\n", deviceInfo.BufferSize);         //缓冲器大小
    printf("\n");
  }
  return rv;
}

int main(int argc, char *argv[]) {
  SGD_HANDLE phDeviceHandle;
  SGD_HANDLE phSessionHandle;
  SGD_HANDLE phKeyHandle;
  SGD_UCHAR pOutRand[16] = {0};
  SGD_UINT32 ulRandLen = 16;
  SGD_UCHAR SN[17] = {0};
  SGD_UCHAR CosVer[10] = {0};
  int loop = 1;
  if (argc > 1) {
    loop = atol(argv[1]);
  }

  SGD_RV rv = SDF_OpenDevice(&phDeviceHandle);
  if (rv != SDR_OK) {
    printf("open devces fail\n");
    return 0;
  }
  printf("open device success!\n");
  printf("\n");

  rv = SDF_OpenSession(phDeviceHandle, &phSessionHandle);
  if (rv != SDR_OK) {
    SDF_CloseDevice(phDeviceHandle);
    printf("open session fail\n");
    return 0;
  }
  printf("open session success!\n");
  printf("\n");

  rv = SDF_GenerateRandom(phSessionHandle, pOutRand, ulRandLen);
  if (rv != SDR_OK) {
    SDF_CloseDevice(phDeviceHandle);
    printf("SDF_GenerateRandom fail\n");
    return 0;
  }
  printf("pOutRand:\n");
  myprintf(pOutRand, ulRandLen);
  printf("SDF_GenerateRandom success!\n\n");
  // return 0;


#if 1
  // 测试获取设备信息
  printf("Testing getting device information...\n");
  rv = Test_GetDeviceInfo(phSessionHandle);

  printf("\n");
  DEVICEINFO devInfo;
  rv = SDF_GetDeviceInfo(phSessionHandle, &devInfo);
  if (rv != SDR_OK) {
    printf("SDF_GetDeviceInfo fail\n");
    printf("Get device information failed with error code: %08x\n", rv);
    goto err;
  }
  memcpy(SN, devInfo.DeviceSerial, 16);
  printf("SN:%s\n", SN);
  // 从DeviceVersion中获取整型值并格式化到CosVer
  // 假设版本号格式为主版本号.次版本号.修订号，例如4205表示4.2.05
  int major = devInfo.DeviceVersion / 1000;       // 主版本号
  int minor = (devInfo.DeviceVersion / 100) % 10; // 次版本号
  int patch = devInfo.DeviceVersion % 100;        // 修订号
  sprintf((char *)CosVer, "%d.%d.%02d", major, minor,
          patch); // 格式化版本号，修订号保持两位数
  printf("设备版本号: %s\n", CosVer);
  printf("Get device information success.\n\n");

#endif

#if 1

  rv = SDF_ImportRootKeyAndDeviceSN(phSessionHandle, (SGD_UINT8 *)ROOTKEY,
                                    (SGD_UINT8 *)DEVSN, 16);
  if (rv != SDR_OK) {
    printf("SDF_ImportRootKeyAndDeviceSN fail, RootKey can only import once\n");
    //	 	goto err;
  } else {
    printf("SDF_ImportRootKeyAndDeviceSN success\n\n");
  }

#endif

  rv = ImportKeyPair(phSessionHandle);
  if (rv != SDR_OK) {
    printf("\nImportKeyPair fail\n\n");
    goto err;
  }
  printf("\nImportKeyPair success\n\n");

  rv = EccBackUpKeyPair(phSessionHandle);
  if (rv != SDR_OK) {
    printf("\nEccBackUpKeyPair fail\n\n");
    goto err;
  }
  printf("\nEccBackUpKeyPair success\n\n");

  rv = ExportKeyPair(phSessionHandle);
  if (rv != SDR_OK) {
    printf("\nExportKeyPair fail\n\n");
    goto err;
  }
  printf("\nExportKeyPair success\n\n");

  rv = SGD_SM3Hash(phSessionHandle);
  if (rv != SDR_OK) {
    printf("\nSGD_SM3Hash fail\n\n");
    goto err;
  }
  printf("\nSGD_SM3Hash success\n\n");
  	
	
  rv = SGD_SM4EncDec(phSessionHandle);
  if (rv != SDR_OK) {
    printf("\nSGD_SM4EncDec fail\n\n");
    goto err;
  }
  printf("\nSGD_SM4EncDec success\n\n");
	
  rv = SM2EncDec(phSessionHandle);
  if (rv != SDR_OK) {
    printf("SM2EncDec fail\n");
    goto err;
  }
  printf("SM2EncDec success\n");

  rv = SM2SignVer(phSessionHandle);
  if (rv != SDR_OK) {
    printf("SM2SignVer fail\n");
    goto err;
  }
  printf("SM2SignVer success\n");
  
 

  rv = SM1_ENC_DEC_ECB(phSessionHandle, phKeyHandle);
  if (rv != SDR_OK) {
    printf("SM1_ENC_DEC_ECB fail\n");
    goto err;
  }
  printf("SM1_ENC_DEC_ECB success. \n");

  rv = SM1_ENC_DEC_CBC(phSessionHandle, phKeyHandle);
  if (rv != SDR_OK) {
    printf("SM1_ENC_DEC_CBC fail\n");
    goto err;
  }
  printf("SM1_ENC_DEC_CBC success. \n");

  rv = SM1_ENC_DEC_OFB(phSessionHandle, phKeyHandle);
  if (rv != SDR_OK) {
    printf("SM1_ENC_DEC_OFB fail\n");
    goto err;
  }
  printf("SM1_ENC_DEC_OFB success. \n");

  rv = SM4_ENC_DEC_ECB(phSessionHandle, phKeyHandle);
  if (rv != SDR_OK) {
    printf("SM4_ENC_DEC_ECB fail\n");
    goto err;
  }
  printf("SM4_ENC_DEC_ECB success. \n");

  rv = SM4_ENC_DEC_CBC(phSessionHandle, phKeyHandle);
  if (rv != SDR_OK) {
    printf("SM4_ENC_DEC_CBC fail\n");
    goto err;
  }
  printf("SM4_ENC_DEC_CBC success. \n");

  rv = SM4_ENC_DEC_OFB(phSessionHandle, phKeyHandle);
  if (rv != SDR_OK) {
    printf("SM4_ENC_DEC_OFB fail\n");
    goto err;
  }
  printf("SM4_ENC_DEC_OFB success. \n");

/*
  rv = SM1_ENC_DEC_IPSEC(phSessionHandle, phKeyHandle);
  if (rv != SDR_OK) {
    printf("SM1_ENC_DEC_IPSEC fail\n");
    goto err;
  }
  printf("SM1_ENC_DEC_IPSEC success. \n");
  */
  
  
initialize_openssl();
          rv =SM4_ENC_DEC_IPSEC(phSessionHandle,phKeyHandle);
          if(rv != SDR_OK)
          {
                  printf("SM4_ENC_DEC_IPSEC fail\n");
                  goto err;
          }
          printf("SM4_ENC_DEC_IPSEC success.\n");
 cleanup_openssl();

err:

  SDF_CloseSession(phSessionHandle);

  SDF_CloseDevice(phDeviceHandle);

  return 0;
}
