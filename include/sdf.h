/*
* File: sdf.h
* Copyright (c) SANGFOR 2017
*/

#ifndef _SDF_H_
#define _SDF_H_ 1


#include <stdint.h>


#ifdef __cplusplus
extern "C"{
#endif


/*类型定义*/
typedef char          SGD_CHAR;
typedef int8_t        SGD_INT8;
typedef int16_t       SGD_INT16;
typedef int32_t       SGD_INT32;
typedef int64_t       SGD_INT64;
typedef unsigned char SGD_UCHAR;
typedef uint8_t       SGD_UINT8;
typedef uint16_t      SGD_UINT16;
typedef uint32_t      SGD_UINT32;
typedef uint64_t      SGD_UINT64;
typedef unsigned int  SGD_RV;
typedef void*         SGD_HANDLE;

/*设备信息结构体*/
typedef struct DeviceInfo_st {
	unsigned char IssuerName[40];
	unsigned char DeviceName[16];
	unsigned char DeviceSerial[16];
	unsigned int  DeviceVersion;
	unsigned int  StandardVersion;
	unsigned int  AsymAlgAbility[2];
	unsigned int  SymAlgAbility;
	unsigned int  HashAlgAbility;
	unsigned int  BufferSize;
} DEVICEINFO;



/*ECC算法*/
#define ECCref_MAX_BITS 256
#define ECCref_MAX_LEN ((ECCref_MAX_BITS+7) / 8)
#define ECCref_MAX_CIPHER_LEN 136

#define ECCref_MAX_PLAINTEXT_LEN_22 128
	
/*ECC 公钥结构体*/
typedef struct ECCrefPublicKey_st {
	unsigned int  bits;
	unsigned char x[ECCref_MAX_LEN];
	unsigned char y[ECCref_MAX_LEN];
} ECCrefPublicKey;

/*ECC 私钥结构体*/
typedef struct ECCrefPrivateKey_st {
	unsigned int  bits;
	unsigned char D[ECCref_MAX_LEN];
} ECCrefPrivateKey;

/*ECC 密文*/
typedef struct ECCCipher_st {
	unsigned int  clength; // C����Ч����
	unsigned char x[ECCref_MAX_LEN];
	unsigned char y[ECCref_MAX_LEN];
	unsigned char C[ECCref_MAX_CIPHER_LEN];
	unsigned char M[ECCref_MAX_LEN];
} ECCCipher;

/*ECC 签名值*/
typedef struct ECCSignature_st {
	unsigned char r[ECCref_MAX_LEN];
	unsigned char s[ECCref_MAX_LEN];
} ECCSignature;


/*算法模式*/
#define SGD_SM1_ECB 0x00000101
#define SGD_SM1_CBC 0x00000102
#define SGD_SM1_CFB 0x00000104
#define SGD_SM1_OFB 0x00000108
#define SGD_SM1_MAC 0x00000110
#define SGD_SM1_CTR 0x00000120
#define SGD_IPSEC_SM1	0x00000121
#define SGD_IPSEC_SM4	0x00000122

#define SGD_SSF33_ECB 0x00000201
#define SGD_SSF33_CBC 0x00000202
#define SGD_SSF33_CFB 0x00000204
#define SGD_SSF33_OFB 0x00000208
#define SGD_SSF33_MAC 0x00000210
#define SGD_SSF33_CTR 0x00000220

#define SGD_AES_ECB 0x00000401
#define SGD_AES_CBC 0x00000402
#define SGD_AES_CFB 0x00000404
#define SGD_AES_OFB 0x00000408
#define SGD_AES_MAC 0x00000410
#define SGD_AES_CTR 0x00000420

#define SGD_3DES_ECB 0x00000801
#define SGD_3DES_CBC 0x00000802
#define SGD_3DES_CFB 0x00000804
#define SGD_3DES_OFB 0x00000808
#define SGD_3DES_MAC 0x00000810
#define SGD_3DES_CTR 0x00000820

#define SGD_SMS4_ECB 0x00002001
#define SGD_SMS4_CBC 0x00002002
#define SGD_SMS4_CFB 0x00002004
#define SGD_SMS4_OFB 0x00002008
#define SGD_SMS4_MAC 0x00002010
#define SGD_SMS4_CTR 0x00002020

#define SGD_SM4_ECB 0x00002001
#define SGD_SM4_CBC 0x00002002
#define SGD_SM4_CFB 0x00002004
#define SGD_SM4_OFB 0x00002008
#define SGD_SM4_MAC 0x00002010
#define SGD_SM4_CTR 0x00002020

#define SGD_DES_ECB 0x00004001
#define SGD_DES_CBC 0x00004002
#define SGD_DES_CFB 0x00004004
#define SGD_DES_OFB 0x00004008
#define SGD_DES_MAC 0x00004010
#define SGD_DES_CTR 0x00004020

#define SGD_RSA      0x00010000
#define SGD_RSA_SIGN 0x00010100
#define SGD_RSA_ENC  0x00010200
#define SGD_SM2_1    0x00020100 //椭圆曲线签名算法
#define SGD_SM2_2    0x00020200 //椭圆曲线密钥交换协议
#define SGD_SM2_3    0x00020400 //椭圆曲线加密算法 

#define SGD_SM3    0x00000001
#define SGD_SHA1   0x00000002
#define SGD_SHA256 0x00000004
#define SGD_SHA512 0x00000008
#define SGD_SHA384 0x00000010
#define SGD_SHA224 0x00000020
#define SGD_MD5    0x00000080


/*错误码定义*/
#define SDR_OK               0x0 						/*成功*/
#define SDR_BASE             0x01000000
#define SDR_UNKNOWERR        (SDR_BASE + 0x00000001)    /*未知错误*/
#define SDR_NOTSUPPORT       (SDR_BASE + 0x00000002)    /*不支持*/
#define SDR_COMMFAIL         (SDR_BASE + 0x00000003)    /*ͨAPDU命令返回失败*/
#define SDR_HARDFAIL         (SDR_BASE + 0x00000004)    /*硬件错误*/
#define SDR_OPENDEVICE       (SDR_BASE + 0x00000005)    /*打开设备失败*/
#define SDR_OPENSESSION      (SDR_BASE + 0x00000006)    /*打开会话失败*/
#define SDR_ALGNOTSUPPORT    (SDR_BASE + 0x00000009)    /*算法模式不支持*/
#define SDR_BUFFER_TOO_SMALL (SDR_BASE + 0x00000016)    /*缓存不够*/
#define SDR_INVALIDPARAMERR  (SDR_BASE + 0x00000017)  	/*参数错误*/
#define SDR_MALLOCFAILED	 (SDR_BASE + 0x00000018)	/*malloc失败*/
#define SDR_MUTEXERR		 (SDR_BASE + 0x00000019)	/*malloc失败*/


/*
功能:连接设备,返回设备句柄;
参数:
	phDeviceHandle		输出, 设备句柄;
返回值:
	返回SDR_OK成功,其他值失败;
*/
SGD_RV SDF_OpenDevice(SGD_HANDLE *phDeviceHandle);
	
/*
功能:断开连接,销毁句柄.
参数:
	hDeviceHandle		输入,设备句柄;
返回值:
	返回SDR_OK成功,其他值失败;
*/
SGD_RV SDF_CloseDevice(SGD_HANDLE hDeviceHandle);
	
/*
功能:打开一个会话,返回会话句柄.Session是SDK内部封装的一个类,内部实现各功能接口.
参数:
	hDeviceHandle		输入,设备句柄.
	phSessionHandle		输出,返回的会话句柄.
返回值:
	返回SDR_OK成功,其他值失败;
*/
SGD_RV SDF_OpenSession(SGD_HANDLE hDeviceHandle, SGD_HANDLE *phSessionHandle);
	
/*
功能:关闭会话,销毁会话句柄
参数:
	hSessionHandle		输入,要关闭的会话句柄.
返回值:
	返回SDR_OK成功,其他值失败;
*/
SGD_RV SDF_CloseSession(SGD_HANDLE hSessionHandle);
	
/*
功能:生成随机数
参数:
	hSessionHandle		输入,会话句柄;
	pOutRand			输出,随机数;
	ulRandLen			输入,要生成的随机数的长度;
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV SDF_GenerateRandom(SGD_HANDLE hSessionHandle, SGD_UCHAR* pOutRand, SGD_UINT32 ulRandLen);
	
/*
功能:导入根密钥和设备SN码, 只能导入一次.
参数:
	 hSessionHandle		输入,会话句柄.
	 rootKey			输入,SM4根密钥
	 devSN				输入,设备SN码.
	 len				输入,DevSN的长度.
返回值:
	 返回SDR_OK成功,其他值失败;
*/
SGD_RV SDF_ImportRootKeyAndDeviceSN(SGD_HANDLE hSessionHandle,SGD_UINT8 * rootKey,SGD_UINT8 * devSN,SGD_UINT32 len);
	
	
/*
功能:获取设备信息
参数:
	hSessionHandle		输入,会话句柄.
	pstDeviceInfo		输出,设备信息结构体.
返回值:
	返回SDR_OK成功,其他值失败;
*/
SGD_RV SDF_GetDeviceInfo(SGD_HANDLE hSessionHandle, DEVICEINFO *pstDeviceInfo);

/*
产生ECC密钥对并输出
描述:请求密码设备产生指定类型和模长的ECC密钥对,此接口暂时只支持产生SM2密钥对。
参数:
	hSessionHandle		输入,与设备建立的会话句柄。
	uiAlgID				输入,指定算法标识,此参数不做要求，固定产生SM2类型密钥对.
	uiKeyBits			输入,指定密钥长度,此参数不做要求，固定产生SM2密钥对，64字节公钥，32字节私钥。
	pucPublicKey		输出,ECC公钥结构.
	pucPrivateKey		输出,ECC私钥结构.
返回值:
	返回0成功,其他值见错误码.
*/
SGD_RV SDF_GenerateKeyPair_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, SGD_UINT32 uiKeyBits, ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey);	

/*
功能描述:导入SM2密钥对,密文形式导入.
参数:
	hSessionHandle	输入,会话句柄.
	uiKeyInd		输入,密钥索引值.
	pKeyEnc			输入,密钥对密文, 公钥在前私钥在后96字节的明文使用根密钥采用SM1算法CBC模式初始向量值为16字节0x00加密得到.
返回值:
	返回SDR_OK成功,其他值失败;
*/
SGD_RV SDF_ImportECCKeyPair(SGD_HANDLE hSessionHandle,SGD_UINT32 uiKeyInd,const SGD_UCHAR *pKeyEnc);

/*
功能描述:导出SM2公钥,明文返回.
参数:
	hSessionHandle		输入,会话句柄.
	uiKeyInd			输入,密钥索引值.
	pPubKey				输出,导出64字节SM2公钥,分配空间不小于64字节.
返回值:
	返回SDR_OK成功,其他值失败;
*/
SGD_RV SDF_ExportECCPubKey(SGD_HANDLE hSessionHandle,SGD_UINT32 uiKeyInd,SGD_UCHAR *pPubKeyEnc);
	
/*
功能:导出SM2私钥,密文形式返回, 密文计算方式与导入时计算方式相同.
参数:
	hSessionHandle		输入,会话句柄.
	uiKeyInd			输入,密钥索引值.
	pPriKeyEnc			输出,返回32字节SM2私钥密文,分配空间不小于32字节.
返回值:
	返回SDR_OK成功,其他值失败;
*/
SGD_RV SDF_ExportECCPriKey(SGD_HANDLE hSessionHandle,SGD_UINT32 uiKeyInd,SGD_UCHAR *pPriKeyEnc);

/*
功能:导出SM2密钥对,密文加Hash值方式返回, 密文和Hash值计算方式与导入时相同.
参数:
	hSessionHandle		输入,会话句柄.
	uiKeyInd			输入,密钥索引值.
	pEncOut				输出,返回SM2密钥对XYD和密钥对明文HASH值
	nOutLen				输出,pEncOut长度
返回值:
	返回SDR_OK成功,其他值失败;
*/
SGD_RV SDF_ECCBackUp(SGD_HANDLE hSessionHandle,SGD_UINT32 uiKeyInd,SGD_UCHAR *pEncOut, SGD_UINT32 *nOutLen);

/*
功能: SM2签名
参数:
	hSessionHandle		输入,会话句柄.
	uiISKIndex			输入,索引值.
	pucData				输入,32字节的Hash结果数据.
	uiDataLength		输入,pucData的长度,固定为32.
	pucSignature		输出,签名值,长度为64字节.
返回值:
	 返回SDR_OK成功,其他值失败;
*/
SGD_RV SDF_InternalSign_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature);
	
/*
功能描述: SM2验签
参数:
	hSessionHandle		输入,会话句柄.
	uiISKIndex			输入,索引值.
	pucData				输入,32字节Hash结果数据.
	uiDataLength		输入,pucData的长度, 固定为32.
	pucSignature		输入,64字节的签名值.
返回值:
	 返回SDR_OK成功,其他值失败;
*/
SGD_RV SDF_InternalVerify_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature);
	
/*
功能: SM2加密
参数:
	hSessionHandle		输入,会话句柄.
	uiIPKIndex			输入,索引值.取值1~8.需保证索引值对应位置已导入密钥.
	uiAlgID				输入,算法类型.固定传SGD_SM2_3.
	pucData				输入,要加密的数据
	uiDataLength		输入,要加密的数据的长度, 最大136字节.
	pucEncData			输出,加密后的数据.
返回值:
	 返回SDR_OK成功,其他值失败;
*/
SGD_RV SDF_InternalEncrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex, SGD_UINT32 uiAlgID, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCCipher *pucEncData);
	
/*
功能:SM2解密
参数:
	参数:
	hSessionHandle		输入,会话句柄.
	uiISKIndex			输入,索引值.取值1~8.需保证索引值对应位置已导入密钥.
	uiAlgID				输入,密钥类型,固定传SGD_SM2_3.
	pucEncData			输入,要解密的数据
	pucData				输出,解密后的数据
	puiDataLength		输入/输出,输入时表示pucData的空间大小, 输出时表示解密后数据的长度.

返回值:
	 返回SDR_OK成功,其他值失败;
*/
SGD_RV SDF_InternalDecrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UINT32 uiAlgID, ECCCipher *pucEncData, SGD_UCHAR *pucData, SGD_UINT32 *puiDataLength);
	
/*
功能:对称算法加密
参数:
	hSessionHandle		输入,会话句柄.
	pucKey				输入,密钥.
	uiAlgID				输入,加密模式,取值 SGD_SM1_ECB/SGD_SM1_CBC/SGD_SM1_OFB/SGD_SM4_ECB/SGD_SM4_CBC/SGD_SM4_OFB.
	pucIV				输入/输出,初始向量, CBC OFB模式使用.
	pucData				输入,要加密的数据.
	uiDataLength		输入,要加密的数据的长度,必须为16的整数倍,且最大4000字节.
	pucEncData			输出,加密后的数据.
	puiEncDataLength	输入/输出,输入是表示pucEncData空间的大小,输出时表示加密后的数据的长度.
返回值:
	 返回SDR_OK成功,其他值失败;
*/
SGD_RV SDF_Encrypt(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucKey, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucEncData, 	SGD_UINT32 *puiEncDataLength);
	
/*
功能描述:对称算法解密
参数:
	hSessionHandle		输入,会话句柄.
	pucKey				输入,密钥.
	uiAlgID				输入,加密模式,取值 SGD_SM1_ECB/SGD_SM1_CBC/SGD_SM1_OFB/SGD_SM4_ECB/SGD_SM4_CBC/SGD_SM4_OFB.
	pucIV				输入/输出,初始向量, CBC OFB模式使用.
	pucEncData			输入,要解密的数据.
	uiEncDataLength		输入,要解密的数据的长度,必须为16的整数倍,且最大4000字节.
	pucData				输出,解密后的数据.
	puiDataLength		输入/输出,输入是表示pucData的空间大小,输出时表示解密后的数据的长度.
返回值:
	 返回SDR_OK成功,其他值失败;
*/
SGD_RV SDF_Decrypt(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucKey, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucEncData, SGD_UINT32 uiEncDataLength, SGD_UCHAR *pucData, SGD_UINT32 *puiDataLength);

/*
功能描述:IPSEC数据加密
参数:
	hSessionHandle		输入,会话句柄.
	pucEncKey			输入,加密用密钥.
	uiAlgID				输入,加密模式,取值 SGD_IPSEC_SM1/SGD_IPSEC_SM4.
	pucIV				输入/输出,初始向量.
	HMACKEY				输入,计算HMAC的密钥.
	HMACKEYLEN			输入,HMAC的密钥长度
	pucData				输入,要加密的数据,包括24字节头和待加密的数据，待加密的数据长度必须为16的整数倍.
	uiDataLen			输入,要加密的数据的长度,必须为24+16的整数倍(24+16n),且最大4096字节.
	pucEncData			输出,加密后的数据.
	puiEncDataLen		输入/输出,输入是表示pucEncData的空间大小,输出时表示输出数据的实际长度.
返回值:
	 返回SDR_OK成功,其他值失败;
*/
SGD_RV SDF_Encrypt_IPSEC(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucEncKey, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *HMACKEY, SGD_UINT32 HMACKEYLEN, SGD_UCHAR *pucData, SGD_UINT32 uiDataLen, SGD_UCHAR *pucEncData, SGD_UINT32 *puiEncDataLen);
	
/*
功能描述:IPSEC数据解密
参数:
	hSessionHandle		输入,会话句柄.
	pucDecKey			输入,解密用密钥.
	uiAlgID				输入,加密模式,取值 SGD_IPSEC_SM1/SGD_IPSEC_SM4.
	pucIV				输入/输出,初始向量.
	HMACKEY				输入,计算HMAC的密钥.
	pucEncData			输入,要解密的数据,包括24字节头和待解密的数据，待解密的数据长度必须为16的整数倍.
	uiEncDataLen		输入,要解密的数据的长度,必须为24+16的整数倍(24+16n),且最大4096字节.
	pucOutputData		输出,解密后的数据.
	puiOutputDataLen	输入/输出,输入是表示pucOutputData的空间大小,输出时表示输出数据的实际长度.
返回值:
	 返回SDR_OK成功,其他值失败;
*/
SGD_RV SDF_Decrypt_IPSEC(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucDecKey, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *HMACKEY, SGD_UINT32 HMACKEYLEN, SGD_UCHAR *pucEncData, SGD_UINT32 uiEncDataLen, SGD_UCHAR *pucOutputData, SGD_UINT32 *puiOutputDataLen);

/*
功能:哈希初始化
参数:
	hSessionHandle		输入,会话句柄.
	uiAlgID				输入,算法类型,当前只支持SGD_SM3.	
	pucPublicKey		输入,公钥数据,SM2密钥的公钥,用于获取Z值.
	pucID				输入,用户ID,用于获取Z值.
	uiIDLength			输入, pucID的长度.
返回值:
	 返回SDR_OK成功,其他值失败;
*/
SGD_RV SDF_HashInit(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucID, SGD_UINT32 uiIDLength);
	
/*
功能:哈希
参数:
	hSessionHandle		输入,会话句柄.
	pucData				输入,要处理的数据.
	uiDataLength		输入, pucData的长度,最大2016字节.
返回值:
	 返回SDR_OK成功,其他值失败;
*/
SGD_RV SDF_HashUpdate(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength);

/*
功能:哈希结束
参数:
	 hSessionHandle		输入,会话句柄.
	 pucHash			输出,处理后的数据.
	 puiHashLength		输入/输出, 输入时表示pucHash的空间大小,输出时表示返回数据pucHash的长度.
返回值:
	 返回SDR_OK成功,其他值失败;
*/
SGD_RV SDF_HashFinal(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucHash, SGD_UINT32 *puiHashLength);
	

#ifdef __cplusplus
}
#endif

#endif /*#ifndef _SDF_H_*/
