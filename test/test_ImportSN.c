//gcc -o test_Import test_ImportSN.c /home/ljm/zBESHELJP/zbishe/src/sdf1.c Unity/src/unity.c -IUnity/src



#include "unity.h"
#include "/home/ljm/zBESHELJP/zbishe/include/sdf.h"  // 请替换成实际的库头文件
#define ROOTKEY   "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"
#define DEVSN "besti_0000001"

void setUp(void) {
    // 在这里执行任何需要在每个测试之前运行的设置代码
}

void tearDown(void) {
    // 在这里执行任何需要在每个测试之后运行的清理代码
}


void test_SDF_ImportRootKeyAndDeviceSN_Success(void) {
    // 设置测试数据
    SGD_HANDLE phSessionHandle;  // 假设已经定义了会话句柄
    SGD_UINT8 rootKey[16] = ROOTKEY;  // 请替换成实际的 RootKey
    SGD_UINT8 devSN[16] = DEVSN;  // 请替换成实际的 DeviceSN

    // 调用 SDF_ImportRootKeyAndDeviceSN 函数
    SGD_RV rv = SDF_ImportRootKeyAndDeviceSN(phSessionHandle, rootKey, devSN, 16);

    // 使用 CUnity 断言检查测试结果
    TEST_ASSERT_EQUAL_INT_MESSAGE(SDR_OK, rv, "Importing RootKey and DeviceSN should succeed");
}

void test_SDF_ImportRootKeyAndDeviceSN_Failure(void) {
    // 设置测试数据
    SGD_HANDLE phSessionHandle;  // 假设已经定义了会话句柄
    SGD_UINT8 rootKey[16] = ROOTKEY;  // 请替换成实际的 RootKey
    SGD_UINT8 devSN[16] = DEVSN;  // 请替换成实际的 DeviceSN

    // 模拟导入失败的情况
    // 这里可以修改测试数据或调整 SDF_ImportRootKeyAndDeviceSN 的实现，使其返回失败的错误码

    // 调用 SDF_ImportRootKeyAndDeviceSN 函数
    SGD_RV rv = SDF_ImportRootKeyAndDeviceSN(phSessionHandle, rootKey, devSN, 16);

    // 使用 CUnity 断言检查测试结果
    TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(SDR_OK, rv, "Importing RootKey and DeviceSN should fail");
}

int main(void) {
    UNITY_BEGIN();

    // 运行测试
    RUN_TEST(test_SDF_ImportRootKeyAndDeviceSN_Success);
    RUN_TEST(test_SDF_ImportRootKeyAndDeviceSN_Failure);

    return UNITY_END();
}

