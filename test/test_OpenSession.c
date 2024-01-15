//gcc -o test_OpenSession test_OpenSession.c /home/ljm/zBESHELJP/zbishe/src/sdf1.c Unity/src/unity.c -IUnity/src


#include "unity.h"
#include <stdlib.h>

// 假设的类型定义和宏定义
typedef int SGD_RV;
typedef void* SGD_HANDLE;

#define SDR_OK 0
#define SDR_UNKNOWERR -1

// 待测试的函数声明
SGD_RV SDF_OpenSession(SGD_HANDLE hDeviceHandle, SGD_HANDLE *phSessionHandle);



void setUp(void) {
    // 在这里执行任何需要在每个测试之前运行的设置代码
}

void tearDown(void) {
    // 在这里执行任何需要在每个测试之后运行的清理代码
}

// 测试函数
void test_SDF_OpenSession_Should_AllocateSessionHandle_And_Return_SDR_OK(void) {
    SGD_HANDLE deviceHandle = malloc(sizeof(SGD_HANDLE)); // 假设设备句柄已经打开
    SGD_HANDLE sessionHandle = NULL;
    SGD_RV result;

    result = SDF_OpenSession(deviceHandle, &sessionHandle);

    // 验证返回值是否为SDR_OK
    TEST_ASSERT_EQUAL_INT(SDR_OK, result);

    // 验证会话句柄是否已分配
    TEST_ASSERT_NOT_NULL(sessionHandle);

    // 如果分配了内存，释放它
    if (sessionHandle != NULL) {
        free(sessionHandle);
    }
    free(deviceHandle); // 释放设备句柄的内存

    // 输出测试结果
    printf("测试 SDF_OpenSession: 返回值 = %d, 会话句柄是否分配 = %s\n", result, sessionHandle ? "已分配" : "未分配");
}

// 失败的测试函数
void test_SDF_OpenSession_Should_Fail_When_Handle_Not_Allocated(void) {
    SGD_HANDLE deviceHandle = malloc(sizeof(SGD_HANDLE)); // 假设设备句柄已经打开
    SGD_HANDLE sessionHandle = NULL;
    SGD_RV result;

    result = SDF_OpenSession(deviceHandle, &sessionHandle);

    // 输出测试执行前的信息
    printf("执行故意失败的测试: SDF_OpenSession 应当返回错误码并且不分配会话句柄\n");

    // 故意验证错误的条件
    TEST_ASSERT_EQUAL_INT(SDR_UNKNOWERR, result); // 期望返回一个错误的状态码
    TEST_ASSERT_NULL(sessionHandle); // 期望会话句柄没有被分配

    // 输出测试结果
    printf("故意失败的测试结果: 返回值 = %d, 会话句柄是否分配 = %s\n", result, sessionHandle ? "已分配" : "未分配");

    // 如果分配了内存，释放它
    if (sessionHandle != NULL) {
        free(sessionHandle);
    }
    free(deviceHandle); // 释放设备句柄的内存
}

// 主函数，运行所有测试
int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_SDF_OpenSession_Should_AllocateSessionHandle_And_Return_SDR_OK);
    RUN_TEST(test_SDF_OpenSession_Should_Fail_When_Handle_Not_Allocated); // 运行故意失败的测试
    return UNITY_END();
    }
