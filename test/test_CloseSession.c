#include "unity.h" 
#include <stdlib.h>
#include "/home/ljm/zBESHELJP/zbishe/include/sdf.h" // 假设sdf.h包含了SDF_CloseSession的声明


#define SDR_GENERALERROR (0x0)

void setUp(void) {
    // 在这里执行任何需要在每个测试之前运行的设置代码
}

void tearDown(void) {
    // 在这里执行任何需要在每个测试之后运行的清理代码
}

// 成功测试用例
void test_SDF_CloseSession_Success(void) {
    SGD_HANDLE sessionHandle = malloc(sizeof(SGD_HANDLE)); // 分配内存模拟会话句柄
    if (sessionHandle == NULL) {
        TEST_FAIL_MESSAGE("内存分配失败，无法进行测试");
    }
    SGD_RV result = SDF_CloseSession(sessionHandle);
    TEST_ASSERT_EQUAL_INT(SDR_OK, result); // 断言返回值为成功状态码
    printf("成功测试: SDF_CloseSession 返回 SDR_OK，会话句柄关闭。\n");
}

// 失败测试用例
void test_SDF_CloseSession_Failure(void) {
    SGD_HANDLE sessionHandle = NULL; // 模拟无效的会话句柄
    SGD_RV result = SDF_CloseSession(sessionHandle);
    TEST_ASSERT_EQUAL_INT(SDR_GENERALERROR, result); // 断言返回值为错误状态码
    printf("失败测试: SDF_CloseSession 返回 SDR_GENERALERROR，无效的会话句柄。\n");
}

// 主函数，运行测试
int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_SDF_CloseSession_Success);
    RUN_TEST(test_SDF_CloseSession_Failure);
    return UNITY_END();
}
