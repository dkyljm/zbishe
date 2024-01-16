//gcc -o test_CloseSession test_CloseSession.c /home/ljm/zBESHELJP/zbishe/src/sdf1.c Unity/src/unity.c -IUnity/src


#include "unity.h" 
#include <stdlib.h>
#include "/home/ljm/zBESHELJP/zbishe/include/sdf.h" // 假设sdf.h包含了SDF_CloseSession的声明


void setUp(void) {
    // 在这里执行任何需要在每个测试之前运行的设置代码
}

void tearDown(void) {
    // 在这里执行任何需要在每个测试之后运行的清理代码
}

void test_SDF_CloseSession_validSession() {
    SGD_HANDLE sessionHandle = malloc(sizeof(SGD_HANDLE))/* 有效的会话句柄 */;
    
     // 调用 SDF_CloseSession 函数
    SGD_RV result = SDF_CloseSession(sessionHandle);

    // 使用 Unity 提供的测试宏来检查结果
    TEST_ASSERT_EQUAL(SDR_OK, result);  // 期望返回 SDR_OK
    if (result == SDR_OK) {
        printf("Test test_SDF_CloseSession_validSession passed.\n");
    } else {
        printf("Test test_SDF_CloseSession_validSession failed.\n");
    }
}

void test_SDF_CloseSession_invalidSession() {
    SGD_HANDLE invalidSessionHandle = NULL;
    
    // 调用 SDF_CloseSession 函数
    SGD_RV result = SDF_CloseSession(invalidSessionHandle);

    // 使用 Unity 提供的测试宏来检查结果
    TEST_ASSERT_EQUAL(SDR_OPENDEVICE, result);  // 期望返回 SDR_OPENDEVICE
    if (result == SDR_OPENDEVICE) {
        printf("Test test_SDF_CloseSession_invalidSession passed.\n");
    } else {
        printf("Test test_SDF_CloseSession_invalidSession failed.\n");
    }
}

int main() {
    UNITY_BEGIN();

    // 注册测试
    RUN_TEST(test_SDF_CloseSession_validSession);
    RUN_TEST(test_SDF_CloseSession_invalidSession);

    UNITY_END();
    return 0;
}
