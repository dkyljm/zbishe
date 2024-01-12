//gcc -o test_OpenDevice test_OpenDevice.c /home/ljm/zBESHELJP/zbishe/src/sdf1.c Unity/src/unity.c -IUnity/src


#include "unity.h"
#include <stdlib.h>

// 你的 SDF_OpenDevice 函数的声明
typedef int SGD_RV;
typedef void* SGD_HANDLE;

#define SDR_OK 0
#define SDR_MALLOCFAILED -1

SGD_RV SDF_OpenDevice(SGD_HANDLE *phDeviceHandle);


void setUp(void) {
    // 在这里执行任何需要在每个测试之前运行的设置代码
}

void tearDown(void) {
    // 在这里执行任何需要在每个测试之后运行的清理代码
}

// 测试 SDF_OpenDevice 函数
void test_SDF_OpenDevice(void) {
    SGD_HANDLE deviceHandle = NULL;
    SGD_RV result;

    result = SDF_OpenDevice(&deviceHandle);

    // 测试是否返回成功
    TEST_ASSERT_EQUAL_INT(SDR_OK, result);

    // 测试设备句柄是否非空
    TEST_ASSERT_NOT_NULL(deviceHandle);

    // 如果分配了内存，释放它
    if (deviceHandle != NULL) {
        free(deviceHandle);
    }

    // 如果你想在控制台输出测试通过的信息，可以使用下面的代码
    printf("Test SDF_OpenDevice: Result = %d, Device Handle is %sNULL\n", result, deviceHandle ? "not " : "");
}

// 主函数，运行测试
int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_SDF_OpenDevice);
    return UNITY_END();
}
