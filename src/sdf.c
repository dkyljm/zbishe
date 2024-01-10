#include "/home/ljm/zBESHELJP/Xiangmu1/include/sdf.h"
#include <stdlib.h>
#include <stdio.h>

SGD_HANDLE tmpHandle =  0x126790;
SGD_HANDLE tmp =  0x0;

SGD_RV SDF_OpenDevice(SGD_HANDLE *phDeviceHandle){

        *phDeviceHandle=tmpHandle;
        return SDR_OK;

}

SGD_RV SDF_CloseDevice(SGD_HANDLE hDeviceHandle){
	hDeviceHandle=tmp;
        return SDR_OK;
}


SGD_RV SDF_OpenSession(SGD_HANDLE hDeviceHandle, SGD_HANDLE *phSessionHandle) {
    // 这里应该包含具体的实现代码，用于打开新的会话

    // 例如，假设要分配内存并将其地址存储在*phSessionHandle中
    *phSessionHandle = malloc(sizeof(SGD_HANDLE));

    

    // 进行一些其他初始化操作...

    // 返回成功状态码
    return SDR_OK;
}


SGD_RV SDF_CloseSession(SGD_HANDLE hSessionHandle) {
    // 这里应该包含具体的实现代码，用于关闭会话

    // 假设有一些操作，比如释放相关资源、关闭会话等
    // 这里的实现是示意性的，具体内容根据实际情况来编写

    // 例如，假设需要释放通过会话句柄引用的内存
    free(hSessionHandle);

    // 返回成功状态码
    return SDR_OK;
}



