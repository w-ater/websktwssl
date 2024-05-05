#ifndef _WSL_H_
#define _WSL_H_

#ifdef __cplusplus
extern "C"
{
#endif
typedef void (*Ondata)(char* data, int length);
typedef void (*OnStatus)(int *is4gOk, int *isSgOk);

int wslConnect(char *snStr, Ondata handleJson, OnStatus linkStatus);

int get4GSerialOutput(const char *strCmd, char *buffer);

#ifdef __cplusplus
}
#endif

#endif // _WS_COM_H_
