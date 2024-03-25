#ifndef _WSL_H_
#define _WSL_H_

#ifdef __cplusplus
extern "C"
{
#endif


int au_server_init(char *get_ip);

int setrecdataca11(int (*handleData)(char* data, int length));

int wssend(char *buf,int len);

//int IsWsClosed();

int closewsl();

#ifdef __cplusplus
}
#endif

#endif // _WS_COM_H_
