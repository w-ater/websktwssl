#include <stdio.h>
//#include <openssl/ssl.h>
//#include <openssl/err.h>
//#include "ws_com.h"
#include <string.h>
#include "wsl.h"
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>

//发包数据量 10K
#define SEND_PKG_MAX (1024 * 10)

//收包缓冲区大小 10K+
#define RECV_PKG_MAX (SEND_PKG_MAX + 16)
//#define SERVER_IP "192.168.1.102"
#define SERVER_IP "ipc.daguiot.com"

//int au_server_init(SSL **ssl);
char recv_buff1[256];
char send_buff2[256];
int isConnected=0;


static int quit = 0;

static void sighandler(int sig)
{
    quit = 1;
    printf("quit\n");
}

void ws_buildCode2001(char* package)
{
    const char CheckToken[] = "{\"code\":2001,\"sn\":\"6902200010110883\",\"message\":\"test\"}";

    sprintf(package, CheckToken);
	printf("package %s\n",package);

}

void ws_buildCode01(char* package)
{
    const char CheckToken[] = "{\"code\":1,\"message\":\"deviceinfo\",\"data\":{\"iccid\":\"\",\"link\":0,\"use\":0,\"sn\":\"6902200010110823\",\"hv\":\"TX5112CV300\",\"sv\":\"v1.0.0.1\"}}";

    sprintf(package, CheckToken);
	printf("package %s\n",package);

}

char buffjson[256] = {0};
static void ws_buildtest(char* str, char* package)
{
    const char teststr[] =
		"{\r\n"
        "\"code\":50,\r\n"
		//"\"message\":\"check_token\",\r\n"
		"\"data\":{\"data\":\"%s\"\r\n}\r\n"
		"}\r\n";
    sprintf(package, teststr, str);
	printf("package %s",package);
}

int handleData(char* data, int length) {
    printf("Received data: %s\n", data);
}

int GetStatus(bool *is4gOk, bool *isSgOk) {
    printf("OnStatus is4gOk %d isSgOk: %d\n", *is4gOk,*isSgOk);
}

void sendata(void *arg)
{
	int rett;
	while(1){
		memset(send_buff2, 0, sizeof(send_buff2));
		printf("请输入send_str\n");
		scanf("%s",send_buff2); 
		
		if(isConnected)
		{
			memset(send_buff2, 0, sizeof(send_buff2));   
			//创建协议包
			ws_buildtest(send_buff2,buffjson); //组装http请求头
			rett =	wssend(buffjson, strlen((const char*)buffjson));
			if (rett > 0)
			{
				printf("rett %d send_buff2%s\r\n", rett,buffjson);
			}else if ((rett == 0) && (errno == EWOULDBLOCK || errno == EINTR)){
				//printf("No receive data   !!\r\n");
			}else{
				perror("111Failed to connection");
				printf("abnormal connection  rett%d  errno%d %d %d!!\r\n",rett,errno,EWOULDBLOCK,EINTR);
			}
		}
	}

}

int main(int argc,char *argv[])
{
		//int port = SERVER_PORT;
		char ip[32] = SERVER_IP;
		//char path[64] = SERVER_PATH;
		int ret;
		static pthread_t p_send;
		
		if (argc > 1) {
			memset(ip, 0, sizeof(ip));
			strcpy(ip, argv[1]);
		}
		/*if (argc > 2) {
			sscanf(argv[2], "%d", &port);
		}
		if (argc > 3) {
			memset(path, 0, sizeof(path));
			strcpy(path, argv[3]);
		}*/

		//SSL *ssl = NULL;

        printf("静态库测试 : \n");
		
		//ret = get4GSerialOutput("echo -e 'AT+MDIALUPCFG=\"auto\"' > /dev/ttyUSB2",send_buff2);
		//return 0;
		char *snstr = "6902200010110883";//6902200010111237 6902200010110883
		wslConnect(snstr,handleData,GetStatus);
        return 0;
}

