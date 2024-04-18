#include <stdio.h>
//#include <openssl/ssl.h>
//#include <openssl/err.h>
//#include "ws_com.h"
#include <string.h>
#include "wsl.h"
#include <pthread.h>
#include <errno.h>

//发包数据量 10K
#define SEND_PKG_MAX (1024 * 10)

//收包缓冲区大小 10K+
#define RECV_PKG_MAX (SEND_PKG_MAX + 16)
//#define SERVER_IP "192.168.1.102"
#define SERVER_IP "ipc.daguiot.com"

//int au_server_init(SSL **ssl);
char recv_buff1[256];
char send_buff[256];
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
void sendata(void *arg)
{
	int rett;
	while(1){
		memset(send_buff, 0, sizeof(send_buff));
		printf("请输入send_str\n");
		scanf("%s",send_buff); 
		
		if(isConnected)
		{
			memset(send_buff, 0, sizeof(send_buff));   
			//创建协议包
			ws_buildtest(send_buff,buffjson); //组装http请求头
			rett =	wssend(buffjson, strlen((const char*)buffjson));
			if (rett > 0)
			{
				printf("rett %d send_buff%s\r\n", rett,buffjson);
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
		char *snstr = "6902200010111237";//6902200010111237 6902200010110883
		WS_GET_SN(snstr);
		
		ret = au_server_init(ip);
		if (ret < 0)
		{
			printf("au fail\n");
			//return -1;
		}
		
		//ret = IsWsClosed();
		//closewsl();
		char httpHead[512] = {0};
		memset(httpHead, 0, sizeof(httpHead));   
		//创建协议包
		ws_buildCode2001(httpHead); //组装http请求头

		wssend(httpHead, strlen((const char*)httpHead));
		
		//pthread_create(&p_send, 0, sendata, 0);
		//pthread_join(p_send, NULL);

		while(!quit){
			/*if(IsWsClosed()==1){
				printf("******disconnect server******\n");
				isConnected=0;
				au_server_init();
				//exit(0);
			}else{*/
				//check_tcp_alive();
				ret = sendHeart(0);
				if (ret < 0)
				{
					printf("******disconnect server******\n");
					closewsl();
					//break;
					ret = au_server_init(ip);
					if(ret < 0){
						isConnected=0;
						continue;
					}
				}
				ret = setrecdataca11(handleData);
				if (ret > 0)
				{
					isConnected=1;
					printf("test!!!%s\r\n", recv_buff1);
				}else if(ret == 0){
					//printf("No receive data   !!\r\n");
				}else{
					printf("******disconnect server******\n");
					closewsl();
					//break;
					ret = au_server_init(ip);
					if(ret < 0){
						isConnected=0;
						continue;
					}
				}
				
				//printf("******\nconnect server******\n");
			//}
			usleep(10000);
		}

		printf("connect exit !!\r\n");	

        return 0;
}

