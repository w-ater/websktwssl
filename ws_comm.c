
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h> //使用 malloc, calloc等动态分配内存方法
#include <time.h>   //获取系统时间
#include <errno.h>
#include <pthread.h>
#include <fcntl.h> //非阻塞
#include <sys/un.h>
#include <arpa/inet.h>  //inet_addr()
#include <unistd.h>     //close()
#include <sys/types.h>  //文件IO操作
#include <sys/socket.h> //
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h> //gethostbyname, gethostbyname2, gethostbyname_r, gethostbyname_r2
#include <sys/un.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h> //SIOCSIFADDR

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "ws_com.h"

#include <stdio.h>
#include <stdlib.h> //exit()
#include <string.h>
#include <errno.h>
#include <unistd.h> //getpid

#include "ws_com.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
 
#include <regex.h>
#include <stdbool.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "./wolfssl/openssl/ssl.h"  //wolfssl转openssl的兼容层
#include "./wolfssl/ssl.h" 

#include "wsl.h"


//发包数据量 10K
#define SEND_PKG_MAX (1024 * 10)

//收包缓冲区大小 10K+
#define RECV_PKG_MAX (SEND_PKG_MAX + 2)
//#define SERVER_IP "192.168.100.111"
//#define SERVER_IP "192.168.1.102"
//#define SERVER_IP "192.168.100.1"

//http://192.168.1.102:7778/server
//#define SERVER_PORT 7758

#define SERVER_IP "ipc.daguiot.com"
#define SERVER_PORT 7778
#define SERVER_PATH "/server"
//#define SERVER_PATH "wss://192.168.1.102:7758/device?sn=6902200000099994&type=0"
//#define SERVER_PATH "/device?sn=6902200000099994&type=0"
/*
#ifdef WS_DEBUG
#define WS_INFO(...) fprintf(stdout, "[WS_INFO] %s(%d): ", __FUNCTION__, __LINE__),fprintf(stdout, __VA_ARGS__)
#define WS_ERR(...) fprintf(stderr, "[WS_ERR] %s(%d): ", __FUNCTION__, __LINE__),fprintf(stderr, __VA_ARGS__)
#else
#define WS_INFO(...)
#define WS_ERR(...) 
#endif
*/

#define NONE_LEVEL 0
#define INFO_LEVEL 1
#define ERR_LEVEL  2


#define LOG_LEVEL 1//打印级别控制的宏定义

#if(LOG_LEVEL == NONE_LEVEL)
#define WS_INFO(...)
#define WS_ERR(...) 
#elif(LOG_LEVEL == INFO_LEVEL)
/*#define WS_INFO(...) do { \
    time_t now = time(NULL); \
    struct tm *t = localtime(&now); \
    char timestamp[20]; \
    strftime(timestamp, 20, "%Y-%m-%d %H:%M:%S", t); \
    fprintf(stdout, "[WS_INFO] %s(%d) [%s]: ", timestamp, __LINE__, __FUNCTION__); \
    fprintf(stdout, __VA_ARGS__); \
} while(0)*/

#define WS_INFO(...) fprintf(stdout, "[WS_INFO] %s(%d): ", __FUNCTION__, __LINE__),fprintf(stdout, __VA_ARGS__)
#define WS_ERR(...) fprintf(stderr, "[WS_ERR] %s(%d): ", __FUNCTION__, __LINE__),fprintf(stderr, __VA_ARGS__)
#elif(LOG_LEVEL == ERR_LEVEL)
#define WS_INFO(...) fprintf(stdout, "[WS_INFO] %s(%d): ", __FUNCTION__, __LINE__),fprintf(stdout, __VA_ARGS__)
#endif

#define MY_BUF_SIZE 256
#include <stdarg.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>




void myprint(const char *format, ...) {
    struct timeval tv;

    // 获取当前时间
    gettimeofday(&tv, NULL);

    time_t now = tv.tv_sec;
    struct tm *t = localtime(&now);
    char strTime[1000] = {0};
    snprintf(strTime, 999, "[%4d-%02d-%02d %02d:%02d:%02d:%03ld] %s(%d) %s\n", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, tv.tv_usec / 1000, __FUNCTION__, __LINE__, format);

    va_list args; // 定义一个 va_list 类型的变量
    va_start(args, format); // 初始化 va_list 变量

    vprintf(strTime, args); // 使用 vprintf 函数打印可变数量的参数

    va_end(args); // 清理 va_list 变量
}


SSL *myssl = NULL;
SSL_CTX *ctx = NULL;

int fd=-1,myfd=-1,pid;
Ws_DataType retPkgType;
pthread_mutex_t mutex;

char recv_buff[RECV_PKG_MAX];
char send_buff[SEND_PKG_MAX];
unsigned char token_checksume[64];
char token_checksume1[128];
char tokenjson[MY_BUF_SIZE] = {0};

//char ctoken_checksume[128];

static int port = SERVER_PORT;
int get_port = SERVER_PORT;
char ip[32] = SERVER_IP;
char path[64] = SERVER_PATH;
int recv_len;

int net_stat;
static int heart = 0;
static int nopong_cnt = 0;
static int g_hbdiscnt = 0;
static bool g_isSg = 0;
static bool g_is4G = 0;
static bool g_is4GDail = 0;
static bool g_fb4GDail = 0;

int interval = 5; // 默认心跳间隔

static pthread_t gHeartThread;
static bool      gHeartThreadExit;
static pthread_t gWebsocketThread;
static bool      gWebsocketThreadExit;
static pthread_t gLink4gThread;
static bool      gLink4gThreadExit;

static bool      gWslConnectExit;


static void WS_HEX(FILE* f, void* dat, uint32_t len)
{
    uint8_t* p = (uint8_t*)dat;
    uint32_t i;
    for (i = 0; i < len; i++)
        fprintf(f, "%02X ", p[i]);
    fprintf(f, "\r\n");
}

//稍微精准的延时
#include <sys/time.h>
void ws_delayus(uint32_t us)
{
    struct timeval tim;
    tim.tv_sec = us / 1000000;
    tim.tv_usec = us % 1000000;
    select(0, NULL, NULL, NULL, &tim);
}
void ws_delayms(uint32_t ms)
{
    ws_delayus(ms * 1000);
}

//返回时间戳字符串,格式 HH:MM:SS
char* ws_time(void)
{
    static char timeStr[9] = {0};
    struct timeval tv = {0};
    gettimeofday(&tv, NULL);
    snprintf(timeStr, sizeof(timeStr), "%02ld:%02ld:%02ld",
             (tv.tv_sec % 86400 / 3600 + 8) % 24,
             tv.tv_sec % 3600 / 60,
             tv.tv_sec % 60);
    return timeStr;
}

//==================== 域名转IP ====================

typedef struct
{
    pthread_t thread_id;
    char ip[MY_BUF_SIZE];
    bool result;
    bool actionEnd;
} GetHostName_Struct;

static void* ws_getHostThread(void* argv)
{
    int32_t ret;
    //int32_t i;
    char buf[1024];
    struct hostent host_body, *host = NULL;
    struct in_addr **addr_list;
    GetHostName_Struct *gs = (GetHostName_Struct *)argv;

    /*  此类方法不可重入!  即使关闭线程
    if((host = gethostbyname(gs->ip)) == NULL)
    //if((host = gethostbyname2(gs->ip, AF_INET)) == NULL)
    {
        gs->actionEnd = true;
        return NULL;
    }*/
    if (gethostbyname_r(gs->ip, &host_body, buf, sizeof(buf), &host, &ret))
    {
        gs->actionEnd = true;
        return NULL;
    }

    if (host == NULL)
    {
        gs->actionEnd = true;
        return NULL;
    }

    addr_list = (struct in_addr **)host->h_addr_list;
    // WS_INFO("ip name: %s\r\nip list: ", host->h_name);
    // for(i = 0; addr_list[i] != NULL; i++)
    //     WS_INFO("%s, ", inet_ntoa(*addr_list[i]));
    // WS_INFO("\r\n");

    //一个域名可用解析出多个ip,这里只用了第一个
    if (addr_list[0] == NULL)
    {
        gs->actionEnd = true;
        return NULL;
    }
    memset(gs->ip, 0, sizeof(gs->ip));
    strcpy(gs->ip, (char*)(inet_ntoa(*addr_list[0])));
    gs->result = true;
    gs->actionEnd = true;
    return NULL;
}

//域名转IP工具,成功返回大于0请求时长ms,失败返回负值的请求时长ms
int32_t ws_getIpByHostName(const char* hostName, char* retIp, int32_t timeoutMs)
{
    int32_t timeout = 0;
    GetHostName_Struct gs;
    if (!hostName || strlen(hostName) < 1)
        return -1;
    //开线程从域名获取IP
    memset(&gs, 0, sizeof(GetHostName_Struct));
    strcpy(gs.ip, hostName);
    gs.result = false;
    gs.actionEnd = false;
    if (pthread_create(&gs.thread_id, NULL, ws_getHostThread, &gs) < 0)
        return -1;
    //等待请求结果
    do {
        ws_delayms(1);
    } while (!gs.actionEnd && ++timeout < timeoutMs);
    //pthread_cancel(gs.thread_id);
    pthread_join(gs.thread_id, NULL);
    if (!gs.result)
        return -timeout;
    //一个域名可用解析出多个ip,这里只用了第一个
    memset(retIp, 0, strlen((const char*)retIp));
    strcpy(retIp, gs.ip);
    return timeout;
}

//==================== 加密方法BASE64 ====================

//base64编/解码用的基础字符集
static const char ws_base64char[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*******************************************************************************
 * 名称: ws_base64_encode
 * 功能: ascii编码为base64格式
 * 参数: 
 *      bindata: ascii字符串输入
 *      base64: base64字符串输出
 *      binlength: bindata的长度
 * 返回: base64字符串长度
 * 说明: 无
 ******************************************************************************/
int32_t ws_base64_encode(const uint8_t* bindata, char* base64, int32_t binlength)
{
    int32_t i, j;
    uint8_t current;
    for (i = 0, j = 0; i < binlength; i += 3)
    {
        current = (bindata[i] >> 2);
        current &= (uint8_t)0x3F;
        base64[j++] = ws_base64char[(int32_t)current];
        current = ((uint8_t)(bindata[i] << 4)) & ((uint8_t)0x30);
        if (i + 1 >= binlength)
        {
            base64[j++] = ws_base64char[(int32_t)current];
            base64[j++] = '=';
            base64[j++] = '=';
            break;
        }
        current |= ((uint8_t)(bindata[i + 1] >> 4)) & ((uint8_t)0x0F);
        base64[j++] = ws_base64char[(int32_t)current];
        current = ((uint8_t)(bindata[i + 1] << 2)) & ((uint8_t)0x3C);
        if (i + 2 >= binlength)
        {
            base64[j++] = ws_base64char[(int32_t)current];
            base64[j++] = '=';
            break;
        }
        current |= ((uint8_t)(bindata[i + 2] >> 6)) & ((uint8_t)0x03);
        base64[j++] = ws_base64char[(int32_t)current];
        current = ((uint8_t)bindata[i + 2]) & ((uint8_t)0x3F);
        base64[j++] = ws_base64char[(int32_t)current];
    }
    base64[j] = '\0';
    return j;
}
/*******************************************************************************
 * 名称: ws_base64_decode
 * 功能: base64格式解码为ascii
 * 参数: 
 *      base64: base64字符串输入
 *      bindata: ascii字符串输出
 * 返回: 解码出来的ascii字符串长度
 * 说明: 无
 ******************************************************************************/
int32_t ws_base64_decode(const char* base64, uint8_t* bindata)
{
    int32_t i, j;
    uint8_t k;
    uint8_t temp[4];
    for (i = 0, j = 0; base64[i] != '\0'; i += 4)
    {
        memset(temp, 0xFF, sizeof(temp));
        for (k = 0; k < 64; k++)
        {
            if (ws_base64char[k] == base64[i])
                temp[0] = k;
        }
        for (k = 0; k < 64; k++)
        {
            if (ws_base64char[k] == base64[i + 1])
                temp[1] = k;
        }
        for (k = 0; k < 64; k++)
        {
            if (ws_base64char[k] == base64[i + 2])
                temp[2] = k;
        }
        for (k = 0; k < 64; k++)
        {
            if (ws_base64char[k] == base64[i + 3])
                temp[3] = k;
        }
        bindata[j++] = ((uint8_t)(((uint8_t)(temp[0] << 2)) & 0xFC)) |
                       ((uint8_t)((uint8_t)(temp[1] >> 4) & 0x03));
        if (base64[i + 2] == '=')
            break;
        bindata[j++] = ((uint8_t)(((uint8_t)(temp[1] << 4)) & 0xF0)) |
                       ((uint8_t)((uint8_t)(temp[2] >> 2) & 0x0F));
        if (base64[i + 3] == '=')
            break;
        bindata[j++] = ((uint8_t)(((uint8_t)(temp[2] << 6)) & 0xF0)) |
                       ((uint8_t)(temp[3] & 0x3F));
    }
    return j;
}

//==================== 加密方法 sha1哈希 ====================

typedef struct SHA1Context
{
    uint32_t Message_Digest[5];
    uint32_t Length_Low;
    uint32_t Length_High;
    uint8_t Message_Block[64];
    int32_t Message_Block_Index;
    int32_t Computed;
    int32_t Corrupted;
} SHA1Context;

#define SHA1CircularShift(bits, word) ((((word) << (bits)) & 0xFFFFFFFF) | ((word) >> (32 - (bits))))

static void SHA1ProcessMessageBlock(SHA1Context *context)
{
    const uint32_t K[] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};
    int32_t t;
    uint32_t temp;
    uint32_t W[80];
    uint32_t A, B, C, D, E;

    for (t = 0; t < 16; t++)
    {
        W[t] = ((uint32_t)context->Message_Block[t * 4]) << 24;
        W[t] |= ((uint32_t)context->Message_Block[t * 4 + 1]) << 16;
        W[t] |= ((uint32_t)context->Message_Block[t * 4 + 2]) << 8;
        W[t] |= ((uint32_t)context->Message_Block[t * 4 + 3]);
    }

    for (t = 16; t < 80; t++)
        W[t] = SHA1CircularShift(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);

    A = context->Message_Digest[0];
    B = context->Message_Digest[1];
    C = context->Message_Digest[2];
    D = context->Message_Digest[3];
    E = context->Message_Digest[4];

    for (t = 0; t < 20; t++)
    {
        temp = SHA1CircularShift(5, A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30, B);
        B = A;
        A = temp;
    }
    for (t = 20; t < 40; t++)
    {
        temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[1];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30, B);
        B = A;
        A = temp;
    }
    for (t = 40; t < 60; t++)
    {
        temp = SHA1CircularShift(5, A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30, B);
        B = A;
        A = temp;
    }
    for (t = 60; t < 80; t++)
    {
        temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[3];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = SHA1CircularShift(30, B);
        B = A;
        A = temp;
    }
    context->Message_Digest[0] = (context->Message_Digest[0] + A) & 0xFFFFFFFF;
    context->Message_Digest[1] = (context->Message_Digest[1] + B) & 0xFFFFFFFF;
    context->Message_Digest[2] = (context->Message_Digest[2] + C) & 0xFFFFFFFF;
    context->Message_Digest[3] = (context->Message_Digest[3] + D) & 0xFFFFFFFF;
    context->Message_Digest[4] = (context->Message_Digest[4] + E) & 0xFFFFFFFF;
    context->Message_Block_Index = 0;
}

static void SHA1Reset(SHA1Context* context)
{
    context->Length_Low = 0;
    context->Length_High = 0;
    context->Message_Block_Index = 0;

    context->Message_Digest[0] = 0x67452301;
    context->Message_Digest[1] = 0xEFCDAB89;
    context->Message_Digest[2] = 0x98BADCFE;
    context->Message_Digest[3] = 0x10325476;
    context->Message_Digest[4] = 0xC3D2E1F0;

    context->Computed = 0;
    context->Corrupted = 0;
}

static void SHA1PadMessage(SHA1Context* context)
{
    if (context->Message_Block_Index > 55)
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while (context->Message_Block_Index < 64)
            context->Message_Block[context->Message_Block_Index++] = 0;
        SHA1ProcessMessageBlock(context);
        while (context->Message_Block_Index < 56)
            context->Message_Block[context->Message_Block_Index++] = 0;
    }
    else
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while (context->Message_Block_Index < 56)
            context->Message_Block[context->Message_Block_Index++] = 0;
    }
    context->Message_Block[56] = (context->Length_High >> 24) & 0xFF;
    context->Message_Block[57] = (context->Length_High >> 16) & 0xFF;
    context->Message_Block[58] = (context->Length_High >> 8) & 0xFF;
    context->Message_Block[59] = (context->Length_High) & 0xFF;
    context->Message_Block[60] = (context->Length_Low >> 24) & 0xFF;
    context->Message_Block[61] = (context->Length_Low >> 16) & 0xFF;
    context->Message_Block[62] = (context->Length_Low >> 8) & 0xFF;
    context->Message_Block[63] = (context->Length_Low) & 0xFF;

    SHA1ProcessMessageBlock(context);
}

static int32_t SHA1Result(SHA1Context* context)
{
    if (context->Corrupted)
    {
        return 0;
    }
    if (!context->Computed)
    {
        SHA1PadMessage(context);
        context->Computed = 1;
    }
    return 1;
}

static void SHA1Input(SHA1Context* context, const char* message_array, uint32_t length)
{
    if (!length)
        return;

    if (context->Computed || context->Corrupted)
    {
        context->Corrupted = 1;
        return;
    }

    while (length-- && !context->Corrupted)
    {
        context->Message_Block[context->Message_Block_Index++] = (*message_array & 0xFF);

        context->Length_Low += 8;

        context->Length_Low &= 0xFFFFFFFF;
        if (context->Length_Low == 0)
        {
            context->Length_High++;
            context->Length_High &= 0xFFFFFFFF;
            if (context->Length_High == 0)
                context->Corrupted = 1;
        }

        if (context->Message_Block_Index == 64)
        {
            SHA1ProcessMessageBlock(context);
        }
        message_array++;
    }
}

static char* sha1_hash(const char* source)
{
    SHA1Context sha;
    char* buff = NULL;

    SHA1Reset(&sha);
    SHA1Input(&sha, source, strlen(source));

    if (!SHA1Result(&sha))
        WS_INFO("SHA1 ERROR: Could not compute message digest \r\n");
    else
    {
        buff = (char*)calloc(128, sizeof(char));
        sprintf(buff, "%08X%08X%08X%08X%08X",
                sha.Message_Digest[0],
                sha.Message_Digest[1],
                sha.Message_Digest[2],
                sha.Message_Digest[3],
                sha.Message_Digest[4]);
    }
    return buff;
}

//==================== websocket部分 ====================

/*******************************************************************************
 * 名称: ws_getRandomString
 * 功能: 生成随机字符串
 * 参数: 
 *      buff: 随机字符串存储到
 *      len: 生成随机字符串长度
 * 返回: 无
 * 说明: 无
 ******************************************************************************/
static void ws_getRandomString(char* buff, uint32_t len)
{
    uint32_t i;
    uint8_t temp;
    srand((int32_t)time(0));
    for (i = 0; i < len; i++)
    {
        temp = (uint8_t)(rand() % MY_BUF_SIZE);
        if (temp == 0) //随机数不要0
            temp = 128;
        buff[i] = temp;
    }
}

/*******************************************************************************
 * 名称: ws_buildShakeKey
 * 功能: client端使用随机数构建握手用的key
 * 参数: *key: 随机生成的握手key
 * 返回: key的长度
 * 说明: 无
 ******************************************************************************/
static int32_t ws_buildShakeKey(char* key)
{
    char tempKey[16] = {0};
    ws_getRandomString(tempKey, 16);
    return ws_base64_encode((const uint8_t*)tempKey, (char*)key, 16);
}

/*******************************************************************************
 * 名称: ws_buildRespondShakeKey
 * 功能: server端在接收client端的key后,构建回应用的key
 * 参数:
 *      acceptKey: 来自客户端的key字符串
 *      acceptKeyLen: 长度
 *      respondKey:  在 acceptKey 之后加上 GUID, 再sha1哈希, 再转成base64得到 respondKey
 * 返回: respondKey的长度(肯定比acceptKey要长)
 * 说明: 无
 ******************************************************************************/
static int32_t ws_buildRespondShakeKey(char* acceptKey, uint32_t acceptKeyLen, char* respondKey)
{
    char* clientKey;
    char* sha1DataTemp;
    uint8_t* sha1Data;
    int32_t i, j, sha1DataTempLen, ret;
    const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    uint32_t guidLen;

    if (acceptKey == NULL)
        return 0;

    guidLen = sizeof(guid);
    clientKey = (char*)calloc(acceptKeyLen + guidLen + 10, sizeof(char));
    memcpy(clientKey, acceptKey, acceptKeyLen);
    memcpy(&clientKey[acceptKeyLen], guid, guidLen);

    sha1DataTemp = sha1_hash(clientKey);
    sha1DataTempLen = strlen((const char*)sha1DataTemp);
    sha1Data = (uint8_t*)calloc(sha1DataTempLen / 2 + 1, sizeof(char));

    //把hex字符串如"12ABCDEF",转为数值数组如{0x12,0xAB,0xCD,0xEF}
    for (i = j = 0; i < sha1DataTempLen;)
    {
        if (sha1DataTemp[i] > '9')
            sha1Data[j] = (10 + sha1DataTemp[i] - 'A') << 4;
        else
            sha1Data[j] = (sha1DataTemp[i] - '0') << 4;

        i += 1;

        if (sha1DataTemp[i] > '9')
            sha1Data[j] |= (10 + sha1DataTemp[i] - 'A');
        else
            sha1Data[j] |= (sha1DataTemp[i] - '0');

        i += 1;
        j += 1;
    }

    ret = ws_base64_encode((const uint8_t*)sha1Data, (char*)respondKey, j);

    free(sha1DataTemp);
    free(sha1Data);
    free(clientKey);
    return ret;
}

/*******************************************************************************
 * 名称: ws_matchShakeKey
 * 功能: client端收到来自服务器回应的key后进行匹配,以验证握手成功
 * 参数:
 *      clientKey: client端请求握手时发给服务器的key
 *      clientKeyLen: 长度
 *      acceptKey: 服务器回应的key
 *      acceptKeyLen: 长度
 * 返回: 0 成功  -1 失败
 * 说明: 无
 ******************************************************************************/
static int32_t ws_matchShakeKey(char* clientKey, int32_t clientKeyLen, char* acceptKey, int32_t acceptKeyLen)
{
    int32_t retLen;
    char tempKey[MY_BUF_SIZE] = {0};

    retLen = ws_buildRespondShakeKey(clientKey, clientKeyLen, tempKey);
    if (retLen != acceptKeyLen)
    {
        WS_INFO("len err, clientKey[%d] != acceptKey[%d]\r\n", retLen, acceptKeyLen);
        return -1;
    }
    else if (strcmp((const char*)tempKey, (const char*)acceptKey) != 0)
    {
        WS_INFO("strcmp err, clientKey[%s -> %s] != acceptKey[%s]\r\n", clientKey, tempKey, acceptKey);
        return -1;
    }
    return 0;
}
static void ws_buildCheckToken(char* str, char* package)
{
    const char CheckToken[] =
		"{\r\n"
        "\"code\":401,\r\n"
		//"\"message\":\"check_token\",\r\n"
		"\"data\":{\"data\":\"%s\"\r\n}\r\n"
		"}\r\n";
    sprintf(package, CheckToken, str);
	WS_INFO("package %s",package);
}

static void ws_buildCode50(char* package)
{
    const char CheckToken[] = "{\"code\":50,\"message\":\"test\"}";

    sprintf(package, CheckToken);
	WS_INFO("package %s\n",package);

}

/*******************************************************************************
 * 名称: ws_buildHttpHead
 * 功能: 构建client端连接服务器时的http协议头, 注意websocket是GET形式的
 * 参数:
 *      ip: 要连接的服务器ip字符串
 *      port: 服务器端口
 *      path: 要连接的端口地址
 *      shakeKey: 握手key, 可以由任意的16位字符串打包成base64后得到
 *      package: 存储最后打包好的内容
 * 返回: 无
 * 说明: 无
 ******************************************************************************/
static void ws_buildHttpHead(char* ip, int32_t port, char* path,char* shakeKey, char* package)
{
    const char httpDemo[] =
        "GET %s HTTP/1.1\r\n"
        "Connection: Upgrade\r\n"
        "Host: %s:%d\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Upgrade: websocket\r\n\r\n";
    sprintf(package, httpDemo, path, ip, port,shakeKey);
	WS_INFO("package %s",package);
}
/*static void ws_buildHttpHead(char* ip, int32_t port, char* path, char* shakeKey, char* package)
{
    const char httpDemo[] =
        "GET /device?sn=6902200000099994&type=0 HTTP/1.1\r\n"
		"Content-Type: application/json\r\n"
		"sn:6902200000099994\r\n"
		"type:0\r\n";
    sprintf(package, httpDemo, path, ip, port, shakeKey);
}*/
#if 0
char SN[64];

int WS_GET_SN()
{
	char *p;
 
	FILE *fp = fopen("./config", "r");
	if(NULL == fp)
	{
		WS_INFO("failed to open config\n");
		return -1;
	}
 
	while(!feof(fp))
	{
		memset(SN, 0, sizeof(SN));
		fgets(SN, sizeof(SN) - 1, fp); // 包含了换行符
		WS_INFO("%s", SN);
		if ((p = strstr((char*)SN, "sn")) != NULL){
							
				char delims[] = "=";
				char *result = NULL;
				result = strtok(p, delims);
				WS_INFO( "result is %s\n", result );
				//strncpy(ip, result+1,strlen(result));
				//WS_INFO( "ip is %s sizeof ip %d\n", ip,sizeof(ip));
				result = strtok(NULL, delims);
				//WS_INFO( "result is %s   %ld\n", result,strlen(result));
				

			//WS_INFO("111%s", result+1);	
			//WS_INFO("111%s", result+1);
			strcpy(SN,result+1);
			//WS_INFO("222%s", SN);
			SN[strcspn(SN, "\n")] = 0;
			//WS_INFO("333%s %d %ld\n", SN,strlen(SN),sizeof(SN));
			break;

		}
		
	}
 
	fclose(fp);
	return 0;
}
/*在strtok函数中，你传入的是p，而p是一个指向SN数组中的子字符串的指针，而不是一个完整的字符串。strtok函数期望的是一个完整的字符串，因此应该传入SN数组的指针而不是p。你可以将fgets函数的结果直接传给strtok函数。

当使用strtok函数时，它会修改原始字符串。因此，在将result+1的内容复制到SN数组之前，最好先检查result+1的长度是否超过了SN数组的大小，以避免缓冲区溢出。

在使用strtok函数后，最好检查result是否为NULL，以避免在result+1时出现未定义行为。

在将换行符替换为空字符之前，最好先检查SN数组中是否存在换行符，以避免访问越界。*/

char SN[64];

int WS_GET_SN()
{
    char *p;
 
    FILE *fp = fopen("./config", "r");
    if(NULL == fp)
    {
        WS_INFO("failed to open config\n");
        return -1;
    }
 
    while(fgets(SN, sizeof(SN), fp) != NULL)
    {
        WS_INFO("%s", SN);
        if ((p = strstr(SN, "sn")) != NULL){
            char delims[] = "=";
            char *result = NULL;
            result = strtok(SN, delims);
            WS_INFO("result is %s\n", result);

            result = strtok(NULL, delims);

            if (result != NULL) {
                strncpy(SN, result+1, sizeof(SN)-1);
                SN[strcspn(SN, "\n")] = 0;
                WS_INFO("SN is %s\n", SN);
            }
            break;
        }
    }
 
    fclose(fp);
    return 0;
}


char SN[64];

int WS_GET_SN()
{
    char *p;
    char temp[64]; // 临时缓冲区

    FILE *fp = fopen("./config", "r");
    if(NULL == fp)
    {
        WS_INFO("failed to open config\n");
        return -1;
    }

    while(fgets(SN, sizeof(SN), fp) != NULL)
    {
        WS_INFO("%s", SN);
        if ((p = strstr(SN, "sn")) != NULL)
        {
            char delims[] = "=";
            char *result = NULL;
            result = strtok(SN, delims);
            WS_INFO("result is %s\n", result);

            result = strtok(NULL, delims);

            if (result != NULL)
            {
                strncpy(temp, result+1, sizeof(temp)-1); // 使用临时缓冲区
                temp[strcspn(temp, "\n")] = 0; // 处理换行符
                WS_INFO("SN00000 is %s\n", temp);
				memcpy(SN,temp,64);
				WS_INFO("SN111 is %s\n", SN);
				strncpy(SN, temp, 64);
				WS_INFO("SN2222 is %s\n", SN);
            }
            break;
        }
    }

    fclose(fp);
    return 0;
}
int WS_GET_SN()
{
    char *p;
    char temp[64]; // 临时缓冲区

    FILE *fp = fopen("./config", "r");
    if(NULL == fp)
    {
        WS_INFO("failed to open config\n");
        return -1;
    }

    while(fgets(SN, sizeof(SN), fp) != NULL)
    {
        WS_INFO("%s", SN);
        if ((p = strstr(SN, "sn")) != NULL)
        {
            char delims[] = "=";
            char *result = NULL;
            result = strtok(SN, delims);
            WS_INFO("result is %s\n", result);

            result = strtok(NULL, delims);

            if (result != NULL)
            {
                strncpy(temp, result+1, sizeof(temp)-1); // 使用临时缓冲区
                temp[strcspn(temp, "\n")] = 0; // 处理换行符
                WS_INFO("SN is %s\n", temp);
				memcpy(SN,temp,64);
            }
            break;
        }
    }

    fclose(fp);
    return 0;
}

#endif
char SN[64];

int WS_GET_SN(char *snstr)
{
    /*char *p;
    char temp[64]; // 临时缓冲区

    FILE *fp = fopen("./config", "r");
    if(NULL == fp)
    {
        WS_INFO("failed to open config\n");
        return -1;
    }

    while(fgets(SN, sizeof(SN), fp) != NULL)
    {
        WS_INFO("%s", SN);
        if ((p = strstr(SN, "sn")) != NULL)
        {
            char delims[] = "=";
            char *result = NULL;
            result = strtok(SN, delims);
            WS_INFO("result is %s\n", result);

            result = strtok(NULL, delims);

            if (result != NULL)
            {
                strncpy(temp, result+1, sizeof(temp)-1); // 使用临时缓冲区
                temp[strcspn(temp, "\n")] = 0; // 处理换行符
                WS_INFO("SN is %s\n", temp);
				memcpy(SN,temp,64);
            }
            break;
        }
    }*/

	strcpy(SN, snstr);
	WS_INFO("SN is %s\n", SN);

    return 0;
}
static void ws_buildHttpHead1(char* ip, int32_t port, char* path, char* package)
{
	//WS_GET_SN();
    const char httpDemo[] =
        "POST %s HTTP/1.1\r\n"
        //"Connection: Upgrade\r\n"
        "Host: %s:%d\r\n"
        //"Sec-WebSocket-Key: %s\r\n"
        //"Sec-WebSocket-Version: 13\r\n"
		"type:0\r\n"
		"sn:%s\r\n"
        //"Upgrade: websocket\r\n\r\n";
		"Accept-Encoding:gzip, deflate, br\r\n"
		"Connection:keep-alive\r\n"
		"Cache-Control:no-cache\r\n"
		"Content-Length:0\r\n"
		"\r\n";
    sprintf(package, httpDemo, path, ip, port, SN);
	WS_INFO("package %s\n",package);

}

/*******************************************************************************
 * 名称: ws_buildHttpRespond
 * 功能: 构建server端回复client连接请求的http协议
 * 参数:
 *      acceptKey: 来自client的握手key
 *      acceptKeyLen: 长度
 *      package: 存储
 * 返回: 无
 * 说明: 无
 ******************************************************************************/
static void ws_buildHttpRespond(char* acceptKey, uint32_t acceptKeyLen, char* package)
{
    const char httpDemo[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Server: Microsoft-HTTPAPI/2.0\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "%s\r\n\r\n"; //时间打包待续, 格式如 "Date: Tue, 20 Jun 2017 08:50:41 CST\r\n"
    time_t now;
    struct tm *tm_now;
    char timeStr[MY_BUF_SIZE] = {0};
    char respondShakeKey[MY_BUF_SIZE] = {0};
    //构建回应的握手key
    ws_buildRespondShakeKey(acceptKey, acceptKeyLen, respondShakeKey);
    //构建回应时间字符串
    time(&now);
    tm_now = localtime(&now);
    strftime(timeStr, sizeof(timeStr), "Date: %a, %d %b %Y %T %Z", tm_now);
    //组成回复信息
    sprintf(package, httpDemo, respondShakeKey, timeStr);
}

/*******************************************************************************
 * 名称: ws_enPackage
 * 功能: websocket数据收发阶段的数据打包, 通常client发server的数据都要mask(掩码)处理, 反之server到client却不用
 * 参数:
 *      data: 准备发出的数据
 *      dataLen: 长度
 *      package: 打包后存储地址
 *      packageMaxLen: 存储地址可用长度
 *      mask: 是否使用掩码     1要   0 不要
 *      type: 数据类型, 由打包后第一个字节决定, 这里默认是数据传输, 即0x81
 * 返回: 打包后的长度(会比原数据长2~14个字节不等) <=0 打包失败 
 * 说明: 无
 ******************************************************************************/
static int32_t ws_enPackage(
    uint8_t* data,
    uint32_t dataLen,
    uint8_t* package,
    uint32_t packageMaxLen,
    bool mask,
    Ws_DataType type)
{
    uint32_t i, pkgLen = 0;
    //掩码
    uint8_t maskKey[4] = {0};
    uint32_t maskCount = 0;
    //最小长度检查
    if (packageMaxLen < 2)
        return -1;
    //根据包类型设置头字节
    if (type == WDT_MINDATA)
        *package++ = 0x80;
    else if (type == WDT_TXTDATA)
        *package++ = 0x81;
    else if (type == WDT_BINDATA)
        *package++ = 0x82;
    else if (type == WDT_DISCONN)
        *package++ = 0x88;
    else if (type == WDT_PING)
        *package++ = 0x89;
    else if (type == WDT_PONG)
        *package++ = 0x8A;
    else
        return -1;
    pkgLen += 1;
    //掩码位
    if (mask)
        *package = 0x80;
    //半字节记录长度
    if (dataLen < 126)
    {
        *package++ |= (dataLen & 0x7F);
        pkgLen += 1;
    }
    //2字节记录长度
    else if (dataLen < 65536)
    {
        if (packageMaxLen < 4)
            return -1;
        *package++ |= 0x7E;
        *package++ = (uint8_t)((dataLen >> 8) & 0xFF);
        *package++ = (uint8_t)((dataLen >> 0) & 0xFF);
        pkgLen += 3;
    }
    //8字节记录长度
    else
    {
        if (packageMaxLen < 10)
            return -1;
        *package++ |= 0x7F;
        *package++ = 0; //数据长度变量是 uint32_t dataLen, 暂时没有那么多数据
        *package++ = 0;
        *package++ = 0;
        *package++ = 0;
        *package++ = (uint8_t)((dataLen >> 24) & 0xFF); //到这里就够传4GB数据了
        *package++ = (uint8_t)((dataLen >> 16) & 0xFF);
        *package++ = (uint8_t)((dataLen >> 8) & 0xFF);
        *package++ = (uint8_t)((dataLen >> 0) & 0xFF);
        pkgLen += 9;
    }
    //数据使用掩码时,使用异或解码,maskKey[4]依次和数据异或运算,逻辑如下
    if (mask)
    {
        //长度不足
        if (packageMaxLen < pkgLen + dataLen + 4)
            return -1;
        //随机生成掩码
        ws_getRandomString((char*)maskKey, sizeof(maskKey));
        *package++ = maskKey[0];
        *package++ = maskKey[1];
        *package++ = maskKey[2];
        *package++ = maskKey[3];
        pkgLen += 4;
        for (i = 0, maskCount = 0; i < dataLen; i++, maskCount++)
        {
            //maskKey[4]循环使用
            if (maskCount == 4) //sizeof(maskKey))
                maskCount = 0;
            //异或运算后得到数据
            *package++ = maskKey[maskCount] ^ data[i];
        }
        pkgLen += i;
        //断尾
        *package = '\0';
    }
    //数据没使用掩码, 直接复制数据段
    else
    {
        //长度不足
        if (packageMaxLen < pkgLen + dataLen)
            return -1;
        //这种方法,data指针位置相近时拷贝异常
        // memcpy(package, data, dataLen);
        //手动拷贝
        for (i = 0; i < dataLen; i++)
            *package++ = data[i];
        pkgLen += i;
        //断尾
        *package = '\0';
    }

    return pkgLen;
}

/*******************************************************************************
 * 名称: ws_dePackage
 * 功能: websocket数据收发阶段的数据解包,通常client发server的数据都要mask(掩码)处理,反之server到client却不用
 * 参数:
 *      data: 要解包的数据,解包后的数据会覆写到这里
 *      len: 要解包的数据的长度
 *      retDataLen: 解包数据段长度信息
 *      retHeadLen: 解包头部长度信息
 *      retPkgType: 识别包类型
 * 返回:
 *      0: 格式错误,非标准数据包数据
 *      <0: 识别包但不完整(能解析类型、掩码、长度),返回缺少的数据量(负值)
 *      >0: 解包数据成功,返回数据长度,等于retDataLen
 * 说明:
 *      建议recv时先接收14字节然后解包,根据返回缺失长度再recv一次,最后再解包,这样可有效避免连包时只解析到一包的问题
 ******************************************************************************/
 static int32_t ws_dePackage2(
    uint8_t* data,
    uint32_t len,
    Ws_DataType* retPkgType)
{
    uint32_t cIn, cOut;
    //包类型
    uint8_t type;
    //数据段起始位置
    uint32_t dataOffset = 2;
    //数据段长度
    uint32_t dataLen = 0;
    //掩码
    uint8_t maskKey[4] = {0};
    bool mask = false;
    uint8_t maskCount = 0;
    //数据长度过短
    if (len < 2)
        return 0;
    //解析包类型
    if ((data[0] & 0x80) == 0x80)
    {
        type = data[0] & 0x0F;
        if (type == 0x00)
            *retPkgType = WDT_MINDATA;
        else if (type == 0x01)
            *retPkgType = WDT_TXTDATA;
        else if (type == 0x02)
            *retPkgType = WDT_BINDATA;
        else if (type == 0x08)
            *retPkgType = WDT_DISCONN;
        else if (type == 0x09)
            *retPkgType = WDT_PING;
        else if (type == 0x0A)
            *retPkgType = WDT_PONG;
        else
            return 0;
    }
    else{
        return 0;
    }
	return 0;
}
static int32_t ws_dePackage(
    uint8_t* data,
    uint32_t len,
    uint32_t* retDataLen,
    uint32_t* retHeadLen,
    Ws_DataType* retPkgType)
{
    uint32_t cIn, cOut;
    //包类型
    uint8_t type;
    //数据段起始位置
    uint32_t dataOffset = 2;
    //数据段长度
    uint32_t dataLen = 0;
    //掩码
    uint8_t maskKey[4] = {0};
    bool mask = false;
    uint8_t maskCount = 0;
    //数据长度过短
    if (len < 2)
        return 0;
    //解析包类型
    if ((data[0] & 0x80) == 0x80)
    {
        type = data[0] & 0x0F;
        if (type == 0x00)
            *retPkgType = WDT_MINDATA;
        else if (type == 0x01)
            *retPkgType = WDT_TXTDATA;
        else if (type == 0x02)
            *retPkgType = WDT_BINDATA;
        else if (type == 0x08)
            *retPkgType = WDT_DISCONN;
        else if (type == 0x09)
            *retPkgType = WDT_PING;
        else if (type == 0x0A)
            *retPkgType = WDT_PONG;
        else
            return 0;
    }
    else
        return 0;
    //是否掩码,及长度占用字节数
    if ((data[1] & 0x80) == 0x80)
    {
        mask = true;
        maskCount = 4;
    }
    //2字节记录长度
    dataLen = data[1] & 0x7F;
    if (dataLen == 126)
    {
        //数据长度不足以包含长度信息
        if (len < 4)
            return 0;
        //2字节记录长度
        dataLen = data[2];
        dataLen = (dataLen << 8) + data[3];
        //转储长度信息
        *retDataLen = dataLen;
        *retHeadLen = 4 + maskCount;
        //数据长度不足以包含掩码信息
        if (len < (uint32_t)(4 + maskCount))
            return -(int32_t)(4 + maskCount + dataLen - len);
        //获得掩码
        if (mask)
        {
            maskKey[0] = data[4];
            maskKey[1] = data[5];
            maskKey[2] = data[6];
            maskKey[3] = data[7];
            dataOffset = 8;
        }
        else
            dataOffset = 4;
    }
    //8字节记录长度
    else if (dataLen == 127)
    {
        //数据长度不足以包含长度信息
        if (len < 10)
            return 0;
        //使用8个字节存储长度时,前4位必须为0,装不下那么多数据...
        if (data[2] != 0 || data[3] != 0 || data[4] != 0 || data[5] != 0)
            return 0;
        //8字节记录长度
        dataLen = data[6];
        dataLen = (dataLen << 8) | data[7];
        dataLen = (dataLen << 8) | data[8];
        dataLen = (dataLen << 8) | data[9];
        //转储长度信息
        *retDataLen = dataLen;
        *retHeadLen = 10 + maskCount;
        //数据长度不足以包含掩码信息
        if (len < (uint32_t)(10 + maskCount))
            return -(int32_t)(10 + maskCount + dataLen - len);
        //获得掩码
        if (mask)
        {
            maskKey[0] = data[10];
            maskKey[1] = data[11];
            maskKey[2] = data[12];
            maskKey[3] = data[13];
            dataOffset = 14;
        }
        else
            dataOffset = 10;
    }
    //半字节记录长度
    else
    {
        //转储长度信息
        *retDataLen = dataLen;
        *retHeadLen = 2 + maskCount;
        //数据长度不足
        if (len < (uint32_t)(2 + maskCount))
            return -(int32_t)(2 + maskCount + dataLen - len);
        //获得掩码
        if (mask)
        {
            maskKey[0] = data[2];
            maskKey[1] = data[3];
            maskKey[2] = data[4];
            maskKey[3] = data[5];
            dataOffset = 6;
        }
        else
            dataOffset = 2;
    }
    //数据长度不足以包含完整数据段
    if (len < dataLen + dataOffset)
        return -(int32_t)(dataLen + dataOffset - len);
    //解包数据使用掩码时, 使用异或解码, maskKey[4]依次和数据异或运算, 逻辑如下
    if (mask)
    {
    	WS_INFO("has mask\n");
        cIn = dataOffset;
        cOut = 0;
        maskCount = 0;
        for (; cOut < dataLen; cIn++, cOut++, maskCount++)
        {
            //maskKey[4]循环使用
            if (maskCount == 4) //sizeof(maskKey))
                maskCount = 0;
            //异或运算后得到数据
            data[cOut] = maskKey[maskCount] ^ data[cIn];
        }
        //断尾
        data[cOut] = '\0';
    }
    //解包数据没使用掩码, 直接复制数据段
    else
    {
        //这种方法,data指针位置相近时拷贝异常
        // memcpy(data, &data[dataOffset], dataLen);
        //手动拷贝
        
		//WS_INFO("not mask\n");
        cIn = dataOffset;
        cOut = 0;
        for (; cOut < dataLen; cIn++, cOut++)
            data[cOut] = data[cIn];
        //断尾
        data[dataLen] = '\0';
    }
    //有些特殊包数据段长度可能为0,这里为区分格式错误返回,置为1
    if (dataLen == 0)
        dataLen = 1;
    return dataLen;
}


/*******************************************************************************
 * 名称: ws_requestServer
 * 功能: 向websocket服务器发送http(携带握手key), 以和服务器构建连接, 非阻塞模式
 * 参数:
 *      ip: 服务器ip
 *      port: 服务器端口
 *      path: 接口地址,格式如"/tmp/xxx"
 *      timeoutMs: connect阶段超时设置,接收阶段为timeoutMs*2,写0使用默认值1000
 * 返回: >0 返回连接描述符 <= 0 连接失败或超时,所花费的时间ms的负值
 * 说明: 无
 ******************************************************************************/
#if 1
int check_tcp_alive()
{
	//WS_INFO("check_tcp_alive\n");

   // while (0) {

	fd_set readfds, writefds;
			struct timeval timeout;
	
			FD_ZERO(&readfds);
			FD_ZERO(&writefds);
			FD_SET(myfd, &readfds);
			FD_SET(myfd, &writefds);
	
			timeout.tv_sec = 5;
			timeout.tv_usec = 0;
	
			int ret = select(myfd + 1, &readfds, &writefds, NULL, &timeout);
			if (ret == -1) {
				perror("Error in select");
				//exit(1);
			} else if (ret == 0) {
				WS_INFO("Timeout occurred\n");
			} else {
				WS_INFO("WebSocket is ok\n");
				/*if (FD_ISSET(fd, &readfds)) {
					WS_INFO("Socket is readable\n");
				}
				if (FD_ISSET(fd, &writefds)) {
					WS_INFO("Socket is writable\n");
				}*/
			}
		//usleep(10000);
    	//}

	return 0;
}
#endif

int closewsl()
{
	
	WS_INFO("Fun:%s closewsl\n", __FUNCTION__);
	int ret;
	nopong_cnt = 0;
    if (myssl != NULL) {
        WS_INFO("Fun:%s Close SSL\n", __FUNCTION__);
		ret = wolfSSL_shutdown(myssl);
        if (ret == WOLFSSL_SHUTDOWN_NOT_DONE)
		{
			WS_INFO("wolfSSL_shutdown again!!\r\n");
            //wolfSSL_shutdown(myssl);    /* bidirectional shutdown */
		}
		wolfSSL_free(myssl); myssl = NULL;
    }
    if (ctx != NULL) {
        WS_INFO("Fun:%s Close CTX\n", __FUNCTION__);
        wolfSSL_CTX_free(ctx); ctx = NULL;
		wolfSSL_Cleanup();
    }

    if (fd != -1)
    {
		close(fd);

        fd = -1; // 将文件描述符置为无效值
    }
	if (myfd != -1)
    {
		close(myfd);

        myfd = -1; // 将文件描述符置为无效值
    }

    return 0; // 返回成功
}

int32_t ws_requestServer(char* ip, int32_t port, char* path, int32_t timeoutMs)
{
    int32_t timeoutCount = 0;
    char retBuff[512] = {0};
    char httpHead[512] = {0};
    char shakeKey[128] = {0};
    char tempIp[128] = {0};
    char* p;
	int ret;

    //服务器端网络地址结构体
    struct sockaddr_in report_addr;
    memset(&report_addr, 0, sizeof(report_addr)); //数据初始化--清零
    report_addr.sin_family = AF_INET;             //设置为IP通信
    report_addr.sin_port = htons(port);           //服务器端口号

    //服务器IP地址, 自动域名转换
    //report_addr.sin_addr.s_addr = inet_addr(ip);
    if ((report_addr.sin_addr.s_addr = inet_addr(ip)) == INADDR_NONE)
    {
        ret = ws_getIpByHostName(ip, tempIp, 1000);
        if (ret < 0)
            return ret;
        else if (strlen((const char*)tempIp) < 7)
            return -ret;
        else
            timeoutCount += ret;
        if ((report_addr.sin_addr.s_addr = inet_addr(tempIp)) == INADDR_NONE)
            return -ret;
#ifdef WS_DEBUG
        WS_INFO("Host(%s) to IP(%s)\r\n", ip, tempIp);
#endif
    }

    //默认超时1秒
    if (timeoutMs == 0)
        timeoutMs = 1000;

    //create unix socket
    if ((myfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        WS_ERR("socket error\r\n");
        return -1;
    }
//	struct timeval tv;
//
//	tv.tv_sec  = 1; 
//	tv.tv_usec = 0;
//
//	setsockopt(myfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
//
//	struct timeval timeout;
//	timeout.tv_sec = 10;
//	timeout.tv_usec = 0;
//
//	if (setsockopt(myfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
//		WS_INFO("SO_RCVTIMEO set\n");
//	}
//	
	/*int iOptVal = 0;
	int iOptLen = sizeof(int);
	int iResult = getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *)&iOptVal, &iOptLen);
	if (iResult < 0) {
		WS_INFO("getsockopt for SO_KEEPALIVE failed with error:\n");
	}
	else
		WS_INFO("SO_RCVBUF Value: %ld\n", iOptVal);*/
	
    //connect
    timeoutCount = 0;
	while (connect(myfd, (struct sockaddr *)&report_addr, sizeof(struct sockaddr)) != 0)
    {
    	WS_ERR("connecting\n");
        //if (connect(fd, (struct sockaddr *)&report_addr, sizeof(struct sockaddr)) != 0)
		if (++timeoutCount > 10)
        {
        	ws_delayms(10*1000);
            WS_ERR("connect to %s:%d timeout\r\n", ip, port);
            close(myfd);
            return -timeoutCount;
        }
		ws_delayms(1);
    }
	    //非阻塞
    //ret = fcntl(myfd, F_GETFL, 0);
    //fcntl(myfd, F_SETFL, ret | O_NONBLOCK);

	//SSL_library_init();
    //SSL_load_error_strings();
    wolfSSL_Init();
    ctx = SSL_CTX_new (SSLv23_client_method());
    if((ctx) == NULL)
    {
        WS_ERR("Fun:%s\tSSL_CTX ERROR\n", __FUNCTION__);
        return -1;
    }
    WS_INFO("tim add SSL_CTX_set_verify test############\n");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);//fix SSL_connect fail

    if( (myssl = SSL_new(ctx)) == NULL) {
        fprintf(stderr, "wolfSSL_new error.\n");
        //exit(EXIT_FAILURE);
		return -1;
    }

    SSL_set_fd(myssl, myfd);
	//SSL_set_mode(myssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	//SSL_set_mode(myssl, SSL_MODE_AUTO_RETRY);

	
    int ssl_ret;
    int fgCycleFlag = 1;
    while(fgCycleFlag )
    {
        ssl_ret = SSL_connect(myssl);
        switch(SSL_get_error(myssl, ssl_ret))//这里出错
        {
            case SSL_ERROR_NONE:
                WS_INFO("Fun:%s\tSSL_ERROR_NONE,ssl_ret = %d\n", __FUNCTION__,ssl_ret);
                fgCycleFlag = 0;
                usleep(100000);
                break;
            case SSL_ERROR_WANT_WRITE:
                WS_ERR("Fun:%s\tSSL_ERROR_WANT_WRITE,ssl_ret = %d\n", __FUNCTION__,ssl_ret);
                usleep(100000);
                return -1;
            case SSL_ERROR_WANT_READ:
                WS_ERR("Fun:%s\tSSL_ERROR_WANT_READ,ssl_ret = %d\n", __FUNCTION__,ssl_ret);
                usleep(100000);
                return -1;
            default:    
                WS_ERR("SSL_connect:%s SSL_get_error= %d\n", __FUNCTION__,SSL_get_error(myssl, ssl_ret));
                return -1;
        }   
    }
	
	ret = fcntl(myfd, F_GETFL, 0);
	fcntl(myfd, F_SETFL, ret | O_NONBLOCK);/* 基于 ctx 产生一个新的 SSL */

    //发送http协议头
    memset(shakeKey, 0, sizeof(shakeKey));
    ws_buildShakeKey(shakeKey);                                   //创建握手key
    memset(httpHead, 0, sizeof(httpHead));                        //创建协议包

	ws_buildHttpHead(ip, port, path, shakeKey, (char*)httpHead); //组装http请求头
	
	//send(fd, httpHead, strlen((const char*)httpHead), MSG_NOSIGNAL);
	// 创建 SSL 对象并进行握手
    //myssl = sync_initialize_ssl("client.crt", "client.key", wolfSSL_MODE_CLIENT, fd); 
	int result = wolfSSL_write(myssl, httpHead, strlen((const char*)httpHead));
	if (result > 0) {
    // 数据成功写入
	WS_INFO("数据成功写入%d\n",result);
} else {
    // 发生错误
		WS_ERR("发生错误%d\n",result);
}
    //send(fd, httpHead, strlen((const char*)httpHead), MSG_NOSIGNAL);

#ifdef WS_DEBUG
    WS_INFO("connect: %dms\r\n%s\r\n", timeoutCount, httpHead);
#endif

#if 1
    while (1)
    {
        memset(retBuff, 0, sizeof(retBuff));
        //ret = recv(fd, retBuff, sizeof(retBuff), MSG_NOSIGNAL);
		ret = wolfSSL_read(myssl, retBuff, sizeof(retBuff)); 
        if (ret > 0)
        {
#ifdef WS_DEBUG
            //显示http返回
            WS_INFO("recv: len %d / %dms\r\n%s\r\n", ret, timeoutCount, retBuff);
#endif
#if 0
			if ((p = strstr((char*)retBuff, "token")) != NULL)
			WS_INFO("token%s\r\n",p+7);
			
			memset(token_checksume1, 0, sizeof(token_checksume1));
			//memcpy(token_checksume1, result+1, strlen(send_buff));
			strncpy(token_checksume1, p+7,strlen(p+7));
			token_checksume1[88]='\0';
			WS_INFO( "token_checksume1 is %s %d\n", token_checksume1 ,strlen(p+7));
/*问题： 在使用strlen(p+7)获取长度时，p+7可能指向的并不是以\0结尾的字符串，可能会导致获取的长度不准确。

建议修改： 在提取token信息时，应该使用指针运算来确定token内容的长度，而不是依赖strlen函数。

问题： 在使用strncpy函数拷贝字符串时，需要确保目标数组足够大以容纳要拷贝的内容，避免发生缓冲区溢出。

建议修改： 在拷贝token信息到token_checksume1时，可以使用一个安全的方式来确保不会发生缓冲区溢出。*/
#endif

			if ((p = strstr((char*)retBuff, "token")) != NULL) {
			    WS_INFO("token%s\r\n", p + 7);
    
			    memset(token_checksume1, 0, sizeof(token_checksume1));
    
			    // 计算token内容的长度
			    size_t token_length = strlen(p + 7);
    
			    // 拷贝token信息到token_checksume1，并避免缓冲区溢出
			    if (token_length < sizeof(token_checksume1)) {
			        strncpy(token_checksume1, p + 7, token_length);
			        token_checksume1[token_length] = '\0';  // 确保字符串以'\0'结尾
			    } else {
			        // token内容过长，进行相应处理
			        // 可以选择截断、报错等操作
			    }
    
			    //WS_INFO("token_checksume1 is %s %d\n", token_checksume1, token_length);
			}			
            //返回的是http回应信息
            if (strncmp((const char*)retBuff, "HTTP", 4) == 0)
            {
                //定位到握手字符串
                if ((p = strstr((char*)retBuff, "Sec-WebSocket-Accept: ")) != NULL)
                {
                    p += strlen("Sec-WebSocket-Accept: ");
                    sscanf((const char*)p, "%s\r\n", p);
                    //比对握手信息
                    if (ws_matchShakeKey(shakeKey, strlen((const char*)shakeKey), p, strlen((const char*)p)) == 0)
                        return 1;
                    //握手信号不对, 重发协议包
                    else
                        //ret = send(fd, httpHead, strlen((const char*)httpHead), MSG_NOSIGNAL);
                        ret = wolfSSL_write(myssl, httpHead, strlen((const char*)httpHead));
					
                }
                //重发协议包
                else
                    //ret = send(fd, httpHead, strlen((const char*)httpHead), MSG_NOSIGNAL);
                    ret = wolfSSL_write(myssl, httpHead, strlen((const char*)httpHead));
				
            }
            //显示异常返回数据
            else
            {
                //#ifdef WS_DEBUG
                WS_ERR("recv: len %d / unknown context\r\n%s\r\n", ret, retBuff);
                WS_HEX(stderr, retBuff, ret);
				return -1;
            }
        }else if ((ret == -1) && (errno == EWOULDBLOCK || errno == EINTR || errno == 0)){
		//WS_INFO("No receive data   !!\r\n");
		
		WS_ERR("%s%d\n", strerror(errno),errno); 
			
		//return 0;
	}else{
		WS_ERR("qqqFailed to connection\n");
		WS_ERR("abnormal connection  ret%d  errno%d %d %d!!\r\n",ret,errno,EWOULDBLOCK,EINTR);
		//return -1;
	}
        ws_delayms(1);
        //超时检查
        if (++timeoutCount > timeoutMs * 2)
            break;
    }
#endif

    //连接失败,返回耗时(负值)
	WS_ERR("xxxxx\n");
    close(myfd);
    return -timeoutCount;
}

int32_t ws_requestQuServer(char* ip, int32_t port, char* path, int32_t timeoutMs)
{
    int32_t timeoutCount = 0;
    char retBuff[512] = {0};
    char httpHead[512] = {0};
    char shakeKey[128] = {0};
    char tempIp[128] = {0};
    char* p;	
	int ret;
	
	memset(path, 0, sizeof(path));
	strcpy(path, "/server");

    //服务器端网络地址结构体
    struct sockaddr_in report_addr;
    memset(&report_addr, 0, sizeof(report_addr)); //数据初始化--清零
    report_addr.sin_family = AF_INET;             //设置为IP通信
    report_addr.sin_port = htons(port);           //服务器端口号

    //服务器IP地址, 自动域名转换
    //report_addr.sin_addr.s_addr = inet_addr(ip);
    if ((report_addr.sin_addr.s_addr = inet_addr(ip)) == INADDR_NONE)
    {
        ret = ws_getIpByHostName(ip, tempIp, 1000);
        if (ret < 0)
            return ret;
        else if (strlen((const char*)tempIp) < 7)
            return -ret;
        else
            timeoutCount += ret;
        if ((report_addr.sin_addr.s_addr = inet_addr(tempIp)) == INADDR_NONE)
            return -ret;
#ifdef WS_DEBUG
        WS_INFO("Host(%s) to IP(%s)\r\n", ip, tempIp);
#endif
    }

    //默认超时1秒
    if (timeoutMs == 0)
        timeoutMs = 1000;
    /* SSL 库初始化 */

    //create unix socket
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        WS_ERR("socket error\r\n");
        return -1;
    }
	
	struct timeval tv;

	tv.tv_sec  = 1; 
	tv.tv_usec = 0;

	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	/*struct timeval timeout;
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;

	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
		WS_INFO("occurred\n");
	}*/
	
    //connect
    timeoutCount = 0;
	while (connect(fd, (struct sockaddr *)&report_addr, sizeof(struct sockaddr)) != 0)
    {
    	WS_ERR("connecting\n");
        //if (connect(fd, (struct sockaddr *)&report_addr, sizeof(struct sockaddr)) != 0)
		if (++timeoutCount > 10)
        {
        	ws_delayms(10*1000);
            WS_ERR("connect to %s:%d timeout\r\n", ip, port);
            close(fd);
            return -timeoutCount;
        }
		ws_delayms(1);
    }
	//SSL_library_init();
    //SSL_load_error_strings();
#if 0
	wolfSSL_Init();
    ctx = SSL_CTX_new (SSLv23_client_method());
    if((ctx) == NULL)
    {
        WS_INFO("Fun:%s\tSSL_CTX ERROR\n", __FUNCTION__);
        return -1;
    }
    WS_INFO("tim add SSL_CTX_set_verify test############\n");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);//fix SSL_connect fail

    if( (myssl = SSL_new(ctx)) == NULL) {
        fprintf(stderr, "wolfSSL_new error.\n");
        exit(EXIT_FAILURE);
    }

    SSL_set_fd(myssl, fd);
    int ssl_ret;
    int fgCycleFlag = 1;
    while(fgCycleFlag )
    {
        ssl_ret = SSL_connect(myssl);
        switch(SSL_get_error(myssl, ssl_ret))//这里出错
        {
            case SSL_ERROR_NONE:
                WS_INFO("Fun:%s\tSSL_ERROR_NONE,ssl_ret = %d\n", __FUNCTION__,ssl_ret);
                fgCycleFlag = 0;
                usleep(100000);
                break;
            case SSL_ERROR_WANT_WRITE:
                WS_INFO("Fun:%s\tSSL_ERROR_WANT_WRITE,ssl_ret = %d\n", __FUNCTION__,ssl_ret);
                usleep(100000);
                break;
            case SSL_ERROR_WANT_READ:
                WS_INFO("Fun:%s\tSSL_ERROR_WANT_READ,ssl_ret = %d\n", __FUNCTION__,ssl_ret);
                usleep(100000);
                break;
            default:    
                WS_INFO("SSL_connect:%s\n", __FUNCTION__);
                return -1;
        }   
    }
#endif
	wolfSSL_Init();
	ctx = SSL_CTX_new(SSLv23_client_method());
	if (ctx == NULL) {
	    WS_INFO("Fun:%s\tSSL_CTX ERROR\n", __FUNCTION__);
	    return -1;
	}

	WS_INFO("tim add SSL_CTX_set_verify test############\n");
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0); //fix SSL_connect fail

	myssl = SSL_new(ctx);
	if (myssl == NULL) {
	    fprintf(stderr, "wolfSSL_new error.\n");
	    SSL_CTX_free(ctx); // 释放SSL上下文
	    return -1;
	}

	SSL_set_fd(myssl, fd);
	int ssl_ret;
	int fgCycleFlag = 1;
	while (fgCycleFlag) {
	    ssl_ret = SSL_connect(myssl);
	    switch (ssl_ret) {
	        case 1: // SSL连接成功
	            WS_INFO("Fun:%s\tSSL connect successful\n", __FUNCTION__);
	            fgCycleFlag = 0;
	            usleep(100000);
	            break;
	        case 0: // SSL连接失败
	        case -1: // SSL连接出错
	            WS_ERR("SSL_connect error in %s\n", __FUNCTION__);
	            //SSL_free(myssl); // 释放SSL对象
	            //SSL_CTX_free(ctx); // 释放SSL上下文
	            return -1;
	        case -2: // 需要再次调用SSL_connect
	            WS_ERR("Fun:%s\tSSL connect in progress\n", __FUNCTION__);
	            usleep(100000);
	            return -1;
	        default:
	            WS_ERR("Unknown SSL_connect return value\n");
	            //SSL_free(myssl); // 释放SSL对象
	            //SSL_CTX_free(ctx); // 释放SSL上下文
	            return -1;
	    }
	}


    //非阻塞
    //ret = fcntl(fd, F_GETFL, 0);
    //fcntl(fd, F_SETFL, ret | O_NONBLOCK);

    //发送http协议头
    memset(shakeKey, 0, sizeof(shakeKey));
    //ws_buildShakeKey(shakeKey);                                   //创建握手key
    memset(httpHead, 0, sizeof(httpHead));                        //创建协议包
	
	ws_buildHttpHead1(ip, port, path, (char*)httpHead); //组装http请求头
    //send(fd, httpHead, strlen((const char*)httpHead), MSG_NOSIGNAL);
	//char *request = "GET /server HTTP/1.1\r\nHost: 192.168.100.20:7758\r\nConnection: keep-alive\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
    	int result = wolfSSL_write(myssl, httpHead, strlen((const char*)httpHead));
	if (result > 0) {
    // 数据成功写入
	//WS_INFO("数据成功写入%d\n",result);
} else {
    // 发生错误
		WS_ERR("发生错误%d\n",result);
		return -1;
}

#ifdef WS_DEBUG
    WS_INFO("connect: %dms\r\n%s\r\n", timeoutCount, httpHead);
#endif
    while (1)
    {
        memset(retBuff, 0, sizeof(retBuff));
        //ret = recv(fd, retBuff, sizeof(retBuff), MSG_NOSIGNAL);
		ret = wolfSSL_read(myssl, retBuff, sizeof(retBuff)); 
        if (ret > 0)
        {
#ifdef WS_DEBUG
            //显示http返回
            WS_INFO("recv: len %d / %dms\r\n%s\r\n", ret, timeoutCount, retBuff);
#endif
            //返回的是http回应信息
            if (strncmp((const char*)retBuff, "HTTP", 4) == 0)
            {            	
            	if ((p = strstr((char*)retBuff, "204 No Content")) != NULL)
            	{
            		WS_ERR("No Content\n");
					ws_delayms(10*1000);
					return -1;
            	}
            }
            //显示异常返回数据
            else
            {
#ifdef WS_DEBUG
				WS_ERR("unknown context /recv: len %d\r\n%s\r\n", ret, retBuff);
				WS_HEX(stderr, retBuff, ret);
#endif
            }
			if ((p = strstr((char*)retBuff, "port")) != NULL)
			{
				char *pt = p + strlen("port\":");
                sscanf((const char*)pt, "%s\r\n", pt);
				//WS_INFO( "pppptt is %s %c %c \n", pt,*pt,*(pt+1));
				for(int i = 1;i++;i<10){
					if(*(pt+i)== '\}'){
						//WS_INFO( "11111\n");
						*(pt+i) = '\0';
						break;
					}
					
				}
				//WS_INFO( "pppptt is %s\n", pt);
				char *endptr;
				long int num;

				num = strtol(pt, &endptr, 10);

				if (*endptr != '\0') {
					WS_ERR("转换失败：输入字符串不是一个有效的整数。\n");
					return -1;
				} else {
					WS_INFO("转换结果：%ld\n", num);
				}
				get_port = num;
				WS_INFO("转换结果：%ld %d\n", num,port);
				WS_INFO("get_port%d\n",get_port);
		
			}
			if ((p = strstr((char*)retBuff, "server")) != NULL)
			{
				p += 8;
				sscanf((const char*)p, "%s\r\n", p);
				WS_INFO(" acceptKey[%s]\r\n", p);
				
				char delims[] = ",";
				char *result = NULL;
				result = strtok(p, delims);
				//WS_INFO( "result is %s\n", result );
				//strncpy(ip, result+1,strlen(result));
				//WS_INFO( "ip is %s sizeof ip %d\n", ip,sizeof(ip));
				char delims2[] = "\"";
				char *result2 = NULL;
				result2 = strtok(result, delims2);
				//WS_INFO( "result2 is %s\n", result2 );
				strcpy(ip, result2);
				//WS_INFO( "ip is %s \n", ip);
						//WS_INFO("%d\r\n",port);

				return fd;
		
			}
        }
    }
    //连接失败,返回耗时(负值)
	WS_ERR("xxxxxret%d\n",ret);
    close(fd);
    return -timeoutCount;
}

/*******************************************************************************
 * 名称: ws_replyClient
 * 功能: 服务器回复客户端的连接请求, 以建立websocket连接
 * 参数:
 *      fd: 连接描述符
 *      buff: 接收到来自客户端的数据(内含http连接请求)
 *      buffLen: 
 *      path: path匹配检查,不用可以置NULL
 * 返回: >0 建立websocket连接成功 <=0 建立websocket连接失败
 * 说明: 无
 ******************************************************************************/
int32_t ws_replyClient(SSL *myssl, char* buff, int32_t buffLen, char* path)
{
    char* keyOffset;
    int32_t ret;
    char recvShakeKey[512] = {0};
    char respondPackage[1024] = {0};
#ifdef WS_DEBUG
    WS_INFO("recv: len %d \r\n%s\r\n", buffLen, buff);
#endif
    //path检查
    if (path && !strstr((char*)buff, path))
    {
        WS_INFO("path not matched\r\n");
        return -1;
    }
    //获取握手key
    if (!(keyOffset = strstr((char*)buff, "Sec-WebSocket-Key: ")))
    {
        WS_INFO("Sec-WebSocket-Key not found\r\n");
        return -1;
    }
    //获取握手key
    keyOffset += strlen("Sec-WebSocket-Key: ");
    sscanf((const char*)keyOffset, "%s", recvShakeKey);
    ret = strlen((const char*)recvShakeKey);
    if (ret < 1)
    {
        WS_INFO("Sec-WebSocket-Key not matched\r\n");
        return -1;
    }
    //创建回复key
    ws_buildHttpRespond(recvShakeKey, (uint32_t)ret, respondPackage);
    //return send(fd, respondPackage, strlen((const char*)respondPackage), MSG_NOSIGNAL);
    return wolfSSL_write(myssl, respondPackage, strlen((const char*)respondPackage));

}

/*******************************************************************************
 * 名称: ws_send
 * 功能: websocket数据基本打包和发送
 * 参数:
 *      fd: 连接描述符
 *      *buff: 数据
 *      buffLen: 长度
 *      mask: 数据是否使用掩码, 客户端到服务器必须使用掩码模式
 *      type: 数据要要以什么识别头类型发送(txt, bin, ping, pong ...)
 * 返回: 调用send的返回
 * 说明: 无
 ******************************************************************************/
int32_t ws_send(SSL *myssl, void* buff, int32_t buffLen, bool mask, Ws_DataType type)
{
    uint8_t* wsPkg = NULL;
    int32_t retLen, ret;
	
    //参数检查
    if (buffLen < 0)
        return 0;
    //非包数据发送
    if (type == WDT_NULL)
        //return send(fd, buff, buffLen, MSG_NOSIGNAL);
        return wolfSSL_write(myssl, buff, buffLen);

    //数据打包 +14 预留类型、掩码、长度保存位
    wsPkg = (uint8_t*)calloc(buffLen + 14, sizeof(uint8_t));
    retLen = ws_enPackage((uint8_t*)buff, buffLen, wsPkg, (buffLen + 14), mask, type);
    if (retLen <= 0)
    {
        free(wsPkg);
        return 0;
    }
#ifdef WS_DEBUG
    //显示数据
    //WS_INFO("ws_send: len/%d %d\r\n", buffLen,retLen);
    //WS_HEX(stdout, wsPkg, retLen);
#endif
	int total_bytes_written = 0;
    int bytes_written;
//	    int sndbuf, rcvbuf, available_sndbuf, available_rcvbuf;
//    socklen_t optlen = sizeof(int);
//
//    // 获取TCP发送缓冲区大小
//    if (getsockopt(myfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &optlen) < 0) {
//        perror("11getsockopt failed");
//    }
//
//    // 获取TCP接收缓冲区大小
//    if (getsockopt(myfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &optlen) < 0) {
//        perror("22getsockopt failed");
//    }
//
//    // 获取可用的发送缓冲区大小
//    if (getsockopt(myfd, SOL_SOCKET, SO_SNDBUFFORCE, &available_sndbuf, &optlen) < 0) {
//        perror("33getsockopt failed");
//    }
//
//    // 获取可用的接收缓冲区大小
//    if (getsockopt(myfd, SOL_SOCKET, SO_RCVBUFFORCE, &available_rcvbuf, &optlen) < 0) {
//        perror("44getsockopt failed");
//    }
//	
//
//    WS_INFO("TCP发送缓冲区大小: %d bytes\n", sndbuf);
//    WS_INFO("TCP接收缓冲区大小: %d bytes\n", rcvbuf);
//    WS_INFO("剩余可用发送缓冲区大小: %d bytes\n", available_sndbuf);
//    WS_INFO("剩余可用接收缓冲区大小: %d bytes\n", available_rcvbuf);
	
//    while (total_bytes_written < retLen) {
//    //ret = send(fd, wsPkg, retLen, MSG_NOSIGNAL);
//		bytes_written = wolfSSL_write(myssl, wsPkg, retLen - total_bytes_written);
//		if (bytes_written > 0) {
//            total_bytes_written += bytes_written;			
//			WS_INFO("this time bytes_written:%d, total_bytes_written:%d, need_written:%d\n",bytes_written,total_bytes_written,retLen);
//		}else if (ret == 0) {
//			
//			WS_INFO("Connection closed by peer\n");
//			return -1;
//		}else {
//			
//			WS_INFO("Handle error\n");
//			return -1;
//		}
//    }
	
	fd_set writefds;
	struct timeval timeout;
	FD_ZERO(&writefds);
    FD_SET(myfd, &writefds);

    timeout.tv_sec = 5;  // Timeout of 5 seconds
    timeout.tv_usec = 0;

    int ready = select(myfd + 1, NULL, &writefds, NULL, &timeout);
    if (ready == -1) {
        perror("select failed");
        return -1;
    } else if (ready == 0) {
        WS_INFO("select timeout, data may not be sent successfully\n");
        // Handle timeout, data may not be sent successfully
        return -1;
    }else{
	    while (total_bytes_written < retLen) {
	    //ret = send(fd, wsPkg, retLen, MSG_NOSIGNAL);
			bytes_written = wolfSSL_write(myssl, wsPkg, retLen - total_bytes_written);
			if (bytes_written > 0) {
	            total_bytes_written += bytes_written;			
				WS_INFO("this time bytes_written:%d, total_bytes_written:%d, need_written:%d\n",bytes_written,total_bytes_written,retLen);
			}else if (ret == 0) {
				
				WS_INFO("Connection closed by peer\n");
				return -1;
			}else {
				
				WS_INFO("Handle error\n");
				return -1;
			}
	    }
	}
    free(wsPkg);
    return total_bytes_written;
}
int wssend2(char *buf,int data_len)
{
	//ret = ws_send(myssl, buf, len, true, WDT_TXTDATA);
	memcpy(send_buff,buf,data_len);
	
	int total_bytes_written = 0;
    int bytes_written;

    while (total_bytes_written < data_len) {
        bytes_written = wolfSSL_write(myssl, (const char*)send_buff + total_bytes_written, data_len - total_bytes_written);
        if (bytes_written > 0) {
            total_bytes_written += bytes_written;
			
			WS_INFO("bytes_written%d\n",bytes_written);
        } else if (bytes_written == 0) {
            
			WS_INFO("Connection closed by peer\n");
            return -1;
        } else {
            
			WS_INFO("Handle error\n");
            return -1;
        }
    }

    return total_bytes_written;
}

/*******************************************************************************
 * 名称: ws_recv
 * 功能: websocket数据接收和基本解包
 * 参数: 
 *      fd: 连接描述符
 *      buff: 数据接收地址
 *      buffSize: 接收区可用最大长度,至少16字节
 * 返回:
 *      =0 没有收到有效数据(或者收到特殊包,如果是 WDT_DISCONN 则fd已被close)
 *      >0 成功接收并解包数据
 *      <0 非标准数据包数据的长度
 * 说明: 无
 ******************************************************************************/
int32_t ws_recv2(SSL *myssl, void* buff, int32_t buffSize, Ws_DataType* retType)
{
    int32_t ret;
    int32_t retRecv = 0;     //调用recv的返回
    int32_t retDePkg;        //调用解包的返回
    uint32_t retDataLen = 0; //解包得到的数据段长度
    uint32_t retHeadLen = 0; //解包得到的包头部长度
    int32_t retFinal = 0;    //最终返回
    uint32_t timeout = 0;    //接收超时计数
    
    uint8_t type;

    char tmp[16]; //为防止一次接收到多包数据(粘包),先尝试性接收ws头部字节,得知总长度后再接收剩下部分
    Ws_DataType retPkgType = WDT_NULL; //默认返回包类型
    char* cBuff = (char*)buff; //转换指针类型

    //丢弃数据
    if (!buff || buffSize < 1)
    {
		//while (recv(fd, tmp, sizeof(tmp), MSG_NOSIGNAL) > 0)
		
		WS_INFO("丢弃数据\r\n");
		while (wolfSSL_read(myssl, tmp, sizeof(tmp)) > 0)
            ;
    }
    //先接收数据头部,头部最大2+4+8=14字节
    else
    {
		//retRecv = recv(fd, buff, 14, MSG_NOSIGNAL);
		retRecv = wolfSSL_read(myssl, buff, buffSize);		
		ws_dePackage2(buff,retRecv,&retPkgType);
		
		WS_INFO("retRecv %d retPkgType %x buff %s\n",retRecv,retPkgType,buff);
		if(retRecv > 2)
		{

			memset(buff,0,buffSize);
			retRecv = wolfSSL_read(myssl, buff, buffSize);		
				
			WS_INFO("retRecv %d buff %s\n",retRecv,buff);

			//收到 PING 包,应自动回复 PONG
			if (retPkgType == WDT_PING)
			{
			    //自动 ping-pong
			    //ws_send(fd, NULL, 0, false, WDT_PONG);
			    WS_INFO("ws_recv: WDT_PING\r\n");
			    retFinal = 0;
			}
			//收到 PONG 包
			else if (retPkgType == WDT_PONG)
			{
			    //WS_INFO("ws_recv: WDT_PONG\r\n");
			    retFinal = 0;
			}
			//收到 断连 包
			else if (retPkgType == WDT_DISCONN)
			{
			    WS_INFO("ws_recv: WDT_DISCONN\r\n");
			    retFinal = 0;
			}
			//其它正常数据包
			else
			    retFinal = retRecv;
		}else{
    	
			WS_INFO("retRecv %d\r\n",retRecv);
			return retRecv;
		}
    }
	
	*retType = retPkgType;

   
    return retFinal;
}
#if 1

int32_t ws_recv(SSL *myssl, void* buff, int32_t buffSize, Ws_DataType* retType)
{
    int32_t ret;
    int32_t retRecv = 0;     //调用recv的返回
    int32_t retDePkg;        //调用解包的返回
    uint32_t retDataLen = 0; //解包得到的数据段长度
    uint32_t retHeadLen = 0; //解包得到的包头部长度
    int32_t retFinal = 0;    //最终返回
    uint32_t timeout = 0;    //接收超时计数

    char tmp[16]; //为防止一次接收到多包数据(粘包),先尝试性接收ws头部字节,得知总长度后再接收剩下部分
    Ws_DataType retPkgType = WDT_NULL; //默认返回包类型
    char* cBuff = (char*)buff; //转换指针类型

    //丢弃数据
    if (!buff || buffSize < 1)
    {
		//while (recv(fd, tmp, sizeof(tmp), MSG_NOSIGNAL) > 0)
		while (wolfSSL_read(myssl, tmp, sizeof(tmp)) > 0)
            ;
    }
    //先接收数据头部,头部最大2+4+8=14字节
    else
    {
        if (buffSize < 2){
            WS_INFO("error, buffSize must be >= 2 \r\n");
        	}
        else{
            //retRecv = recv(fd, buff, 14, MSG_NOSIGNAL);
			retRecv = wolfSSL_read(myssl, buff, MY_BUF_SIZE);
			
			//char recv_buff[128];
			//memcpy();
        	}
    }

    if (retRecv > 0)
    {
        //数据解包
        retDePkg = ws_dePackage((uint8_t*)buff, retRecv, &retDataLen, &retHeadLen, &retPkgType);
        //1. 非标准数据包数据,再接收一次(防止丢数据),之后返回"负len"长度值
        //2. buffSize不足以收下这一包数据,当作非标准数据包数据处理,能收多少算多少
        if (retDePkg == 0 || (retDePkg < 0 && retRecv - retDePkg > buffSize))
        {
            //能收多少算多少
            //retRecv += recv(fd, &cBuff[retRecv], buffSize - retRecv, MSG_NOSIGNAL);
            retRecv += wolfSSL_read(myssl, &cBuff[retRecv], buffSize - retRecv);
			
            //对于包过大的问题
            if (retDePkg < 0)
            {
                //1. 发出警告
                WS_INFO("warnning, pkgLen(%d) > buffSize(%d)\r\n", retRecv - retDePkg, buffSize);
                //2. 把这包数据丢弃,以免影响后续包
                //while (recv(fd, tmp, sizeof(tmp), MSG_NOSIGNAL) > 0)
				while (wolfSSL_read(myssl, tmp, sizeof(tmp)) > 0)
                    ;
            }
            retFinal = -retRecv;
#ifdef WS_DEBUG
            //显示数据
            WS_INFO("ws_recv1: len/%d retDePkg/%d retDataLen/%d retHeadLen/%d retPkgType/%d\r\n",
                    retRecv, retDePkg, retDataLen, retHeadLen, retPkgType);
            WS_HEX(stdout, buff, retRecv);
#endif
        }
        //正常收包
        else
        {
            //检查是否需要续传
            if (retDePkg < 0)
            {
                //再接收一次(通常情况)
                //ret = recv(fd, &cBuff[retRecv], -retDePkg, MSG_NOSIGNAL);
                ret = wolfSSL_read(myssl, &cBuff[retRecv], -retDePkg);
				
                if (ret > 0)
                {
                    retRecv += ret;
                    retDePkg += ret;
                }

                //数据量上百K时需要多次recv,无数据200ms超时,继续接收
				for (timeout = 0; timeout < 200 && retDePkg < 0;)
                {
                    ws_delayus(5000);
                    timeout += 5;
                    //ret = recv(fd, &cBuff[retRecv], -retDePkg, MSG_NOSIGNAL);
					ret = wolfSSL_read(myssl, &cBuff[retRecv], -retDePkg);

                    if (ret > 0)
                    {
                        timeout = 0;
                        retRecv += ret;
                        retDePkg += ret;
                    }
                }
#ifdef WS_DEBUG
                //显示数据
                WS_INFO("ws_recv2: len/%d retDePkg/%d retDataLen/%d retHeadLen/%d retPkgType/%d\r\n",
                        retRecv, retDePkg, retDataLen, retHeadLen, retPkgType);
                WS_HEX(stdout, buff, retRecv);
#endif
                //二次解包
                retDePkg = ws_dePackage((uint8_t*)buff, retRecv, &retDataLen, &retHeadLen, &retPkgType);
            }
#ifdef WS_DEBUG
            //显示数据
            WS_INFO("ws_recv3: len/%d retDePkg/%d retDataLen/%d retHeadLen/%d retPkgType/%d\r\n",
                    retRecv, retDePkg, retDataLen, retHeadLen, retPkgType);
            WS_HEX(stdout, buff, retRecv);
#endif
            //一包数据终于完整的接收完了...
            if (retDePkg > 0)
            {
                //收到 PING 包,应自动回复 PONG
                if (retPkgType == WDT_PING)
                {
                    //自动 ping-pong
                    //ws_send(fd, NULL, 0, false, WDT_PONG);
                    WS_INFO("ws_recv: WDT_PING\r\n");
                    retFinal = 0;
                }
                //收到 PONG 包
                else if (retPkgType == WDT_PONG)
                {
                    //WS_INFO("ws_recv: WDT_PONG\r\n");
                    retFinal = 0;
                }
                //收到 断连 包
                else if (retPkgType == WDT_DISCONN)
                {
                    WS_INFO("ws_recv: WDT_DISCONN\r\n");
                    retFinal = 0;
                }
                //其它正常数据包
                else
                    retFinal = retDePkg;
            }
            //未曾设想的道路...
            else
                retFinal = -retRecv;
        }
    }else{
    	
		WS_INFO("retRecv %d\r\n",retRecv);
		return retRecv;
	}
    //返回包类型
    if (retType)
        *retType = retPkgType;

    return retFinal;
}
#endif
#if 1 // 发收包测试
/* 
int base64_encode(char *in_str, int in_len, char *out_str)
{
    BIO *b64, *bio;
    BUF_MEM *bptr = NULL;
    size_t size = 0;
 
    if (in_str == NULL || out_str == NULL)
        return -1;
 
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
 
    BIO_write(bio, in_str, in_len);
    BIO_flush(bio);
 
    BIO_get_mem_ptr(bio, &bptr);
    memcpy(out_str, bptr->data, bptr->length);
    out_str[bptr->length] = '\0';
	//out_str[88] = '\0';
    size = bptr->length;
 
    BIO_free_all(bio);
    return size;
}

int base64_decode(char *in_str, int in_len, char *out_str)
{
    BIO *b64, *bio;
    BUF_MEM *bptr = NULL;
    int counts;
    int size = 0;
 
    if (in_str == NULL || out_str == NULL)
        return -1;
 
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
 
    bio = BIO_new_mem_buf(in_str, in_len);
    bio = BIO_push(b64, bio);
 
    size = BIO_read(bio, out_str, in_len);
    out_str[size] = '\0';
 
    BIO_free_all(bio);
    return size;
}
*/

/*
 *  usage: ./client ip port path
 */
int get_ramdom_num(unsigned char *token_checksume)
{
    unsigned char token[64];
	//unsigned char *token_checksume2 = malloc(64);
	//token_checksume2 = *(token_checksume);
	//unsigned char token[]="123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234";
	memcpy(token,token_checksume,64);
	//TODO:存入 token
	//unsigned char token_checksume[64];
	unsigned long long checksume[8];
	//memcpy(checksume, token, 64);
	memcpy(checksume, token, 64);

	for (int i = 0; i < 8; i++)
	{
		for (int j = 0; j < 32; j++)
		{
			checksume[i] = checksume[i] * 0x9A8BDDAE2BE7 + j +0xAD262C5CDEBF8E74;
		}
	}
    memcpy(token_checksume, checksume, 64);
	/*for (int i = 0; i < 64; i++)
   {
	   WS_INFO("0x%02x ", token_checksume[i]);
   }
   WS_INFO(" \r\n");*/
}
#if 0
int au_server()
{

	memset(token_checksume, 0, sizeof(token_checksume));
	ws_base64_decode(token_checksume1,token_checksume);
	WS_INFO("base64_decode token_checksume %s \n", token_checksume);
	/*WS_INFO(" \r\n");
					for (int i = 0; i < 128; i++)
	{
	   WS_INFO("0x%02x ", token_checksume[i]);
	}
	WS_INFO(" \r\n");*/

	get_ramdom_num(token_checksume);
	//token_checksume[64]='\0';
	//WS_INFO("get_ramdom_num");
	//WS_INFO( "token_checksume is %s\n", token_checksume);

	for (int i = 0; i < 64; i++)
	{
	   WS_INFO("0x%02x ", token_checksume[i]);
	}
	WS_INFO(" \r\n");

	//base64_encode(token_checksume,strlen(token_checksume),token_checksume1);
	//WS_INFO("base64_encode %s \n", token_checksume1);
		memset(token_checksume1, 0, sizeof(token_checksume1));

	ws_base64_encode(token_checksume,token_checksume1,64);
	WS_INFO("ws_base64_encode %s \n", token_checksume1);

	memset(tokenjson, 0, sizeof(tokenjson));                        //创建协议包
	ws_buildCheckToken(token_checksume1, (char*)tokenjson); //组装http请求头
	//send(fd, httpHead, strlen((const char*)httpHead), MSG_NOSIGNAL);
					
	//ret = ws_send(fd, send_buff, strlen(send_buff), true, WDT_BINDATA);
	ret = ws_send(myssl, tokenjson, strlen(tokenjson), true, WDT_BINDATA);
	if (ret <= 0)
	{
		WS_INFO("client(%d): send failed %d, try again now ...\r\n", pid, ret);
		ret = ws_send(myssl, tokenjson, strlen(tokenjson), true, WDT_BINDATA);
		if (ret <= 0)
		{
			WS_INFO("client(%d): send failed %d, disconnect now ...\r\n", pid, ret);
			//break;
		}
	}
	else{
		//au = 1;
		WS_INFO("ws_send au success\n");
		return 0;

	}
}
#endif
int au_server()
{
    memset(token_checksume, 0, sizeof(token_checksume));
    ws_base64_decode(token_checksume1, token_checksume);
    WS_INFO("base64_decode token_checksume %s \n", token_checksume);

    get_ramdom_num(token_checksume);

    /*for (int i = 0; i < 64; i++)
    {
        WS_INFO("0x%02x ", token_checksume[i]);
    }
    WS_INFO(" \r\n");*/

    memset(token_checksume1, 0, sizeof(token_checksume1));
    ws_base64_encode(token_checksume, token_checksume1, 64);
    WS_INFO("ws_base64_encode %s \n", token_checksume1);

    memset(tokenjson, 0, sizeof(tokenjson));
    ws_buildCheckToken(token_checksume1, (char*)tokenjson);

    int retry = 3; // 设置最大重试次数
    int ret = -1;
    while (retry > 0)
    {
        ret = ws_send(myssl, tokenjson, strlen(tokenjson), true, WDT_BINDATA);
        if (ret <= 0)
        {
            WS_ERR("client(%d): send failed %d, retrying...\r\n", pid, ret);
            retry--;
        }
        else
        {
            WS_INFO("ws_send auth\n");
            return 0;
        }
    }

    if (ret <= 0)
    {
        WS_ERR("client(%d): send failed, disconnecting...\r\n");
        // 可以在发送失败后进行适当的处理，如关闭连接等
    }

    return -1; // 返回发送失败
}

bool hasIP2(const char *strSrc) {
    regex_t regex;
    int ret;
    char pattern[] = "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";
    regmatch_t match[1];
    
    if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
        return false;
    }

    ret = regexec(&regex, strSrc, 1, match, 0);
    regfree(&regex);

    if (ret == 0) {
        char ip[MY_BUF_SIZE];
        snprintf(ip, sizeof(ip), "%.*s", (int)(match[0].rm_eo - match[0].rm_so), strSrc + match[0].rm_so);
        WS_INFO("find: %s\n", ip);
        return true;
    }

    return false;
}

bool hasIP(const char *strSrc) {
	
	 regex_t regex;
	 int reti;
	 char ip_pattern[] = "([0-9]{1,3}\\.){3}[0-9]{1,3}";
	
	 // 编译正则表达式
	 reti = regcomp(&regex, ip_pattern, REG_EXTENDED);
	 if (reti) {
		 fprintf(stderr, "Could not compile regex\n");
		 return -1;
	 }
	
		 reti = regexec(&regex, strSrc, 0, NULL, 0);
		 if (!reti) {
			 WS_INFO("Found IP address: %s", strSrc);
			 regfree(&regex);
			 return true;
		 }
	
	 regfree(&regex);
	
	 return 0;

}


int getCmdResult(const char *strCmd, char *strResult, size_t resultSize) {
    FILE *fp;
    char buffer[1024] = {0};
    char strRet[1024] = {0};

    // 执行命令并打开管道
    fp = popen(strCmd, "r");
    if (fp == NULL) {
        WS_INFO("无法执行命令\n");
        return 1;
    }
	WS_ERR("strCmd %s\n", strCmd);
    // 逐行读取命令输出并存储
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		
	WS_INFO("无法执行命令\n");
        strncat(strRet, buffer, sizeof(strRet) - strlen(strRet) - 1);
		
    strRet[resultSize - 1] = '\0'; // 确保以空字符结尾
		WS_ERR("strRet %s\n", strRet);
	usleep(100*1000);
    }

    // 关闭管道
    pclose(fp);

    // 将结果复制到输出参数中
    strncpy(strResult, strRet, resultSize - 1);
    strResult[resultSize - 1] = '\0'; // 确保以空字符结尾
	WS_ERR(" %s\n", strResult);

    return 0;
}

#include <signal.h>

pid_t KillProcessPidbyName2(char *name)
{
    FILE *fptr;
    char buf[1056] = { 0 };
    char cmd[MY_BUF_SIZE] = { 0 };
    pid_t pid = -1;
    sprintf(cmd, "pidof %s", name);
    if ((fptr = popen(cmd, "r")) != NULL) {
        if (fgets(buf, sizeof(buf), fptr) != NULL) {
            pid = atoi(buf);
            //kill(pid, SIGINT);
            
			sprintf(cmd, "pidof %s", buf);
            system(cmd);
        }
    }
    if (fptr){
        pclose(fptr);
    }
    return pid;
}
int KillProcessByName(char *processName) 
{
    FILE *fp;
    char buf[MY_BUF_SIZE];
	
    char cmd[MY_BUF_SIZE] = { 0 };
	sprintf(cmd, "ps aux | grep %s | grep -v grep | awk '{print $1}'", processName);
    // 使用popen调用ps命令获取进程信息
    //fp = popen("ps aux | grep cat | grep -v grep | awk '{print $1}'", "r");
	
    fp = popen(cmd, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error opening pipe!\n");
        return -1;
    }
    // 逐行读取进程ID并杀死进程
    while (fgets(buf, sizeof(buf), fp) != NULL) {
		
		//WS_ERR(" processName %s pid: %s\n",processName, buf);
        int pid = atoi(buf);
        if (pid > 0) {
            //WS_INFO("Killing process with PID: %d\n", pid);
            kill(pid, SIGKILL);
        }
    }

    pclose(fp);

    return 0;
}

int execute4GCmd3(const char *strCmd, char *buffer) 
{
    //system(strCmd);
	
    char cmd[258];
	sprintf(cmd, "%s;cat /dev/ttyUSB2",strCmd);
    FILE *fp;
    char buf[258];

    //fp = popen("cat /dev/ttyUSB2", "r");
	
    fp = popen(cmd, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error opening pipe!\n");
        return -1;
    } else {
        WS_ERR("strCmd %s success\n", strCmd);
    }
	//int fd = fileno(fp);

	// 设置文件描述符为非阻塞模式
	//fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

    usleep(1000 * 1000);

    int i = 10;
	while(i--){
		//fflush(fp);
        if (fgets(buf, sizeof(buf), fp) != NULL){
			if(strlen(buf)>2)
			WS_ERR("Received data: %s,\n", buf,strlen(buf));
            if (strstr(buf, buffer)){
	            strcpy(buffer, buf);
	            WS_ERR("strCmd %s buffer is %s\n", strCmd, buffer);
	            pclose(fp);
	            return 0;
                break;
            } else if (strstr(buf, "OK")){
                break;
            } else if (strstr(buf, "ERROR")){
                break;
            }        
        }
    }
	WS_ERR("KillProcessByName\n");
	KillProcessByName("cat");

    pclose(fp);
    return -1;
}

#define TIMEOUT_SEC 3

int get4GSerialOutput(const char *strCmd, char *buffer) 
{
    char cmd[MY_BUF_SIZE];
    sprintf(cmd, "%s && cat /dev/ttyUSB2", strCmd);
    
    //sprintf(cmd, "cat /dev/ttyUSB2 & %s;",strCmd);
    FILE *fp;
    char buf[MY_BUF_SIZE];
    char tempBuf[MY_BUF_SIZE] = "";
	unsigned int msgLine = 0;

    fp = popen(cmd, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error opening pipe!\n");
        return -1;
    } else {
         //WS_ERR("strCmd %s success\n", strCmd);
    }

    int fd = fileno(fp);
	
    fd_set readfds;
    struct timeval timeout;
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);

    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = 0;
	//system(strCmd);

	
    while (1) {
		int ret = select(fd + 1, &readfds, NULL, NULL, &timeout);
	    if (ret == -1) {
	        perror("select failed");
	        KillProcessByName("cat");
	        pclose(fp);
	        return -2;
	    } else if (ret == 0) {
			if(msgLine > 1){
				
				WS_ERR("msg: %s \n",tempBuf);
				memcpy(buffer,tempBuf,MY_BUF_SIZE);
			
				WS_ERR("msgbuffer: %s \n",buffer);
				KillProcessByName("cat");
		        pclose(fp);				
				return 0;
			}else{				
				WS_ERR("Timeout occurred strCmd %s\n", strCmd);
		        KillProcessByName("cat");
		        pclose(fp);
		        return -2;
			}
	    }else{
			if (fgets(buf, sizeof(buf), fp) != NULL) {
				if (strlen(buf) > 1) {
					msgLine++;
					WS_ERR("Received data: msgLine:%d len:%d%s,%d\n",msgLine, strlen(buf),buf);
					strcat(tempBuf, buf);
					tempBuf[255]='\0';
					//WS_ERR("tempBuf %s \n",tempBuf);

				}
			}
		}
		
        //usleep(10000);
    }
}
int ensureGet4GOutput(const char *strCmd, char *buffer) 
{
    char cmd[MY_BUF_SIZE];
    sprintf(cmd, "cat /dev/ttyUSB2");
    
    //sprintf(cmd, "cat /dev/ttyUSB2 > ATOutput.txt &",strCmd);
    FILE *fp;
    char buf[MY_BUF_SIZE];
    char tempBuf[MY_BUF_SIZE] = "";
	unsigned int msgLine = 0;

    fp = popen(cmd, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error opening pipe!\n");
        return -1;
    } else {
         WS_ERR("strCmd %s success\n", strCmd);
    }

    int fd = fileno(fp);
	
    // 将文件描述符设置为非阻塞模式
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	
    fd_set readfds;
    struct timeval timeout;
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);

    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
	system(strCmd);

	
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        if (strlen(buf) > 1) {
            msgLine++;
            WS_ERR("output_fd data: msgLine:%d len:%d%s,%d\n", msgLine, (int)strlen(buf), buf);
            strncat(tempBuf, buf, sizeof(tempBuf) - strlen(tempBuf) - 1);
							KillProcessByName("cat");
		        pclose(fp);	
				return 0;
            if (msgLine >= 5) {
                break; // 限制读取的行数
            }
        }
    }

}
int execute4GCmd(const char *strCmd, char *buffer) {
	
	int ret;
    //char buf[MY_BUF_SIZE] = {0};
	int getCNT = 5;
	while(getCNT--){
		
	    char buf[MY_BUF_SIZE] = {0};
		//ret = get4GSerialOutput(strCmd,buf);
		ret = Get4GOutputBySaveFile(strCmd,buf);
		if(!ret){
			if (strstr(buf, buffer)) {
				strcpy(buffer, buf);
				WS_ERR("strCmd %s buffer is %s\n", strCmd, buffer);
				return 0;
			} else if (strstr(buf, "OK")) {
				
				WS_ERR("OK\n");
				ret =  0;
			} else if (strstr(buf, "ERROR")) {
				
				WS_ERR("ERROR\n");
				ret =  -1;
			}
			
		}else if (ret == -2){
			WS_ERR("select failed or Timeout occurred try again\n");	
			ret =  -2;
		}
	}
	
	return ret;
}

int Get4GOutputBySaveFile(const char *strCmd, char *buffer) 
{
    char cmd[MY_BUF_SIZE];
    //sprintf(cmd, "%s && cat /dev/ttyUSB2", strCmd);
    
    //sprintf(cmd, "cat /dev/ttyUSB2 > ATOutput.txt &",strCmd);
    FILE *fp;
    char buf[MY_BUF_SIZE];
    char tempBuf[MY_BUF_SIZE] = "";
	unsigned int msgLine = 0;


	
	system("cat /dev/ttyUSB2 > /tmp/ATOutput.txt &");
	system(strCmd);
	
	KillProcessByName("cat");
	
	usleep(100*1000);
	WS_ERR("strCmd %s success\n", strCmd);
	
	fp = fopen("/tmp/ATOutput.txt" , "r");
	if(fp == NULL) {
	   perror("打开文件时发生错误");
	   return(-1);
	}
	int i=3;
	fseek(fp, 0, SEEK_SET); // 将文件指针重新定位到文件开头
    while (i--) {
		if (fgets(buf, sizeof(buf), fp) != NULL) {
	            msgLine++;
	            WS_INFO("output_fd data: msgLine:%d len:%d%s,%d\n", msgLine, (int)strlen(buf), buf);
				strcat(tempBuf, buf);
				tempBuf[255]='\0';
				
	            //if (msgLine >= 5) {
	            //    break; // 限制读取的行数
	            //}
		}else{
				fseek(fp, 0, SEEK_SET);
				WS_ERR("fgets null\n");

		}
    }
	
	if(msgLine > 1){
				
		//WS_ERR("msg: %s \n",tempBuf);
		memcpy(buffer,tempBuf,MY_BUF_SIZE);
	
		WS_ERR("msgbuffer: %s \n",buffer);
		//KillProcessByName("cat");
        fclose(fp);				
		return 0;
	}else{				
		WS_ERR("fgets err strCmd %s\n", strCmd);
        //KillProcessByName("cat");
        fclose(fp);
        return -1;
	}


}

int getATOutput(const char *strCmd, char *buffer) 
{
	
	int ret;
	int getCNT = 10;
	while(getCNT--){
		
    	char buf[MY_BUF_SIZE] = {0};
		ret = Get4GOutputBySaveFile(strCmd,buf);
		if(!ret){
			
			WS_ERR("strCmd %s \n buf %s\n buffer is %s\n", strCmd, buf,buffer);
			if (strstr(buf, buffer)) {
				strcpy(buffer, buf);
				WS_ERR("strCmd %s buffer is %s\n", strCmd, buffer);
				return 0;
			} else if (strstr(buf, "OK")){
				
				WS_ERR("OK\n");
			} else if (strstr(buf, "ERROR")){
				
				WS_ERR("ERROR\n");
			}
			
			//return -1;

		}else{
			WS_ERR("cant get ATOutput, try again\n");	
		}
	}
	WS_ERR("cant get ATOutput, please try again\n");
	return -1;
}

int dail4G()
{
	int ret;
    int dailCnt = 0;
    int autoDailCnt = 0;
    char buffer[MY_BUF_SIZE]={0};

	memset(buffer,0,MY_BUF_SIZE);
	strcpy(buffer, "+MDIALUPCFG: \"auto\"");
	ret = getATOutput("echo -e 'AT+MDIALUPCFG=\"auto\"' > /dev/ttyUSB2",buffer);
	if(ret == 0)
	{	
		if (strstr(buffer, "\"auto\",0")!= NULL)
		{
			WS_ERR("is not auto dail \n");
			memset(buffer,0,MY_BUF_SIZE);
			strcpy(buffer, "OK");
			ret = getATOutput("echo -e 'AT+MDIALUPCFG=\"auto\",1' > /dev/ttyUSB2",buffer);
			if(ret == 0)
			{	
				
				WS_ERR("auto dail success \n");
			}else{
				WS_ERR("auto dail fail \n");
				return -1;
			}
		}else if(strstr(buffer, "\"auto\",1")!= NULL){
			WS_ERR("is auto dail \n");
		}
		
	}else if(ret == -1){
			WS_ERR("ERROR!!!, please dail agai\n");			

			return -1;
	}
	
	memset(buffer,0,MY_BUF_SIZE);
	strcpy(buffer, "MDIALUP");
	ret = getATOutput("echo -e 'AT+MDIALUP?\r\n' > /dev/ttyUSB2",buffer);
	
	WS_ERR("MDIALUP buffer is %s\n", buffer);
	if(ret == -1){
		WS_ERR("ERROR!!!, please dail agai\n");				

		return -1;
	}else if (!hasIP(buffer)) {
		memset(buffer,0,MY_BUF_SIZE);
		strcpy(buffer, "OK");
		ret = getATOutput("echo -e 'AT+MDIALUP=1,1\r\n' > /dev/ttyUSB2",buffer);
		if(ret == 0)
		{
			
			WS_ERR("MDIALUP success\n");
		}else{
			
			WS_ERR("MDIALUP fail\n");
			return -1;
		}
	}else{
		
		WS_ERR("MDIALUP hasIP\n");
	}	
	
	//execute4GCmd("echo -e 'AT+MDIALUP=1,1\r\n' > /dev/ttyUSB2",buffer);
	
	//memset(buffer,0,258);
	//execute4GCmd("echo -e 'AT+MDIALUPCFG=\"auto\",1\r\n' > /dev/ttyUSB2",buffer);
	
	memset(buffer,0,MY_BUF_SIZE);
	strcpy(buffer, "MIPCALL");
	ret = getATOutput("echo -e 'AT+MIPCALL?\r\n' > /dev/ttyUSB2",buffer);
	if(ret == 0)
	{
		
		WS_ERR("MIPCALL success\n");
		if (hasIP(buffer)) {
			
			WS_ERR("MIPCALL hasIP\n");
		}
	}else if(ret == -1){
		
		WS_ERR("ERROR!!!, please dail agai\n");
		return -1;
	}
	KillProcessByName("udhcpc");
	system("udhcpc -i 4g0");	

	return 0;
}

int dail4G2()
{
	int ret;
    int dailCnt = 0;
    int autoDailCnt = 0;
    char buffer[MY_BUF_SIZE]={0};
autodail:

	memset(buffer,0,MY_BUF_SIZE);
	strcpy(buffer, "+MDIALUPCFG: \"auto\"");
	ret = execute4GCmd("echo -e 'AT+MDIALUPCFG=\"auto\"' > /dev/ttyUSB2",buffer);
	if(ret == 0)
	{	
		if (strstr(buffer, "\"auto\",0")!= NULL)
		{
			WS_ERR("is not auto dail \n");
			memset(buffer,0,MY_BUF_SIZE);
			strcpy(buffer, "OK");
			ret = execute4GCmd("echo -e 'AT+MDIALUPCFG=\"auto\",1' > /dev/ttyUSB2",buffer);
			if(ret == 0)
			{	
				
				WS_ERR("auto dail success \n");
			}else{
				WS_ERR("auto dail fail \n");
				return -1;
			}
		}else if(strstr(buffer, "\"auto\",1")!= NULL){
			WS_ERR("is auto dail \n");
		}
		
	}else if(ret == -2){
			WS_ERR("select failed or or error or Timeout,%d\n",autoDailCnt);			
			if(autoDailCnt++ < 3){
				goto autodail;
			}else{
				autoDailCnt = 0;
				
				//system("udhcpc -i 4g0");
				return -1;
			}
	}
dail:

	memset(buffer,0,MY_BUF_SIZE);
	strcpy(buffer, "MDIALUP");
	ret = execute4GCmd("echo -e 'AT+MDIALUP?\r\n' > /dev/ttyUSB2",buffer);
	if(ret == -2){
			WS_ERR("select failed or Timeout occurred try again\n");			
			if(dailCnt++ < 3){
				goto dail;
			}else{
				dailCnt = 0;
				
				//system("udhcpc -i 4g0");
				return -1;
			}
	}
	WS_ERR("MDIALUP buffer is %s\n", buffer);
	if (!hasIP(buffer)) {
		memset(buffer,0,MY_BUF_SIZE);
		strcpy(buffer, "OK");
		ret = execute4GCmd("echo -e 'AT+MDIALUP=1,1\r\n' > /dev/ttyUSB2",buffer);
		if(ret == 0)
		{
			
			WS_ERR("MDIALUP success\n");
		}else{
			
			WS_ERR("MDIALUP fail\n");
			return -1;
		}
	}else{
		
		WS_ERR("MDIALUP hasIP\n");
	}	
	
	//execute4GCmd("echo -e 'AT+MDIALUP=1,1\r\n' > /dev/ttyUSB2",buffer);
	
	//memset(buffer,0,258);
	//execute4GCmd("echo -e 'AT+MDIALUPCFG=\"auto\",1\r\n' > /dev/ttyUSB2",buffer);
	
	memset(buffer,0,MY_BUF_SIZE);
	strcpy(buffer, "MIPCALL");
	ret = execute4GCmd("echo -e 'AT+MIPCALL?\r\n' > /dev/ttyUSB2",buffer);
	if(ret == 0)
	{
		
		WS_ERR("MIPCALL success\n");
		if (hasIP(buffer)) {
			
			WS_ERR("MIPCALL hasIP\n");
		}
	}else if(ret == -1){
		
		WS_ERR("MIPCALL fail");
		if(dailCnt++ < 3){
			goto dail;
		}else{			
			dailCnt = 0;
			//system("udhcpc -i 4g0");
			return -1;
		}
	}else if(ret == -2){
			WS_ERR("select failed or or error or Timeout\n");			
			if(dailCnt++ < 3){
				goto dail;
			}else{
				dailCnt = 0;
				
				//system("udhcpc -i 4g0");
				return -1;
			}
	}
	
	KillProcessByName("udhcpc");
	system("udhcpc -i 4g0");	

	return 0;
}
int test4Gcmd()
{
	int ret;
    int dailCnt = 0;
    int autoDailCnt = 0;
    char buffer[MY_BUF_SIZE]={0};
	
	KillProcessByName("udhcpc");
	system("udhcpc -i 4g0");	
	memset(buffer,0,MY_BUF_SIZE);
	strcpy(buffer, "CCLK");
	ret = getATOutput("echo -e 'AT+CCLK?\r\n' > /dev/ttyUSB2",buffer);

	memset(buffer,0,MY_BUF_SIZE);
	strcpy(buffer, "CESQ");
	ret = getATOutput("echo -e 'AT+CESQ\r\n' > /dev/ttyUSB2",buffer);

	memset(buffer,0,MY_BUF_SIZE);
	strcpy(buffer, "CESQ");
	ret = execute4GCmd("echo -e 'AT+CESQ\r\n' > /dev/ttyUSB2",buffer);

	return 0;
}

int check4GDail()
{
	
	int ret;
    FILE *fp;
    char buffer[258];

    fp = popen("cat /sys/class/net/4g0/carrier", "r");
    if (fp == NULL) {
        WS_ERR("Error opening pipe!\n");
        return -1;
    }
	if(fgets(buffer, 64, fp)!= NULL){
	if (strstr(buffer, "1") != NULL) {
	    WS_ERR("4g is available %s\n", buffer);
		//return 0;
		
		memset(buffer,0,MY_BUF_SIZE);
		strcpy(buffer, "MDIALUP");
		ret = getATOutput("echo -e 'AT+MDIALUP?\r\n' > /dev/ttyUSB2",buffer);
		WS_ERR("MDIALUP buffer is %s\n", buffer);
		if (!hasIP(buffer)) {
			memset(buffer,0,MY_BUF_SIZE);
			strcpy(buffer, "OK");
			ret = getATOutput("echo -e 'AT+MDIALUP=1,1\r\n' > /dev/ttyUSB2",buffer);
			if(ret == 0)
			{
				
				WS_ERR("MDIALUP success\n");
				
				pclose(fp);
				return 0;
			}else{
				
				WS_ERR("MDIALUP fail\n");				
				pclose(fp);
				return -1;
			}
		}else{
			
			WS_ERR("MDIALUP hasIP\n");
			
			pclose(fp);
			return 0;
		}

	}
	}else{
		WS_ERR("4g is not available,please wait redail\n", buffer);
		ws_delayms(10*1000);
		ret = dail4G();
		if(ret<0)
		{
			pclose(fp);
			return -1;
		}
	}
	return 0;

}
int linkCmdServer(char* ip, int32_t port, char* path)
{
	int ret;

	WS_INFO("client wss://%s:%d%s pid/%d\r\n", ip, get_port, path, pid);
    if ((ret = ws_requestServer(ip, get_port, path, 3000)) <= 0)
    {
        WS_ERR("connect failed !!\r\n");
		closewsl();
        return -1;
    }else{
		WS_INFO("connect success !!\r\n");
    }
	ret = au_server();
	if(-1 == ret)
		return -1;

	fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(myfd, &readfds);

    struct timeval timeout;
    timeout.tv_sec = 5;  // Timeout of 5 seconds
    timeout.tv_usec = 0;

    int ready = select(myfd + 1, &readfds, NULL, NULL, &timeout);
    if (ready == -1) {
        perror("select failed");
        return -1;
    } else if (ready == 0) {
        WS_INFO("select timeout, no data available for reading\n");
        return -1;
    }else{
		ret = ws_recv(myssl, recv_buff, sizeof(recv_buff), &retPkgType);		
		if (ret > 0)
		{
			WS_INFO("111client(%d): recv len/%d %s\r\n", pid, ret, recv_buff);
			
			if (strstr(recv_buff, "\"code\":200") != NULL)
            {
				WS_INFO("111au success \r\n");
				return 0;

            }else if(strstr(recv_buff, "\"code\":403") != NULL){
				WS_ERR("au fail \r\n");
				return -1;

			}else				
				WS_INFO("recv > 0 unknown !!\r\n");			
				return -1;

		}else if(ret < 0){
			WS_INFO("recv <= 0 linkCmdServer fail!!\r\n");
			//recvCount--;
		}
    }
//	int recvCount = 3; // 设置最大重试次数
//	while(recvCount-- > 0)
//	{
//		//接收数据
//
//		ret = ws_recv(myssl, recv_buff, sizeof(recv_buff), &retPkgType);		
//		if (ret > 0)
//		{
//			WS_INFO("111client(%d): recv len/%d %s\r\n", pid, ret, recv_buff);
//			
//			if (strstr(recv_buff, "\"code\":200") != NULL)
//            {
//				WS_INFO("111au success \r\n");
//				return 0;
//
//            }else if(strstr(recv_buff, "\"code\":403") != NULL){
//				WS_ERR("au fail \r\n");
//				return -1;
//
//			}else				
//				WS_INFO("recv > 0 unknown !!\r\n");			
//				return -1;
//
//		}else if(ret < 0){
//			WS_INFO("recv <= 0 linkCmdServer fail!!\r\n");
//			//recvCount--;
//		}
//		ws_delayms(10);
//
//	}

    return -1;
}

int linkWebServer()
{

#ifdef FIREALARM
	WS_INFO("FIREALARM version\r\n");
	memset(path, 0, sizeof(path));
	char pathDemo[] = "/device?sn=%s&type=0";
	sprintf(path, pathDemo, SN);
	strcpy(ip, "ws5.daguipc.com");
	
	//strcpy(ip, "dgiot.tpddns.cn");
	get_port = 7758;

#else
	WS_INFO("universal version\r\n");
	memset(path, 0, sizeof(path));
	char pathDemo[] = "/server";
	sprintf(path, pathDemo);
	strcpy(ip, "ipc.daguiot.com");
	
    //用本进程pid作为唯一标识
    pid = getpid();
    WS_INFO("client https://%s:%d%s pid/%d\r\n", ip, port, path, pid);

    //3秒超时连接服务器
    //同时大量接入时,服务器不能及时响应,可以加大超时时间
	if ((fd = ws_requestQuServer(ip, port, path, 3000)) <= 0)
	//if (0)
    {
        WS_ERR("connectQu failed !!\r\n");
		closewsl();
        return -1;
    }else{
		closewsl();
		WS_INFO("connectQu success !!\r\n");
		//port = 7758;
		memset(path, 0, sizeof(path));
		char pathDemo[] = "/device?sn=%s&type=0";
		sprintf(path, pathDemo, SN);
		//strcpy(path, "/device?sn=6902200000099990&type=0");
		//strcpy(ip, "192.168.100.20");
		//get_port = 7758;
	}

#endif
	
	int ret = linkCmdServer(ip, get_port, path);
	if(-1 == ret)
	{
		
		WS_INFO("linkCmdServer fail!!!\n");
        return -1;
	}else{
		
		WS_INFO("linkCmdServer success!!!\n");
		return 0;
	}

}
typedef int (*handleData)(char* data, int length);

int netlink_check()
{
	
	int net_fd;
	char statue[20];
	
	net_fd=open("/sys/class/net/eth0/operstate",O_RDONLY);//以只读的方式打开/sys/class/net/eth0/operstate carrier
	if(net_fd<0)
	{
	
		WS_INFO("open eth0/operstate err\n");
		return 0;
	}
	
	WS_INFO("open success\n");
	memset(statue,0,sizeof(statue));
    int ret=read(net_fd,statue,10);
    WS_INFO("statue is %s",statue);
	if(NULL!=strstr(statue,"up"))
	{
		WS_INFO("on line\n");
		return 1;
	}
	else if(NULL!=strstr(statue,"down"))
	{
	   WS_INFO("off line\n");
	   return -1;
	}
	else
	{
		WS_INFO("unknown err\n");
		return 0;
	}
	close(net_fd);

}

int wssend(char *buf,int len)
{
	memset(send_buff, 0,sizeof(send_buff));
	memcpy(send_buff,buf,len);
	
	//WS_INFO("!!!!!send_buff%s send_buff %d\n", send_buff,sizeof(send_buff));
	/*ret = ws_send(myssl, buf, len, true, WDT_TXTDATA);
	//ret = wolfSSL_write(myssl, buf, len);
	if (ret > 0) {
	// 数据成功写入
			WS_INFO("数据成功写入%d\n",ret);
	} else {
		// 发生错误
			WS_INFO("发生错误%d\n",ret);
	}
	return ret;*/
}

// 发送心跳的函数
void* dg_send(void* arg) 
{
	int ret;
	char* jsonData;
	int32_t jsonDataLen;
	jsonData = (char*)arg;
	
    while (gHeartThreadExit == FALSE && g_isSg) {
        if (nopong_cnt > 10) {
        
        //if (0) {
            WS_INFO("!!!!!client: not recv WDT_PONG %d\n", nopong_cnt);		
			WS_INFO("!!!!!******disconnect server\n******connect to the xinling server\n");
            nopong_cnt = 0;
			g_isSg =  0;
			g_is4GDail = 0;
			g_fb4GDail = 0;
			closewsl();
#ifdef FIREALARM
			WS_INFO("FIREALARM version\r\n");
			memset(path, 0, sizeof(path));
			char pathDemo[] = "/device?sn=%s&type=0";
			sprintf(path, pathDemo, SN);
			//strcpy(ip, "iot.daguiot.com");
			
			strcpy(ip, "iot.daguiot.com");
			get_port = 7758;			
			ret = linkCmdServer(ip, get_port, path);
		
#else
			ret = linkCmdServer(ip, get_port, path);		
#endif
			if(!ret){
				g_isSg = 1;
				g_is4GDail = 1;
				g_fb4GDail = 1;
				continue;
			}else{
				
				//g_is4GDail = 0;
				ws_delayms(10*1000);
				gHeartThreadExit = TRUE;
				gHeartThread = 0;
			}
			/*if(++g_hbdiscnt == 1){
				ret = linkCmdServer(ip, get_port, path);
				if(!ret){					
					g_hbdiscnt = 0;
					continue;
				}else{

				}
			}
			if(++g_hbdiscnt == 2){
				g_hbdiscnt = 0;
				g_isSg =  0;
			}*/
        }

        heart += 1;
        if (heart > interval * 10) {
            heart = 0;

            // 发送心跳
            // 实现发送心跳的逻辑
            
			ret =  ws_send(myssl, NULL, 0, true, WDT_PING);
			//send返回异常, 连接已断开
			if (ret <= 0)
			{
				WS_INFO("!!!!!client(%d): send failed %d, disconnect now ...\r\n", pid, ret);
				gHeartThreadExit = TRUE;
			}else{
				nopong_cnt++;
				WS_INFO("client: send WDT_PING %d\r\n",nopong_cnt);
			}

        }
		jsonDataLen = strlen(jsonData);
	    if (jsonDataLen > 0) {
            // 传入的参数即为额外数据
            //jsonData = (char*)arg;
            //jsonDataLen = strlen(jsonData);
			ret = ws_send(myssl, jsonData, jsonDataLen, true, WDT_TXTDATA);
            if (ret <= 0) {
                WS_INFO("client: send failed with json data, disconnecting now...\n");
                gHeartThreadExit = TRUE;
			
				memset(send_buff, 0,sizeof(send_buff));
            } else {
                WS_INFO("client:send json success Data%s,jsonDataLen%d\n",jsonData,jsonDataLen);
				
				memset(send_buff, 0,sizeof(send_buff));
            }
        }
        //sleep(1); // 每次心跳间隔为秒
        
		usleep(100000);
    }
    WS_INFO("sendJsonHeart exit\n");
    pthread_exit(NULL);

    //return NULL;
}

// 启动心跳线程
void startHeartThread(void)
{
    gHeartThreadExit = FALSE;
    int ret           = 0;

    WS_INFO("start HeartThread thread\n");

    if (0 != gHeartThread)
    {
        WS_ERR("alread start\n");
        return 0;
    }

    pthread_create(&gHeartThread, NULL, dg_send, send_buff);
    if (0 == ret)
        pthread_setname_np(gHeartThread, "sendHeart");
    else
        WS_ERR("pthread_create failed\n");
	
	pthread_detach(gHeartThread);

    return ret;
}

// 修改心跳间隔
void setHeartInterval(int newInterval) {
    interval = newInterval;
	
	WS_INFO("current HeartInterval is (%d) \r\n", interval);
}

// 停止心跳线程
void stopHeartThread() {
    pthread_cancel(gHeartThread);
}

int getTimeFromJSON(const char* json_data) {
    const char* code_key = "\"code\":9";
    const char* time_key = "\"time\":";

    char* code_pos = strstr(json_data, code_key);
    if (code_pos == NULL) {
        return -1; // Code 9 not found
    }

    char* time_pos = strstr(code_pos, time_key);
    if (time_pos == NULL) {
        return -1; // Time key not found
    }

    // Extract the integer value for time
    int time_value;
    sscanf(time_pos + strlen(time_key), "%d", &time_value);

    return time_value;
}
int recvDataCall(handleData callback)
{
    int ret;
    memset(recv_buff, 0, sizeof(recv_buff));
    retPkgType = 0;
    
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(myfd, &readfds);

    struct timeval timeout;
    timeout.tv_sec = 5;  // Timeout of 5 seconds
    timeout.tv_usec = 0;

    int ready = select(myfd + 1, &readfds, NULL, NULL, &timeout);
    if (ready == -1) {
        perror("select failed");
        return -1;
    } else if (ready == 0) {
        WS_INFO("select timeout, no data available for reading\n");
        return 0;
    }else{

	    // Set the socket to non-blocking mode
//	    int flags = fcntl(myfd, F_GETFL, 0);
//	    fcntl(myfd, F_SETFL, flags | O_NONBLOCK);

	    // Read data from the socket
	    ret = ws_recv(myssl, recv_buff, sizeof(recv_buff), &retPkgType);
	    WS_INFO("ws_recv(%d) \r\n", ret);

	    if (ret > 0) {
	        if (strstr(recv_buff, "\"code\":9") != NULL) {
	            int time_value = getTimeFromJSON(recv_buff);
	            if (time_value != -1) {
	                WS_INFO("Time value: %d\n", time_value);
	                setHeartInterval(time_value);
	            } else {
	                WS_INFO("Error: time key not found\n");
	            }
	            return 0;
	        }
	        WS_INFO("ret %d recv_buff%s\r\n", ret, recv_buff);
	        callback(recv_buff, sizeof(recv_buff));
	        return ret;
	    } else if (retPkgType == WDT_DISCONN) {
	        WS_INFO("client(%d): recv WDT_DISCONN \r\n", pid);
	        return -1;
	    } else if (retPkgType == WDT_PING) {
	        WS_INFO("client(%d): recv WDT_PING \r\n", pid);
	    } else if (retPkgType == WDT_PONG) {
	        nopong_cnt--;
	        WS_INFO("client: recv WDT_PONG %d, errno %d\r\n", nopong_cnt, errno);
	        return 0;
	    } else if ((ret == -1) && (errno == EWOULDBLOCK || errno == EINTR || errno == 0)) {
	        WS_INFO("No receive data !!\r\n");
	        WS_INFO("ret %d %s%d\n", ret, strerror(errno), errno);
	        return 0;
	    } else {
	        WS_INFO("******disconnect server******\nabnormal connection  ret %d  errno %d!!\r\n", ret, errno);
	        return -1;
	    }
    }
    return ret;
}

int recvDataCall2(handleData callback)
{
	
	int ret;
	memset(recv_buff, 0, sizeof(recv_buff));
	retPkgType = 0;
	//ret = wolfSSL_read(myssl, recv_buff, recv_buff);
	ret = ws_recv(myssl, recv_buff, sizeof(recv_buff), &retPkgType);	
	WS_INFO("ws_recv(%d) \r\n", ret);
	if (ret > 0)
	{
		if (strstr(recv_buff, "\"code\":9") != NULL)
        {
			int time_value = getTimeFromJSON(recv_buff);
		    if (time_value != -1) {
		        WS_INFO("Time value: %d\n", time_value);
				setHeartInterval(time_value);
		    } else {
		        WS_INFO("Error: time key not found\n");
		    }
			return 0;

        }
		WS_INFO("ret %d recv_buff%s\r\n", ret,recv_buff);
		callback(recv_buff,sizeof(recv_buff));
		return  ret;
	}else if (retPkgType == WDT_DISCONN)
    {
        WS_INFO("client(%d): recv WDT_DISCONN \r\n", pid);
		
		return -1;
    }
    else if (retPkgType == WDT_PING){
        WS_INFO("client(%d): recv WDT_PING \r\n", pid);
    }
    else if (retPkgType == WDT_PONG){
		nopong_cnt--;
        WS_INFO("client: recv WDT_PONG %d,errno%d\r\n", nopong_cnt,errno);
		return 0;
    }else if ((ret == -1) && (errno == EWOULDBLOCK || errno == EINTR || errno == 0)){		//EWOULDBLOCK,EINTR 11 4
		WS_INFO("No receive data   !!\r\n");
		
		WS_INFO("ret %d %s%d\n", ret ,strerror(errno),errno); 
		//if(net_stat++ > 1)
		if(0)
		{
			net_stat = 0;
			return -1;
			net_stat = 0;
			ret = netlink_check();
			if (ret <= 0)
			{
				return -1;
			}else{
				return 0;
			}
								
		}
			
		return 0;
	}else{

		WS_INFO("******disconnect server******\nabnormal connection  ret%d  errno%d!!\r\n",ret,errno);
		return -1;
	}
	return  ret;
}


int ensure4gConnection()
{
	
	int ret;
	while(1)
	{
		if(!g_is4G)
		{
		    ret = dail4G();
		    WS_INFO("dail4G ret %d\n", ret);
		    if (!ret) {
		        g_is4G = true;
				
				return 0;
		        WS_INFO("dail4G g_is4G %d\n", g_is4G);
		    } else {
		        g_is4G = false;
		        WS_INFO("dail4G g_is4G %d\n", g_is4G);
		    }
		}
		if(!g_is4GDail && !g_fb4GDail){
		    ret = check4GDail();
		    if (!ret) {
		        g_is4GDail = true;
				
				return 0;
		        WS_INFO("check4GDail g_is4GDail %d\n", g_is4GDail);
				//return 0;
		    } else {
		        g_is4GDail = false;
		        WS_INFO("check4GDail g_is4GDail %d\n", g_is4GDail);
		    }
		}
		if(!g_is4GDail)
		{			
			WS_INFO("check4GDail,wait \n");
			sleep(5);
		}
//		if(g_is4G || g_is4GDail)
//		{
//			return 0;
//		}
		usleep(100000);
    }
}

void* link4G(void* arg) 
{
    int ret;
    while (gLink4gThreadExit == FALSE) {
        //if (!g_is4G && !g_is4GDail) {
            ret = ensure4gConnection();
            if (ret == 0) {
                //break;
				WS_ERR("link4G success\n");
                gLink4gThreadExit = TRUE;
            }
        //}
        
		WS_ERR("link4G thread ing\n");
        usleep(100000);
    }
    WS_INFO("link4G exit\n");
    pthread_exit(NULL);
}

// 启动心跳线程
void startLink4G(void)
{
    gLink4gThreadExit = FALSE;
    int ret           = 0;

    WS_ERR("start link4G thread\n");

    if (0 != gLink4gThread)
    {
        WS_ERR("alread start\n");
        return 0;
    }

    pthread_create(&gLink4gThread, NULL, link4G, NULL);
    if (0 == ret)
        pthread_setname_np(gLink4gThread, "link4G");
    else
        WS_ERR("pthread_create failed\n");
	
	pthread_detach(gLink4gThread);

    return ret;
}

void* connectWebServer(void* arg) 
{
	int ret;
    while (gWebsocketThreadExit == FALSE) {
		
		if (g_is4G && g_is4GDail && !g_isSg) {
			
			ret = linkWebServer();
			if (ret < 0) {
				
				WS_INFO("linking WebServer fail\n");
				g_isSg = false;
				continue;
			}else{
				
				WS_INFO("linking WebServer success\n");
				g_isSg = true;
				gWebsocketThreadExit = TRUE;
			}
		}
		if(!g_isSg)
		{			
			WS_INFO("connecting Server,wait \n");
			sleep(5);
		}
		
		usleep(10000);
    }
    WS_INFO("connectWebServer exit\n");
    pthread_exit(NULL);

    //return NULL;
}

// 启动心跳线程
void startWebServer(void)
{
    gWebsocketThreadExit = FALSE;
    int ret           = 0;

    WS_ERR("start websocketThread thread\n");

    if (0 != gWebsocketThread)
    {
        WS_ERR("alread start\n");
        return 0;
    }

    pthread_create(&gWebsocketThread, NULL, connectWebServer, NULL);
    if (0 == ret)
        pthread_setname_np(gWebsocketThread, "WebServer");
    else
        WS_ERR("pthread_create failed\n");

	pthread_detach(gWebsocketThread);

    return ret;
}
void ws_buildCode1(char* package)
{
    const char CheckToken[] = "{\"code\":1,\"message\":\"deviceinfo\",\"data\":{\"iccid\":\"\",\"link\":0,\"use\":0,\"sn\":\"6902200010110823\",\"hv\":\"TX5112CV300\",\"sv\":\"v1.0.0.1\"}}";

    sprintf(package, CheckToken);
	printf("package %s\n",package);

}
void clearThreadId()
{
	if(gLink4gThreadExit){
	
			gLink4gThread = 0;
	}
	if(gHeartThreadExit){
	
			gHeartThread = 0;
	}
	if(gWebsocketThreadExit){
	
			gWebsocketThread = 0;
	}
}
int wslConnect(char *snStr, Ondata handleJson, OnStatus linkStatus)
{
    int ret = 0;
    int hbSel = 1;

    WS_GET_SN(snStr);

    while (1) {
		while(0 == gWslConnectExit){
			clearThreadId();
	        if (0 == gLink4gThread && (!g_is4G || !g_is4GDail) )
	    	{
				
				startLink4G();
			}
			if (0 == gWebsocketThread && g_is4GDail && !g_isSg)
	    	{
				
				startWebServer();
			}
	        if (0 == gHeartThread && g_isSg)
	    	{
				
				startHeartThread();
			}
			if(g_isSg){
	        ret = recvDataCall(handleJson);
				if(ret < 0){
					if(g_isSg){
						closewsl();
						g_is4GDail = 0;
			            g_isSg = 0;
		
						closewsl();
#ifdef FIREALARM
						WS_INFO("FIREALARM version\r\n");
						memset(path, 0, sizeof(path));
						char pathDemo[] = "/device?sn=%s&type=0";
						sprintf(path, pathDemo, SN);
						//strcpy(ip, "iot.daguiot.com");
						
						//strcpy(ip, "dgiot.tpddns.cn");
						
						strcpy(ip, "ws5.daguipc.com");
						get_port = 7758;			
						ret = linkCmdServer(ip, get_port, path);
		
#else					
						ret = linkCmdServer(ip, get_port, path);		
#endif
						if(!ret){
							g_isSg = 1;
							g_is4GDail = 1;
							//g_fb4GDail = 1;
							continue;
						}else{
							
							//g_is4GDail = 0;
							gHeartThread = 0;
							gLink4gThread = 0;
							gWebsocketThread  = 0;
						}
					}
					
					WS_INFO("OnStatus g_is4G %d g_is4GDail%d g_isSg %d\n", g_is4G, g_is4GDail, g_isSg);
		            linkStatus(&g_is4G, &g_isSg);

		        }else if (ret > 0) {
		            g_isSg = 1;
		            linkStatus(&g_is4G, &g_isSg);
		        }else{
		            WS_INFO("No receive data !!\r\n");
		            //g_isSg = 1;
		            linkStatus(&g_is4G, &g_isSg);
					
				/*char httpHead[512] = {0};
				memset(httpHead, 0, sizeof(httpHead));   
				//创建协议包
				ws_buildCode1(httpHead); //组装http请求头

				wssend(httpHead, strlen((const char*)httpHead));*/
		        	}	
			}
			//WS_INFO("!!!!!!!\r\n");

	        usleep(10000);
		}
    }

    WS_INFO("connect exit !!\r\n");

    return 0;
}

#if 0
int wslConnect2(char *snStr, Ondata handleJson, OnStatus linkStatus)
{
	
	bool *g_isSg=0;
	bool *g_is4G=0;
  	int hbSel = 1;
	
	WS_GET_SN(snStr);
	//check4G();
	ret = dail4G();
	WS_INFO("dail4G ret%d\n",ret);
	if(!ret){
		
		*g_is4G = 1;
		
		WS_INFO("dail4G *g_is4G%d\n",*g_is4G);
	}else{
		*g_is4G = 0;
		
		WS_INFO("dail4G *g_is4G%d\n",*g_is4G);
	}
	if(*g_is4G)
	{
		
	WS_INFO("!!!!ip %s !!\r\n",ip);
		ret = linkWebServer(ip);
		if (ret < 0)
		{
			WS_INFO("au fail\n");
			//return -1;
		}
	}

	while(1){
			ret = sendHeart(hbSel);
			ret += setrecdataca11(handleJson);
			if (ret >= 0)
			{
				*g_isSg = 1;
				linkStatus(g_is4G,g_isSg);
			}else if(ret == 0){
				WS_INFO("No receive data	!!\r\n");
				*g_isSg = 1;
				linkStatus(g_is4G,g_isSg);
			}else{
				WS_INFO("******disconnect server******\n");
				
				*g_isSg = 0;
				
				linkStatus(g_is4G,g_isSg);
				closewsl();
				if(!g_is4G){						
					ret = dail4G();
					if(!ret){
						*g_is4G = 1;
					}else{
						*g_is4G = 0;
					}
				}
				ret = check4GDail();
				if(!ret){
					
					*g_is4G = 1;
				
					WS_INFO("dail4G *g_is4G%d\n",*g_is4G);
				}else{
					*g_is4G = 0;
					
					WS_INFO("dail4G *g_is4G%d\n",*g_is4G);
				}
				//break;
				if(*g_is4G = 1)
				{
					ret = linkWebServer(ip);
					if(ret < 0){
						*g_isSg=0;
						continue;
					}
				}
			}
			
			//WS_INFO("******\nconnect server******\n");
		//}
		usleep(10000);
	}

	WS_INFO("connect exit !!\r\n");	

	return 0;

}
#endif


#endif
