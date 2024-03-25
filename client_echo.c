//client_echo.c
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <wolfssl/openssl/ssl.h>  //wolfssl转openssl的兼容层

#define MAXLINE     4096
#define SERV_PORT        9877   

#define OPEN_SSL

#ifdef OPEN_SSL
void str_cli_ssl(FILE *fp, SSL* ssl)
{
    char    sendline[MAXLINE], recvline[MAXLINE];
    int     n = 0;

    while (fgets(sendline, MAXLINE, fp) != NULL) {

        if(SSL_write(ssl, sendline, strlen(sendline)) !=
                strlen(sendline)){
            printf("wolfSSL_write failed");
        }

        if ((n = SSL_read(ssl, recvline, MAXLINE)) <= 0)
            printf("wolfSSL_read error");

        recvline[n] = '\0';
        fputs(recvline, stdout);
    }
}
#else
void str_cli(FILE *fp, int sockfd)
{
    char    sendline[MAXLINE], recvline[MAXLINE];

    while(fgets(sendline, MAXLINE, fp) != NULL)
    {
        printf("sendline : %s\n",sendline);
        if (send(sockfd,sendline,strlen(sendline),0) < 0)
        {
            perror("Send");
            exit(-1);
        }
        if (recv(sockfd,recvline,MAXLINE,0) < 0 )
        {
            perror("recv");
            exit(-1);
        }
        printf("recvline : %s\n",recvline);
        fputs(recvline, stdout);
    }
}
#endif

int main(int argc, char **argv)
{
    int sockfd;
    struct sockaddr_in  servaddr;

    if (argc != 2)
    {
        perror("usage: tcpcli <IPaddress>");
        exit(-1);
    }


    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("sockfd");
        exit(-1);
    }
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERV_PORT);
    if (inet_pton(AF_INET, argv[1], &servaddr.sin_addr) < 0)
    {
        perror("inet_pton");    
        exit(-1);       
    }

    if (connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0)
    {
        perror("connect");
        exit(-1);       
    }

#ifdef OPEN_SSL
    SSL_CTX* ctx;
    SSL_library_init();
    SSL_load_error_strings();
    ctx = SSL_CTX_new (SSLv23_client_method());
    if((ctx) == NULL)
    {
        printf("Fun:%s\tSSL_CTX ERROR\n", __FUNCTION__);
        return -1;
    }
    printf("tim add SSL_CTX_set_verify test############\n");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);//fix SSL_connect fail
    SSL *ssl;

    if( (ssl = SSL_new(ctx)) == NULL) {
        fprintf(stderr, "wolfSSL_new error.\n");
        exit(EXIT_FAILURE);
    }

    SSL_set_fd(ssl, sockfd);
    int ssl_ret;
    int fgCycleFlag = 1;
    while(fgCycleFlag )
    {
        ssl_ret = SSL_connect(ssl);
        switch(SSL_get_error(ssl, ssl_ret))//这里出错
        {
            case SSL_ERROR_NONE:
                printf("Fun:%s\tSSL_ERROR_NONE,ssl_ret = %d\n", __FUNCTION__,ssl_ret);
                fgCycleFlag = 0;
                usleep(100000);
                break;
            case SSL_ERROR_WANT_WRITE:
                printf("Fun:%s\tSSL_ERROR_WANT_WRITE,ssl_ret = %d\n", __FUNCTION__,ssl_ret);
                usleep(100000);
                break;
            case SSL_ERROR_WANT_READ:
                printf("Fun:%s\tSSL_ERROR_WANT_READ,ssl_ret = %d\n", __FUNCTION__,ssl_ret);
                usleep(100000);
                break;
            default:    
                printf("SSL_connect:%s\n", __FUNCTION__);
                return -1;
        }   
    }
    str_cli_ssl(stdin, ssl);        /* do it all */
//程序不会走这里，缺少回收资源的机制，实际运用中需要及时对资源进行释放！！
    if(ssl != NULL)
    {
        printf("Fun:%s Close SSL\n", __FUNCTION__);
        SSL_shutdown (ssl); 
        SSL_free (ssl);    /* Free SSL object */
        ssl = NULL;
    }
    if(ctx != NULL)
    {
        printf("Fun:%s Close SSL\n", __FUNCTION__);
        SSL_CTX_free (ctx); 
        ctx = NULL;
    }
#else
/
    str_cli(stdin, sockfd);
#endif
    exit(1);
}

