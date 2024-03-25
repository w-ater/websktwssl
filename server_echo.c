//server_echo.c
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/in.h>

#include <signal.h>   //信号
#include <wolfssl/openssl/ssl.h>  //wolfssl转openssl的兼容层

#define SERV_PORT        9877   
#define LISTENQ     1024
#define MAXLINE     4096

#define OPEN_SSL

static int cleanup;     /* To handle shutdown */
void sig_handler(const int sig)
{
    printf("\nSIGINT handled.\n");
    cleanup = 1;
    return;
}


#ifdef OPEN_SSL
void str_echo_ssl(WOLFSSL* ssl)
{
    int         n;
    char        buf[MAXLINE];
    while ( (n = SSL_read(ssl, buf, MAXLINE)) > 0) {
        if(SSL_write(ssl, buf, n) != n) {
            printf("wolfSSL_write failed");
        }
    }
    if( n < 0 )
        printf("wolfSSL_read error = %d\n", wolfSSL_get_error(ssl,n));

    else if( n == 0 )
        printf("The peer has closed the connection.\n");
}
#else
void str_echo(int sockfd)
{
    char buff[MAXLINE];
    int length=0;
    printf("server begin recv\n");
    while(length=recv(sockfd,buff,MAXLINE,0)) //这里是分包接收，每次接收4096个字节
    {
        if(length<0)
        {
            perror("recv");
            exit(-1);
        }
        printf("server send\n");
        if (send(sockfd,buff,MAXLINE,0) < 0)
        {
            perror("Send");
            exit(-1);
        }
        bzero(buff, sizeof(buff));
    }
}
#endif
int main(int argc, char **argv)
{
    int                 listenfd, connfd,fpid;
    pid_t               childpid;
    socklen_t           clilen;
    struct sockaddr_in  cliaddr, servaddr;
    struct sigaction    act, oact;      /* structures for signal handling */    
    act.sa_handler = sig_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGINT, &act, &oact);

#ifdef OPEN_SSL
    wolfSSL_Init();      /* Initialize wolfSSL */
    WOLFSSL_CTX* ctx;

    /* Create and initialize WOLFSSL_CTX structure */
    if ( (ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method())) == NULL){
        fprintf(stderr, "wolfSSL_CTX_new error.\n");
        exit(EXIT_FAILURE);
    }

    /* Load CA certificates into WOLFSSL_CTX */
    /*if (wolfSSL_CTX_load_verify_locations(ctx,"./mycerts/ca-cert.pem",0) !=
            SSL_SUCCESS) {
        fprintf(stderr, "Error loading ../certs/ca-cert.pem, "
                "please check the file.\n");
        exit(EXIT_FAILURE);
    }*/

    /* Load server certificate into WOLFSSL_CTX */
    if (wolfSSL_CTX_use_certificate_file(ctx,"./mycerts/server-cert.pem",
                SSL_FILETYPE_PEM) != SSL_SUCCESS) {
       fprintf(stderr, "Error loading ../certs/server-cert.pem, "
               "please check the file.\n");
       exit(EXIT_FAILURE);
    }

    /* Load server key into WOLFSSL_CTX */
    if (wolfSSL_CTX_use_PrivateKey_file(ctx,"./mycerts/server-key.pem",
                SSL_FILETYPE_PEM) != SSL_SUCCESS) {
       fprintf(stderr, "Error loading ../certs/server-key.pem, "
               "please check the file.\n");
       exit(EXIT_FAILURE);
    }   
#endif

    //建立socket连接
    if ((listenfd = socket(AF_INET,SOCK_STREAM,0)) < 0)
    {
        perror("socket");
        exit(1);
    }
    printf("create socket success!\n");

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family      = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port        = htons(SERV_PORT);

    // 设置套接字选项避免地址使用错误，为了允许地址重用，我设置整型参数（on）为 1 （不然，可以设为 0 来禁止地址重用）
    int on=1;  
    if((setsockopt(listenfd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)))<0)  
    {  
        perror("setsockopt failed");  
        exit(-1);  
    }

    if(bind(listenfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0)
    {
        perror("bind");
        exit(-1);
    }
    printf("Bind success!\n");
    if(listen(listenfd, LISTENQ) == -1)
    {
        perror("listen");
        exit(-1);
    }

    while(cleanup != 1)
    {
        clilen = sizeof(cliaddr);
        printf("begin accept!\n");
        if ((connfd = accept(listenfd, (struct sockaddr *) &cliaddr, &clilen)) < 0)
        {
            perror("accept");
            exit(-1);           
        }
        //
#ifdef OPEN_SSL
        WOLFSSL* ssl;
        /* Create WOLFSSL Object */
        if( (ssl = wolfSSL_new(ctx)) == NULL) {
           printf("wolfSSL_new error.\n");
           exit(-1);
        }

        wolfSSL_set_fd(ssl, connfd);
        str_echo_ssl(ssl);              /* process the request */
        wolfSSL_free(ssl);          /* Free WOLFSSL object */
#else
        /
        printf("begin fork!\n");
        fpid=fork();   
        if (fpid < 0)   
        {
            perror("fork");
            exit(-1);
        } 
        else if (fpid == 0) //child process
        {  
            close(listenfd);    // close listening socket
            str_echo(connfd);   // process the request
            exit(0);
        }
#endif
        close(connfd);          // parent closes connected socket
    }
#ifdef OPEN_SSL
    wolfSSL_CTX_free(ctx);          /* Free WOLFSSL_CTX */
    printf("wolfSSL_CTX freed\n");
    wolfSSL_Cleanup();              /* Free wolfSSL */
    printf("wolfSSL freed\n");
#endif
    exit(1);
}


