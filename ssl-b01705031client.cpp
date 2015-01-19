#include <iostream>
#include <string>
#include <cstring>
#include <string.h>
#include <cstdlib>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <regex.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sstream>
#include <openssl/ssl.h>
#include <openssl/err.h>
using namespace std;

SSL_CTX* InitServerCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;
 
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = SSLv3_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}
 

SSL_CTX* InitCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;
 
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = SSLv3_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("No certificates.\n");
}

void * sendwhilelis(void * arg)
{
    char buf [1000];
    //int* fd;
    //fd=(int *) arg;
    //int sockfd=*fd;
    
    SSL* ssl;
    ssl=(SSL *)arg;
    string s;
    bzero(buf,1024);
    while(cin>>s)
    {
        
        strcpy(buf,s.c_str());
        
        
       SSL_write(ssl,buf,strlen(buf));
        //cout<<buf;
        bzero(buf,1024);
        if(s=="Exit")
            break;
    }
   // return 0;
}

void * Listen(void * arg)
{
    struct sockaddr_in server_addr,clien_addr;
    int listenfd,connectfd;
    socklen_t length;
    char test[1024];
    bzero(test,1023);
    int* portno;
    portno= (int*)arg;
    int pt=*portno;
    
    SSL_CTX *ctx;
    SSL_library_init();
    ctx = InitServerCTX();
    LoadCertificates(ctx,"mycert.pem","mykey.pem");
    
    listenfd=socket(AF_INET,SOCK_STREAM,0);
    bzero((char*)&server_addr, sizeof(server_addr));
    //int portno;
    //cin>>portno;
    server_addr.sin_family=AF_INET;
    server_addr.sin_addr.s_addr=INADDR_ANY;
    server_addr.sin_port=htons(pt+1);
    //cout<<pt;
    //bind(listenfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    //int r;
    if(::bind(listenfd, (struct sockaddr *)&server_addr, sizeof(server_addr))==0)
    {
        cout<<"Bind complete!"<<endl;
        
    }
    
    listen(listenfd,5);
    //cout<<"Listening"<<endl;
    length=sizeof (clien_addr);
    
    
    if((connectfd=accept(listenfd,(struct sockaddr *)&clien_addr,&length)))
    {
        //cout<<"fuck";
        if(connectfd==0)
        {
            cout<<"good"<<endl;
            
        }
        SSL *ssl;
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl,connectfd);
        if(SSL_accept(ssl)==-1)
        {
        	cout<<"Error!"<<endl;
        }
        else
        {
        	ShowCerts(ssl);
        }
        //cout<<connectfd<<endl;
        //bool loop=false;
        bzero(test,1024);
        pthread_t thread;
        pthread_create(&thread,NULL,&sendwhilelis,ssl);
        while(SSL_read(ssl,test,1024))
        {
            string resultt;
            resultt.assign(test);
            cout<<"Receive: "<<resultt<<endl;
            
            if (resultt=="Exit")
            {
                SSL_CTX_free(ctx);
                //close(sockfd);
                break;
            }
            bzero(test,1024);
            //cout<<"dd";
            
        }
       // pthread_
    }
    //cout<<"dd";
    return 0;
}

void * liswhilesend(void * arg)
{
    char buf [1024];
    //int* fd;
    //fd=(int *)arg;
    //int sockfd=*fd;
    SSL* ssl;
    ssl=(SSL *)arg;
    while(SSL_read(ssl,buf,1024))
    {
        string resultt;
        resultt.assign(buf);
        cout<<"Receive: "<<resultt<<endl;
        
        if (resultt=="Exit")
        {
            break;
        }
        bzero(buf,1024);
        //cout<<"dd";
    }
    return 0;
}


void chatwithserv(SSL *ssl,string s,char * buffer)
{
    strcpy(buffer,s.c_str());
    SSL_write(ssl,buffer,strlen(buffer));
    
    /* Receive message from the server and print to screen */
    bzero(buffer, 1024);
    SSL_read(ssl,buffer,1023);
    
    string result;
    result.assign(buffer);
    
    cout<<result<<endl<<endl;
    
    if(result=="Bye\r\n")  //if receive Bye then end the connection
    {
        //break;
    }
    
};

void sendmsg(SSL* ssl,string s,char * buffer)
{
    strcpy(buffer,s.c_str());
    
    
    SSL_write(ssl,buffer,strlen(buffer));
    //cout<<buffer;
    bzero(buffer,1024);
    
    /* Receive message from the server and print to screen */
    //bzero(buffer, 1024);
    //read(sockfd,buffer,1023);
    
    //string result;
    //result.assign(buffer);
    
    //cout<<result<<endl<<endl;
    
    //cout<< "afdsadfkjajdksfl;ads;f";
};

int getlocalhost(int sockfd,sockaddr_in serv)
{
    int local_port;
    socklen_t addrlen = sizeof(serv);
    if(getsockname(sockfd, (struct sockaddr *)&serv, &addrlen) == 0 &&serv.sin_family == AF_INET &&addrlen == sizeof(serv))
    {
        local_port = ntohs(serv.sin_port);
    }
    //cout<<local_port<<"here"<<endl;
    return local_port;
    
}


void connecting(int port)
{
    int sockfd;
    struct sockaddr_in con;
    struct hostent *conn;
    char sendbuf [1024];
    char readbuf [1024];
    SSL_CTX *ctx;
    SSL_library_init();
    ctx = InitCTX();
    LoadCertificates(ctx,"mycert.pem","mykey.pem");
    //int * portno;
    //portno=(int *)arg;
    //int port=*portno;
    
    string t="localhost";
    
    char * tt;
   //  tt=(char * )t;
    
    sockfd= socket(AF_INET,SOCK_STREAM,0);
    bzero(&con,sizeof(con));
    
    conn=gethostbyname(t.c_str());
    if(conn==NULL){
        cout<<"Fail"<<endl;
    }
    con.sin_family=AF_INET;
    bcopy((char *)conn->h_addr,(char *)&con.sin_addr.s_addr,conn->h_length);
    con.sin_port = htons(port);

    SSL* ssl = SSL_new(ctx); 
    SSL_set_fd(ssl, sockfd);
    
    if(connect(sockfd, (struct sockaddr*)&con, sizeof(con))<0)
        
    {
        cout<<"Connection Failed!"	<<endl;
        
    }
    else
        cout<<"Connection Success!"<<endl;
    string s;
    
    //cout<<"ssssssssssssss!"<<endl;
	

    if(SSL_connect(ssl)==-1)
    	cout<<"Fail"<<endl;
    else
    {
    	cout<<"Connected with"<<SSL_get_cipher(ssl)<<" encryption"<<endl;
    	ShowCerts(ssl);

	    pthread_t thread;
	    pthread_create(&thread,NULL,&liswhilesend,ssl);
	    while(cin>>s)
	    {
	        //cout<<s;
	        sendmsg(ssl,s,sendbuf);
	        //cout<<"send!"<<endl;
	        
	        if(s=="Exit")
	         {
	         	SSL_CTX_free(ctx);
	         	close(sockfd);
	            	break;
	        }
	    }
    }
}


int main ()
{
    int sockfd,n/*,listenfd,connfd*/;
    struct sockaddr_in serv/*,server_addr,clien_addr*/;
    struct hostent *server;
    char buffer[1024];
    string tmp,s;
    pthread_t lis;

    SSL_CTX *ctx;
    SSL *ssl;
    SSL_library_init();
	ctx= InitCTX();
	LoadCertificates(ctx, "mycert.pem", "mykey.pem");

    //thread newwww;
    /* create socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    /* initialize value in dest */
    bzero(&serv, sizeof(serv));
    int portnum;
    //cout<<"input port: ";
    //cin>>portnum;
    server=gethostbyname("127.0.0.1");
    if(server==NULL)
    {
        cout<<"NO serv!";
    }
    
    serv.sin_family = AF_INET;
    bcopy((char *)server->h_addr,(char *)&serv.sin_addr.s_addr,server->h_length);
    serv.sin_port = htons(5901);
    
    ssl = SSL_new(ctx); 
    SSL_set_fd(ssl, sockfd);

    /* Connecting to server */
    if(connect(sockfd, (struct sockaddr*)&serv, sizeof(serv))<0)
        
    {
        cout<<"Connection Failed!"	<<endl;
        return 0;
    }
    else
        cout<<"Connection Success!"<<endl;
    
    
   	

    if(SSL_connect(ssl)==-1)
    	cout<<"Fail"<<endl;
    else
    {
    	cout<<"Connected with"<<SSL_get_cipher(ssl)<<" encryption"<<endl;
    	ShowCerts(ssl);
    }	
    //cout<<"thread"<<endl;
	    cout<<"Please enter user name: ";
	    cin>>tmp;
	    s="REGISTER#"+tmp;
	    
	    bzero(buffer,1024);
	    strcpy(buffer,s.c_str());
	    SSL_write(ssl,buffer,1024);
	    bzero(buffer, 1024);
	    SSL_read(ssl,buffer,1023);
	    
	    string result;
	    result.assign(buffer);

	    
	    cout<<result<<endl<<endl;
	    if(result=="210 fail\r\n")
	   	{
	   		cout<<"Register fail"<<endl;
	   		return 0;
	   		close(sockfd);
	   	}
	    s="List";
	    chatwithserv(ssl,s,buffer);
	    
	    while(cin)
	    {
	        string t;
	        cout<<"Do?"<<endl;
	        cin>>t;
	        //cout<<"What to do: ";
	        if(t=="wait")
	        {
	            int pt;
	            cin>>pt;
	            pthread_t thread;
	            pthread_create(&thread,NULL,&Listen,&pt);
	            pthread_join(thread, NULL);
	            
	            
	        }
	        else if(t=="conn")
	        {
	            
	            pthread_t thread;
	            int i;
	            //string t;
	            //cin>>t;
	            cin>>i;
	            connecting(i+1);
	            
	            //cout<<"End chat"<<endl;
	            
	        }
	        else if (t=="Exit")
	        {
	        	chatwithserv(ssl,t,buffer);
	        	break;
	        }
	        else
	        {
	        	chatwithserv(ssl,t,buffer);
	        }
	    }	
	    
	    
	    
    
    
    
    
    
    close(sockfd);
    
    
    
    
    
    //return 0;
}
