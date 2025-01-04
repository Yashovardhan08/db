#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <iostream>
#include <cstring>

const int MAX_MSG = 4096;

#define ERROR -1


int32_t read_all(int socketFD,char* buf,int32_t len){
    while(len>0){
        ssize_t readLen = read(socketFD,buf,len);
        
        if(readLen<=0 || readLen>len)return ERROR;
        len-=readLen;
        buf+=len;
    }
    return 0;
}

int32_t write_all(int socketFD, char *buf, int32_t len) {
    while(len>0){
        ssize_t writtenLen = write(socketFD,buf,len);
        if(writtenLen<=0 || writtenLen>len)return ERROR;

        len-=writtenLen;
        buf+=writtenLen;
    }
    return 0;
}

int32_t func(int clientFD)
{
    char buf[] = "Message from client!!";
    char sendBuf[4 + MAX_MSG + 1];
    int32_t sendLen = strlen(buf);
    sendBuf[4 + sendLen] = '\0';
    memcpy(sendBuf, &sendLen, 4);
    memcpy(&sendBuf[4], buf, sendLen);

    return write_all(clientFD, sendBuf, sendLen+4);
}

static int32_t query(int fd){
    func(fd);

    char readBuf[4+MAX_MSG+1];
    read_all(fd,readBuf,4);
    int readLen;
    memcpy(&readLen,readBuf,4);

    int err = read_all(fd,&readBuf[4],readLen);
    printf("Server says: %s\n",&readBuf[4]);
    return err;
}

int main(int argc, char *argv[]){

    // create socket
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in clientAddress;
    clientAddress.sin_family = AF_INET;
    clientAddress.sin_port = htons(9696);
    clientAddress.sin_addr.s_addr = INADDR_ANY;
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(6969);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    // bind 
    connect(clientSocket,(struct sockaddr*)&serverAddress,sizeof(serverAddress));
    
    for(int i=0;i<3;++i){
        query(clientSocket);
    }
    func(clientSocket);
    close(clientSocket);

    return 0;
}