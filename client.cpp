#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <vector>
using namespace std;

const int MAX_MSG = 4096;

#define ERROR -1


static void msg(const char *msg) {
    fprintf(stderr, "%s\n", msg);
}

static void die(const char *msg) {
    int err = errno;
    fprintf(stderr, "[%d] %s\n", err, msg);
    abort();
}


int32_t read_all(int socketFD,uint8_t* buf,size_t len){
    while(len>0){
        // printf("waiting to read\n");        
        ssize_t readLen = read(socketFD,buf,len);
        if(readLen<=0 || readLen>len)return ERROR;
        len-=readLen;
        buf+=len;
    }
    return 0;
}

int32_t write_all(int socketFD,const uint8_t *buf,size_t len) {
    while(len>0){
        // printf("waiting to write\n");
        ssize_t writtenLen = write(socketFD,buf,len);
        if(writtenLen<=0 || writtenLen>len)return ERROR;

        // printf("wrote : %d\n",writtenLen);
        len-=writtenLen;
        buf+=writtenLen;
    }
    return 0;
}

static void buf_append(vector<uint8_t> &buf, const uint8_t *data, size_t len) {
    buf.insert(buf.end(), data, data + len);
}

static int32_t send_req(int fd,const uint8_t *text, size_t len){
    if(len>MAX_MSG)return -1;

    vector<uint8_t> buf;
    buf_append(buf,(const uint8_t*)&len,4);
    buf_append(buf,text,len);
    return write_all(fd, buf.data(),buf.size());
}


static int32_t read_res(int fd) {
    // 4 bytes header
    vector<uint8_t> rbuf;
    rbuf.resize(4);
    errno = 0;
    int32_t err = read_all(fd, &rbuf[0], 4);
    if (err) {
        if (errno == 0) {
            msg("EOF");
        } else {
            msg("read() error");
        }
        return err;
    }

    uint32_t len = 0;
    memcpy(&len, rbuf.data(), 4);  // assume little endian
    if (len > MAX_MSG) {
        msg("too long");
        return -1;
    }

    // reply body
    rbuf.resize(4 + len);
    err = read_all(fd, &rbuf[4], len);
    if (err) {
        msg("read() error");
        return err;
    }

    // do something
    printf("len:%u data:%.*s\n", len, len < 100 ? len : 100, &rbuf[4]);
    return 0;
}

int main(int argc, char *argv[]){

    // create socket
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(6969);
    serverAddress.sin_addr.s_addr = ntohl(INADDR_LOOPBACK);

    // bind 
    connect(clientSocket,(struct sockaddr*)&serverAddress,sizeof(serverAddress));
    
    vector<string> query_list = {
        "hello1", "hello2", "hello3",
        // a large message requires multiple event loop iterations
        string(MAX_MSG, 'z'),
        "hello5",
    };
    for (const std::string &s : query_list) {
        int32_t err = send_req(clientSocket, (uint8_t *)s.data(), s.size());
        if (err) {
            goto L_DONE;
        }
    }
    for (size_t i = 0; i < query_list.size(); ++i) {
        int32_t err = read_res(clientSocket);
        if (err) {
            goto L_DONE;
        }
    }

L_DONE:
    close(clientSocket);
    return 0;

}