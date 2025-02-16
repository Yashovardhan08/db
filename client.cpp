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
        ssize_t readLen = read(socketFD,buf,len);
        if(readLen<=0 || readLen>len)return ERROR;
        len-=readLen;
        buf+=readLen;
    }
    *buf = '\0';
    return 0;
}

int32_t write_all(int socketFD,const uint8_t *buf,size_t len) {
    while(len>0){
        ssize_t writtenLen = write(socketFD,buf,len);
        if(writtenLen<=0 || writtenLen>len)return ERROR;
        len-=writtenLen;
        buf+=writtenLen;
    }
    return 0;
}

static void buf_append(vector<uint8_t> &buf, const uint8_t *data, size_t len) {
    buf.insert(buf.end(), data, data + len);
}

static int32_t send_req(int fd, const std::vector<std::string> &cmd) {
    char wbuf[4 +MAX_MSG];
    uint32_t n = 0;
    for(int i=0;i<cmd.size();++i)n+=cmd[i].size()+4;
    memcpy(&wbuf[0], &n, 4);
    size_t cur = 4;
    for (const std::string &s : cmd) {
        uint32_t p = (uint32_t)s.size();
        memcpy(&wbuf[cur], &p, 4);
        memcpy(&wbuf[cur + 4], s.data(), s.size());
        cur += 4 + s.size();
    }
    return write_all(fd,(const uint8_t *) wbuf, cur);
}

static int32_t read_res(int fd) {
    // 4 bytes header
    uint8_t rbuf[MAX_MSG+8];
    errno = 0;
    int32_t err = read_all(fd, rbuf, 8);
    if (err) {
        if (errno == 0) {
            msg("EOF");
        } else {
            msg("read() error");
        }
        return err;
    }

    uint32_t responseLen = 0;
    uint32_t status = 0;
    memcpy(&responseLen, rbuf, 4);  // assume little endian
    memcpy(&status, rbuf+4, 4);  // assume little endian

    if (responseLen > MAX_MSG) {
        msg("too long");
        return -1;
    }
    cout<<"RESPONSE STATUS:"<<status<<endl;

    if(responseLen>0){
        // reply body
        err = read_all(fd, rbuf+8, responseLen);
        if (err) {
            msg("read() error");
            return err;
        }
        // do something
        cout<<"RESPONSE : "<<rbuf+8<<endl;
        // printf("len:%u data:%.*s\n", responseLen, rbuf+8);
    }
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
    

    // query user for commands
    vector<string> commands;
    commands.push_back("set");
    commands.push_back("yashovardhan");
    commands.push_back("2001");
    int32_t err = send_req(clientSocket,commands);
    if(err){
        goto L_DONE;
    }
    err = read_res(clientSocket);
    if(err){
        goto L_DONE;
    }

    commands.clear();
    commands.push_back("get");
    commands.push_back("yashovardhan");
    err = send_req(clientSocket,commands);
    if(err){
        goto L_DONE;
    }
    err = read_res(clientSocket);
    if(err){
        goto L_DONE;
    }

    commands.clear();
    commands.push_back("del");
    commands.push_back("yashovardhan");
    err = send_req(clientSocket,commands);
    if(err){
        goto L_DONE;
    }
    err = read_res(clientSocket);
    if(err){
        goto L_DONE;
    }

    commands.clear();
    commands.push_back("get");
    commands.push_back("yashovardhan");
    err = send_req(clientSocket,commands);
    if(err){
        goto L_DONE;
    }
    err = read_res(clientSocket);
    if(err){
        goto L_DONE;
    }

    commands.clear();
    commands.push_back("set");
    commands.push_back("shriya");
    commands.push_back("2006");
    err = send_req(clientSocket,commands);
    if(err){
        goto L_DONE;
    }
    err = read_res(clientSocket);
    if(err){
        goto L_DONE;
    }


    commands.clear();
    commands.push_back("get");
    commands.push_back("shriya");
    err = send_req(clientSocket,commands);
    if(err){
        goto L_DONE;
    }
    err = read_res(clientSocket);
    if(err){
        goto L_DONE;
    }

L_DONE:
    close(clientSocket);
    return 0;

}