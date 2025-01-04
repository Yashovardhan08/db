#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <vector>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <poll.h>
#include <arpa/inet.h>

#define ERROR -1

const int MAX_MSG = 4096;

enum {
    STATE_REQ = 0,// reading the request
    STATE_RES = 1,// sending the response
    STATE_END = 2,// close the fd
};

struct Conn {
    int fd = -1;
    unsigned short state = 0;
    // read buffer
    size_t rBuffSize = 0;
    uint8_t rBuff[4+MAX_MSG];
    // write buffer
    size_t wBuffSize = 0;
    size_t wBuffSent = 0;
    uint8_t wBuff[4+MAX_MSG];
};

void process_response(Conn *conn);

    void fd_set_nb(int fd)
{
    int currFDOptions = fcntl(fd,F_GETFL,0);
    if(currFDOptions<0){
        printf("ERROR Setting FD to Non Blocking!\n");
        return;
    }
    currFDOptions |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL,currFDOptions) < 0){
        printf("ERROR Setting FD to Non Blocking!\n");
    }
}

void accept_new_connection(std::vector<Conn*> & fd2Conn,int serverSocket){
    // accept
    sockaddr_in clientAddress = {};
    socklen_t clientAddrSize = sizeof(clientAddress);
    int clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientAddrSize);
    if (clientSocket < 0){
        printf("ERROR Accepting new client connection!\n");
    }
    fd_set_nb(clientSocket);
    if (clientSocket > fd2Conn.size())
    {
        fd2Conn.resize(clientSocket+1);
    }
    Conn * conn = (struct Conn *)malloc(sizeof(struct Conn));
    conn->fd = clientSocket;
    conn->state = STATE_REQ;
    conn->rBuffSize = 0;
    conn->wBuffSize = 0;
    conn->wBuffSent = 0;

    fd2Conn[clientSocket] = conn;
}

static bool try_one_request(Conn * conn){
    if(conn->rBuffSize<4)return false;// not enough space in buffer

    uint32_t len = 0;
    memcpy(&len, &conn->rBuff[0], (int)4);
    if(len>MAX_MSG){// length too long to hold in the buffer
        printf("ERROR Excess data to read!\n");
        conn->state = STATE_END;
        return false;
    }
    if(4+len> conn->rBuffSize){
        // Not enough data in buffer, try again in next iteration
        return false;
    }
    printf("Client says: %.*s\n",len,&conn->rBuff[4]);
    memcpy(&conn->wBuff[0], &len, 4);
    memcpy(&conn->wBuff[4], &conn->rBuff[4], len);
    conn->wBuffSize = 4 + len;

    size_t remaining = conn->rBuffSize - 4 - len;
    if(remaining){
        memmove(conn->rBuff,&conn->rBuff[4+len],remaining);
    }
    conn->rBuffSize = remaining;
    conn->state=STATE_RES;
    process_response(conn);

    return (conn->state == STATE_REQ);
}

bool try_fill_buffer(Conn* conn){
    assert(conn->rBuffSize< sizeof(conn->rBuff));
    ssize_t rv = 0;
    do {
        size_t cap = sizeof(conn->rBuff) - conn->rBuffSize;
        rv = read(conn->fd,&conn->rBuff[conn->rBuffSize],cap);
    }
    while(rv<0 && errno == EINTR);// EINTR: our call was interrupted by a signal 

    if(rv<0 && errno == EAGAIN){// EAGAIN: resource not ready, try again
        // not ready
        return false;
    }
    if(rv<0){
        printf("ERROR Read Error!\n");
        conn->state = STATE_END;
        return false;
    }
    if(rv==0){
        printf("Recieved EOF while trying to read!\n");
        conn->state = STATE_END;
        return false;
    }

    conn->rBuffSize+=(size_t)rv;
    assert(conn->rBuffSize <= sizeof(conn->rBuff));

    while(try_one_request(conn)){}
    return (conn->state == STATE_REQ);
}

static bool try_flush_buffer(Conn *conn)
{
    ssize_t rv = 0;
    do
    {
        size_t remain = conn->wBuffSize - conn->wBuffSent;
        rv = write(conn->fd, &conn->wBuff[conn->wBuffSent], remain);
    } while (rv < 0 && errno == EINTR);
    if (rv < 0 && errno == EAGAIN)
    {
        // got EAGAIN, stop.
        return false;
    }
    if (rv < 0)
    {
        printf("write() error\n");
        conn->state = STATE_END;
        return false;
    }
    conn->wBuffSent += (size_t)rv;
    assert(conn->wBuffSent <= conn->wBuffSize);
    if (conn->wBuffSent == conn->wBuffSize)
    {
        // response was fully sent, change state back
        conn->state = STATE_REQ;
        conn->wBuffSent = 0;
        conn->wBuffSize = 0;
        return false;
    }
    // still got some data in wbuf, could try to write again
    return true;
}

void process_request(Conn* conn){
    while(try_fill_buffer(conn)){}
}

void process_response(Conn* conn){
    while(try_flush_buffer(conn)){}
}

void process_connection(Conn* conn){
    if(conn->state == STATE_REQ){
        process_request(conn);
    }
    else if(conn->state == STATE_RES){
        process_response(conn);
    }
    else {
        printf("ERROR Illegal connection state!\n");
    }
}

int32_t read_all(int socketFD, char *buf, int32_t len)
{
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

int main(int argc, char *argv[]){
    // create socket
    int serverSocket = socket(AF_INET,SOCK_STREAM,0);
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(6969);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    // bind 
    bind(serverSocket,(struct sockaddr*)&serverAddress, sizeof(serverAddress));

    // listen
    listen(serverSocket,3);

    // map of all connections with key as the socket fd
    std::vector<Conn* > fd2Conn;

    // set server socket to non blocking
    fd_set_nb(serverSocket);

    std::vector<struct pollfd> poll_args;
    while(true){
        poll_args.clear();

        // server fd is put in first position
        struct pollfd serverFd = {serverSocket,POLLIN,0};
        poll_args.push_back(serverFd);

        // set the poll args 
        for(Conn* conn: fd2Conn){
            if(!conn)continue;

            struct pollfd pfd = {};
            pfd.fd = conn->fd;
            pfd.events = (conn->state == STATE_REQ)?POLLIN:POLLOUT;
            pfd.events |= POLLERR;
            poll_args.push_back(pfd);
        }

        // poll for active fd
        int rv = poll(poll_args.data(),(nfds_t)poll_args.size(),100);

        if(rv<0){
            printf("ERROR Polling all the poll args!\n");
            return 0;
        }

        // process active connections
        for(int i=1;i<poll_args.size();++i){
            struct pollfd pfd = poll_args[i];
            if(pfd.revents){
                Conn* conn = fd2Conn[pfd.fd];
                // connection io
                process_connection(conn);
                if(conn->state == STATE_END){
                    
                    fd2Conn[pfd.fd] = NULL;
                    close(conn->fd);
                    free(conn);
                }
            }
        }

        if(poll_args[0].revents){
            accept_new_connection(fd2Conn,serverSocket);
        }
    }
    close(serverSocket);
    return 0;
}