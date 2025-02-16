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
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <map>

#define ERROR -1

const int MAX_MSG = 4096;
const int MAX_CONNECTIONS = 1000;
const int MAX_COMMANDS = 500;
enum {
    STATE_REQ = 0,// reading the request
    STATE_RES = 1,// sending the response
    STATE_END = 2,// close the fd
};

static std::map<std::string, std::string> g_data;

struct Conn {
    int fd = -1;
    unsigned short state = 0;
    bool want_close=false;
    // read buffer
    size_t rBuffSize = 0;
    uint8_t rBuff[4+MAX_MSG];
    // write buffer
    size_t wBuffSize = 0;
    size_t wBuffSent = 0;
    uint8_t wBuff[4+MAX_MSG];
};

// struct Response{
//     uint32_t status;
//     std::vector<uint8_t> data;
// };

void process_response(Conn *conn);
void process_connection(Conn* conn);
static void process_commands(Conn *conn,std::vector<std::string> &commands);
static int32_t parse_commands(const uint8_t *startPtr,size_t size,std::vector<std::string> &cmds);
static bool parse_string(const uint8_t *&ptr,const uint8_t * endPtr,const uint32_t len, std::string & command);
static bool parse_uint32(const uint8_t *&ptr,const uint8_t * endPtr,uint32_t & len);


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

void accept_new_connection(std::vector<Conn*> & fd2Conn,int serverSocket,int epFd){
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

    static struct epoll_event ev;
    ev.events = EPOLLIN |EPOLLOUT;
    ev.data.fd = clientSocket;
    int res = epoll_ctl(epFd, EPOLL_CTL_ADD, clientSocket, &ev);

    if(res<0){
        printf("ERROR adding new client fd through epoll_ctl with error %d \n",res);
    }

    fd2Conn[clientSocket] = conn;
}

static bool try_one_request(Conn * conn){
    if(conn->rBuffSize<4)return false;// not enough data in buffer

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

    // Processing all the requests
    std::vector<std::string> commands;
    if(parse_commands(&conn->rBuff[4],len,commands)<0){
        conn->want_close=true;
        conn->state=STATE_END;
        return false;
    }
    process_commands(conn,commands);
    size_t remaining = conn->rBuffSize - 4 - len;
    if(remaining){
        memmove(conn->rBuff,&conn->rBuff[4+len],remaining);
    }
    conn->rBuffSize = remaining;
    conn->state=STATE_RES;
    process_response(conn);
    return (conn->state == STATE_REQ);
}

static void process_commands(Conn *conn,std::vector<std::string> &commands){
    uint32_t status=0;
    std::vector<uint8_t> result;
    if(commands.size() == 2){
        if(commands[0]=="get"){
            auto it = g_data.find(commands[1]);
            if(it == g_data.end()){
                // error status not found
                status=-1;
            }
            else {
                const std::string &val = it->second;
                result.assign(val.begin(), val.end());
            }
        }
        else if(commands[0]=="del"){
            // status 0
            g_data.erase(commands[1]);
        }
        else {
            //error status command not found
            status = -1;
        }
    }
    else if(commands.size()==3 && commands[0] == "set"){
        g_data[commands[1]].swap(commands[2]);
    }
    else {
        // error status command not found
        status=-1;
    }
    uint32_t responseLength=result.size();
    memcpy(&conn->wBuff[0],&responseLength,4);
    memcpy(&conn->wBuff[4],&status,4);
    conn->wBuffSize  = 8 + responseLength;
    if(result.size()>0)memcpy(&conn->wBuff[8],result.data(),result.size());
}

static int32_t parse_commands(const uint8_t *startPtr,size_t size,std::vector<std::string> &cmds){
    const uint8_t *endPtr = startPtr+size;
    while(startPtr<endPtr){
        uint32_t len = 0;
        if(!parse_uint32(startPtr,endPtr,len)){
            return -1;
        }
        std::string command;
        if(!parse_string(startPtr,endPtr,len,command)){
            return -1;
        }
        cmds.push_back(command);
    }
    return 0;
}

static bool parse_uint32(const uint8_t *&ptr,const uint8_t * endPtr,uint32_t & len){
    if(ptr+4>endPtr){
        // Corrupted data
        return false;
    }
    memcpy(&len,ptr,(int)4);
    ptr+=4;
    return true;
}

static bool parse_string(const uint8_t *&ptr,const uint8_t * endPtr,const uint32_t len, std::string & command){
    if(ptr+len>endPtr){
        // Corrupted data
        return false;
    }
    command.assign(ptr,ptr+len);
    ptr+=len;
    return true;
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
        printf("WARNING resource not ready to read!\n");
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
        printf("WARNING resource not ready to write!\n");
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
    serverAddress.sin_addr.s_addr = ntohl(0);

    // bind 
    bind(serverSocket,(struct sockaddr*)&serverAddress, sizeof(serverAddress));

    // listen
    listen(serverSocket,MAX_CONNECTIONS);

    // map of all connections with key as the socket fd
    std::vector<Conn* > fd2Conn;

    // set server socket to non blocking
    fd_set_nb(serverSocket);

    // create epoll fd
    int epFd = epoll_create1(0);
    struct epoll_event serverEvent;
    serverEvent.data.fd = serverSocket;
    serverEvent.events = EPOLLIN | EPOLLOUT ; 
    int rv = epoll_ctl(epFd,EPOLL_CTL_ADD, serverSocket,&serverEvent);
    while(true){
        // wait for something to do...
        struct epoll_event events[MAX_CONNECTIONS];
        int nfds = epoll_wait(epFd, events,
                              MAX_CONNECTIONS,
                              -1);
        if (nfds == -1){
            printf("Error in epoll_wait!\n");
            break;
        }
        // for each ready socket
        for (int i = 0; i < nfds; i++)
        {
            int fd = events[i].data.fd;
            if(fd == serverSocket){
                accept_new_connection(fd2Conn, serverSocket, epFd);
            }
            else {
                Conn *conn = fd2Conn[fd];
                // connection io
                process_connection(conn);
                if (conn->state == STATE_END)
                {
                    fd2Conn[fd] = NULL;
                    close(conn->fd);
                    free(conn);
                }
            }
            
        }
    }
    close(serverSocket);
    return 0;
}