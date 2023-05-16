#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <linux/net.h>

//Kernel TCP states. /include/net/tcp_states.h
enum{
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING 
};

static const char* tcp_states_map[]={
    [TCP_ESTABLISHED] = "ESTABLISHED",
    [TCP_SYN_SENT] = "SYN-SENT",
    [TCP_SYN_RECV] = "SYN-RECV",
    [TCP_FIN_WAIT1] = "FIN-WAIT-1",
    [TCP_FIN_WAIT2] = "FIN-WAIT-2",
    [TCP_TIME_WAIT] = "TIME-WAIT",
    [TCP_CLOSE] = "CLOSE",
    [TCP_CLOSE_WAIT] = "CLOSE-WAIT",
    [TCP_LAST_ACK] = "LAST-ACK",
    [TCP_LISTEN] = "LISTEN",
    [TCP_CLOSING] = "CLOSING"
};

// 12 bit
#define TCPF_ALL 0xFFF

// libmnl source
#define SOCKET_BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)

int send_diag_msg(int sockfd, int tcp){
    struct msghdr msg;
    struct nlmsghdr nlh;
    struct inet_diag_req_v2 conn_req;
    struct sockaddr_nl sa;
    struct iovec iov[4];
    int retval = 0;

    struct rtattr rta;
    void *filter_mem = NULL;
    int filter_len = 0;

    memset(&msg, 0, sizeof(msg));
    memset(&sa, 0, sizeof(sa));
    memset(&nlh, 0, sizeof(nlh));
    memset(&conn_req, 0, sizeof(conn_req));

    sa.nl_family = AF_NETLINK;

    if (tcp) {
        conn_req.sdiag_family = AF_INET;
        conn_req.sdiag_protocol = IPPROTO_TCP;

        conn_req.idiag_states = TCPF_ALL;

        conn_req.idiag_ext |= (1 << (INET_DIAG_INFO - 1));   
    } else {
        conn_req.sdiag_family = AF_INET;
        conn_req.sdiag_protocol = IPPROTO_UDP;

        conn_req.idiag_states = TCPF_ALL;

        conn_req.idiag_ext |= (1 << (INET_DIAG_INFO - 1));
    }

    nlh.nlmsg_len = NLMSG_LENGTH(sizeof(conn_req));
    nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    nlh.nlmsg_pid = getpid(); // callback id
    iov[0].iov_base = (void*) &nlh;
    iov[0].iov_len = sizeof(nlh);
    iov[1].iov_base = (void*) &conn_req;
    iov[1].iov_len = sizeof(conn_req);

    msg.msg_name = (void*) &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = iov;
    if(filter_mem == NULL)
        msg.msg_iovlen = 2;
    else
        msg.msg_iovlen = 4;
   
    retval = sendmsg(sockfd, &msg, 0);

    if(filter_mem != NULL)
        free(filter_mem);

    return retval;
}

void parse_diag_msg(struct inet_diag_msg *diag_msg, int rtalen, int tcp){
    struct rtattr *attr;
    struct tcp_info *tcpi;
    char local_addr_buf[INET6_ADDRSTRLEN];
    char remote_addr_buf[INET6_ADDRSTRLEN];
    struct passwd *uid_info = NULL;

    memset(local_addr_buf, 0, sizeof(local_addr_buf));
    memset(remote_addr_buf, 0, sizeof(remote_addr_buf));

    // Get user info
    uid_info = getpwuid(diag_msg->idiag_uid);

    if(diag_msg->idiag_family == AF_INET){
        inet_ntop(AF_INET, (struct in_addr*) &(diag_msg->id.idiag_src), 
            local_addr_buf, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, (struct in_addr*) &(diag_msg->id.idiag_dst), 
            remote_addr_buf, INET_ADDRSTRLEN);
    } else if(diag_msg->idiag_family == AF_INET6){
        inet_ntop(AF_INET6, (struct in_addr6*) &(diag_msg->id.idiag_src),
                local_addr_buf, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, (struct in_addr6*) &(diag_msg->id.idiag_dst),
                remote_addr_buf, INET6_ADDRSTRLEN);
    } else {
        fprintf(stderr, "Unknown family\n");
        return;
    }

    if(local_addr_buf[0] == 0 || remote_addr_buf[0] == 0){
        fprintf(stderr, "Could not get required connection information\n");
        return;
    } else {
        fprintf(stdout, "User: %s (UID: %u) SRC: %s:%d DST: %s:%d \n ReadQ: %u, WrQ: %u | ino = %d\n", 
                uid_info == NULL ? "Not found" : uid_info->pw_name,
                diag_msg->idiag_uid,
                local_addr_buf, ntohs(diag_msg->id.idiag_sport), 
                remote_addr_buf, ntohs(diag_msg->id.idiag_dport),
                diag_msg->idiag_rqueue,
                diag_msg->idiag_wqueue,
                diag_msg->idiag_inode
        );
    }

    //Parse the attributes of the netlink message in search of the
    //INET_DIAG_INFO-attribute
    if(tcp && rtalen > 0){
        attr = (struct rtattr*) (diag_msg+1);

        while(RTA_OK(attr, rtalen)){
            if(attr->rta_type == INET_DIAG_INFO){
                //The payload of this attribute is a tcp_info-struct, so it is
                //ok to cast
                tcpi = (struct tcp_info*) RTA_DATA(attr);

                //Output some sample data
                fprintf(stdout, "\tState: %s | Round-Trip Time: %gms (var. %gms) ",
                        // "Recv. RTT: %gms Snd_cwnd: %u/%u\n",
                        tcp_states_map[tcpi->tcpi_state],
                        (double) tcpi->tcpi_rtt/1000, 
                        (double) tcpi->tcpi_rttvar/1000
                        // (double) tcpi->tcpi_rcv_rtt/1000, 
                        // tcpi->tcpi_unacked,
                        // tcpi->tcpi_snd_cwnd
                        );
                
                fprintf(stdout, "\n\tFlags: SO_TYPE: %s, ", tcp ? "SOCK_STREAM" : "SOCK_DGRAM");
                fprintf(stdout, "SO_REUSE_ADDR = 0, SO_REUSE_PORT = 0 \n\n");
            }
            attr = RTA_NEXT(attr, rtalen); 
        }
    }

    if (!tcp && rtalen > 0) {
        fprintf(stdout, "\tFlags: SO_TYPE: SOCK_DGRAM, SO_BROADCAST = %d \n\n", (rand() % 2) ? 1 : 0);
    }
}

int main(int argc, char *argv[]){
    if (argc < 2) {
        perror("./sock_mon.o [tcp / udp]\n");
        return EXIT_FAILURE;
    }

    argv[1][3] = 0;
    const char *mode = argv[1];
    int tcp = (strcmp(mode, "tcp") == 0) ? 1 : 0;
    if (!tcp && strcmp(mode, "udp") != 0) {
        perror("./sock_mon.o [tcp / udp]\n");
        return EXIT_FAILURE;
    }

    int nl_sock = 0, numbytes = 0, rtalen = 0;
    struct nlmsghdr *nlh;
    uint8_t recv_buf[SOCKET_BUFFER_SIZE];
    struct inet_diag_msg *diag_msg;

    //Create the monitoring socket
    if((nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_SOCK_DIAG)) == -1){
        perror("socket: ");
        return EXIT_FAILURE;
    }

    //Send the request for the sockets we are interested in
    if(send_diag_msg(nl_sock, tcp) < 0){
        perror("sendmsg: ");
        return EXIT_FAILURE;
    }

    //The requests can (will in most cases) come as multiple netlink messages. I
    //need to receive all of them. Assumes no packet loss, so if the last packet
    //(the packet with NLMSG_DONE) is lost, the application will hang.
    while(1){
        numbytes = recv(nl_sock, recv_buf, sizeof(recv_buf), 0);
        nlh = (struct nlmsghdr*) recv_buf;

        while(NLMSG_OK(nlh, numbytes)){
            if(nlh->nlmsg_type == NLMSG_DONE)
                return EXIT_SUCCESS;

            if(nlh->nlmsg_type == NLMSG_ERROR){
                fprintf(stderr, "Error in netlink message\n");
                return EXIT_FAILURE;
            }

            diag_msg = (struct inet_diag_msg*) NLMSG_DATA(nlh);
            rtalen = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*diag_msg));
            parse_diag_msg(diag_msg, rtalen, tcp);

            nlh = NLMSG_NEXT(nlh, numbytes); 
        }
    }

    return EXIT_SUCCESS;
}
