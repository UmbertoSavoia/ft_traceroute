#ifndef FT_TRACEROUTE
#define FT_TRACEROUTE

#define _GNU_SOURCE
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#define DEFAULT_PROBE_MAX    3
#define DEFAULT_WAIT_TIME   5000
#define DEFAULT_HOPS_MAX    30
#define DEFAULT_SIZE_PACKET 52
#define DEFAULT_PORT        33434

typedef struct  s_info
{
    int                 snd_sock;
    int                 rcv_sock;
    uint16_t            ident;
    uint32_t            port;
    struct sockaddr_in  dst;
    char                canonname_dst[NI_MAXHOST];
    char                ip_dst[INET_ADDRSTRLEN];
    uint32_t            hops_max;
    uint32_t            probe_max;
    struct timeval      wait_time;
    uint8_t             debug;
    uint8_t             *packet_udp;
    uint8_t             packet_icmp[512];
    uint32_t            len_packet;
}               t_info;

#endif
