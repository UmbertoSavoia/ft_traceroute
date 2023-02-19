#include "ft_traceroute.h"
#include "ft_getopt.h"

struct timeval ms_to_timeval(uint32_t t)
{
    return (struct timeval){
        .tv_sec  = t / 1000,
        .tv_usec = (t % 1000) * 1000
    };
}

double  delta_time(struct timeval *t1, struct timeval *t2)
{
    return (t2->tv_sec - t1->tv_sec) * 1000.0 + (t2->tv_usec - t1->tv_usec) / 1000.0;
}

int     resolve_destination(char *str, t_info *info)
{
    int error = 0, on = 1;
    struct addrinfo hints = {0};
    struct addrinfo *addrinfo_list = 0, *tmp = 0;
    struct sockaddr_storage addr;
    errno = 0;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;
    hints.ai_flags = AI_CANONNAME;

    if ((error = getaddrinfo(str, 0, &hints, &addrinfo_list))) {
        printf("%s: %s\n", str, gai_strerror(error));
        return -2;
    }
    for (tmp = addrinfo_list; tmp; tmp = tmp->ai_next) {
        if ((info->snd_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) >= 0 &&
                (info->rcv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) >= 0)
            break;
    }
    if ((info->snd_sock < 0) || (info->rcv_sock < 0) || !tmp) {
        printf("ft_traceroute: %s\n", strerror(errno));
        freeaddrinfo(addrinfo_list);
        return -1;
    }
    memcpy(&addr, tmp->ai_addr, tmp->ai_addrlen);
    info->dst.sin_family = AF_INET;
    memcpy(&(info->dst.sin_addr), &((struct sockaddr_in *)&addr)->sin_addr, sizeof(struct in_addr));
    memcpy(info->canonname_dst, tmp->ai_canonname, strlen(tmp->ai_canonname));
    inet_ntop(addr.ss_family, (void *)&((struct sockaddr_in *)&addr)->sin_addr, info->ip_dst, INET_ADDRSTRLEN);
    freeaddrinfo(addrinfo_list);
    if (info->debug) {
        setsockopt(info->snd_sock, SOL_SOCKET, SO_DEBUG, &on, sizeof(on));
        setsockopt(info->rcv_sock, SOL_SOCKET, SO_DEBUG, &on, sizeof(on));
    }
    return 0;
}

void    send_probe(t_info *info, uint32_t seq, uint32_t ttl)
{
    int ret = 0;
    uint32_t tot = info->len_packet + sizeof(struct ip) + sizeof(struct udphdr);
    struct ip    *ip  = (struct ip *)info->packet_udp;
    struct udphdr   *udp = (struct udphdr *)(info->packet_udp + sizeof(struct ip));

    ip->ip_tos = 0;
    ip->ip_dst.s_addr = info->dst.sin_addr.s_addr;
    ip->ip_off = 0;
    ip->ip_hl = sizeof(struct ip) >> 2;
    ip->ip_p = IPPROTO_UDP;
    ip->ip_len = tot;
    ip->ip_ttl = ttl;
    ip->ip_v = IPVERSION;
    ip->ip_id = htons(info->ident + seq);
    udp->uh_sport = htons(info->ident);
    udp->uh_dport = htons(info->port + seq);
    udp->uh_ulen = htons((uint16_t)(info->len_packet + sizeof(struct udphdr)));
    udp->uh_sum = 0;

    if ((ret = sendto(info->snd_sock, info->packet_udp, tot, 0,
                      (struct sockaddr *)&(info->dst), sizeof(struct sockaddr_in))) < 0)
        printf("ft_traceroute: wrote %s, ret=%d\n", info->canonname_dst, ret);
}

int     wait_response(t_info *info, struct sockaddr_in *addr)
{
    socklen_t addr_len = sizeof(struct sockaddr_in);
    struct timeval timeout = info->wait_time;
    int ret = 0;
    fd_set fds;

    FD_ZERO(&fds);
    FD_SET(info->rcv_sock, &fds);

    if (select(info->rcv_sock + 1, &fds, 0, 0, &timeout) > 0)
        ret = recvfrom(info->rcv_sock, info->packet_icmp, sizeof(info->packet_icmp),
                       0, (struct sockaddr *)addr, &addr_len);
    return ret;
}

int     check_packet(t_info *info, int ret, uint32_t seq)
{
    struct icmp *icmp = (struct icmp *)(info->packet_icmp + (((struct ip *)info->packet_icmp)->ip_hl << 2));
    struct ip *ip = 0;
    struct udphdr *udp = 0;
    int hlen = 0;

    if (!ret) return -1;
    if ((icmp->icmp_type == ICMP_TIMXCEED && icmp->icmp_code == ICMP_TIMXCEED_INTRANS) || icmp->icmp_type == ICMP_UNREACH) {
        ip = &(icmp->icmp_ip);
        hlen = ip->ip_hl << 2;
        udp = (struct udphdr *)((uint8_t *)ip + hlen);
        if (ip->ip_p == IPPROTO_UDP && udp->uh_sport == htons(info->ident) && udp->uh_dport == htons(info->port + seq)) {
            return (icmp->icmp_type == ICMP_TIMXCEED) ? ICMP_TIMXCEED : icmp->icmp_code;
        }
    }
    return -1;
}

void    ft_traceroute(t_info *info)
{
    struct sockaddr_in from = {0};
    char hostname[NI_MAXHOST] = {0};
    uint32_t last_addr = 0, seq = 1;
    int ret = 0, check = 0;
    struct timeval t1, t2;
    struct timezone tz;

    for (uint32_t ttl = 1; ttl <= info->hops_max; ++ttl) {
        printf("%2d ", ttl); fflush(stdout);
        for (uint32_t probe = 0; probe < info->probe_max; ++probe, ++seq) {
            gettimeofday(&t1, &tz);
            send_probe(info, seq, ttl);
            while (1) {
                ret = wait_response(info, &from);
                gettimeofday(&t2, &tz);
                if ((check = check_packet(info, ret, seq)) >= 0) {
                    if (from.sin_addr.s_addr != last_addr) {
                        last_addr = from.sin_addr.s_addr;
                        getnameinfo((struct sockaddr *)&from, sizeof(struct sockaddr),
                                hostname, sizeof(hostname), 0, 0, NI_IDN);
                        printf(" %s (%s)", hostname, inet_ntoa(from.sin_addr)); fflush(stdout);
                    }
                    printf("  %g ms", delta_time(&t1, &t2)); fflush(stdout);
                    break;
                }
                if (!ret) break;
            }
            if (!ret) {
                printf(" *"); fflush(stdout);
            }
        }
        write(1, "\n", 1);
        if (check == ICMP_UNREACH_PORT)
            return;
    }
}

int     set_option(int ac, char **av, t_info *info)
{
    int c = 0;
    ft_optind = 1;
    info->hops_max = DEFAULT_HOPS_MAX;
    info->len_packet = DEFAULT_SIZE_PACKET + sizeof(struct udphdr);
    info->probe_max = DEFAULT_PROBE_MAX;
    info->ident = (getpid() & 0xffff) | 0x8000;
    info->wait_time = ms_to_timeval(DEFAULT_WAIT_TIME);
    info->port = DEFAULT_PORT;

    while ((c = ft_getopt(ac, av, "m:p:q:w:dh")) != -1) {
        switch (c) {
            case 'm':
                info->hops_max = atoi(ft_optarg);
                break;
            case 'p':
                info->port = atoi(ft_optarg);
                if (info->port < 33434 || info->port > 33534) {
                    printf("%s: Port not in range (33434 - 33534)\n", av[0]);
                    return -1;
                }
                break;
            case 'q':
                info->probe_max = atoi(ft_optarg);
                break;
            case 'w':
                info->wait_time = ms_to_timeval(atoi(ft_optarg));
                break;
            case 'd':
                info->debug = 1;
                break;
            case 'h':
                printf("%s [-hd] [-m max_ttl] [-p port] [-q nqueries] [-w waittimes (ms)] host\n", av[0]);
                exit(0);
        }
    }
    return 0;
}

int     main(int ac, char **av)
{
    t_info info = {0};

    if (set_option(ac, av, &info) < 0)
        return 1;
    if (resolve_destination(av[ft_optind], &info) < 0)
        return 2;
    printf("ft_traceroute to %s (%s), %d hops max, %d byte packets\n",
           info.canonname_dst, info.ip_dst, info.hops_max, info.len_packet);
    if (!(info.packet_udp = calloc(info.len_packet+sizeof(struct udphdr)+sizeof(struct ip),
            sizeof(uint8_t))))
        return 3;
    ft_traceroute(&info);
    free(info.packet_udp);
    close(info.snd_sock);
    close(info.rcv_sock);
}
