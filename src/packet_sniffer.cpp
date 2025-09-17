#include "packet_sniffer.h"
#include "http_parse.h"
#include "httpfake.h"
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>


#define BUF_LEN         (2048)
#define CHECK_PATH_LEN  (18)

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100
#endif
#ifndef VALUE_GET
#define VALUE_GET 0x47455420
#endif

// 劫持响应
static char *g_Response = "<html>"
                          "<head><title>intercept demo</title></head>"
                          "<body><h1>You web is hijacked, Haha</h1></body>"
                          "</html>";

volatile sig_atomic_t keepRunning = 1;

void sig_handler(int sig) {
    if (sig == SIGINT) {
        keepRunning = 0;
    }
}

///
PacketSniffer::PacketSniffer() {
  mParser = new HttpParse();
  if (mParser == NULL) {
    fprintf(stderr, "Init http parser error");
    exit(1);
  }

  mFaker = new HttpFake();
  if (mParser == NULL) {
    fprintf(stderr, "Init http parser error");
    exit(1);
  }
}

PacketSniffer::~PacketSniffer() {
  if (mParser) {
    delete mParser;
    mParser = NULL;
  }

  if (mFaker) {
    delete mFaker;
    mFaker = NULL;
  }
}

void PacketSniffer::Start(char *eth, int type) {
  // inet_pton( AF_INET, ip, &m_PreventIp );

  // 采集类型
  if (type == 1) {
    printf("In raw socket mode\n");

    this->RawSniffer(eth);
  } else if (type == 2) {
    printf("In libpcap mode\n");

    this->PcapSniffer(eth);
  }
}

void PacketSniffer::HandleFrame(char *pdata) {
  if (pdata == NULL) {
    return;
  }

  struct ethhdr *pe;
  struct iphdr *iphead;
  struct tcphdr *tcp;

  char *Data = NULL;
  unsigned int Length = 0;

  URLInfo host = {};
  int offset = 0;

  pe = (struct ethhdr *)pdata;

  /// vlan
  if (ntohs(pe->h_proto) == ETHERTYPE_VLAN) // vlan
  {
    offset = 4;
  } else if (ntohs(pe->h_proto) != ETHERTYPE_IP) // ip
  {
    return;
  }

  /// ip
  iphead = (struct iphdr *)(pdata + offset + sizeof(struct ethhdr));
  if (NULL == iphead) {
    return;
  }

  if (iphead->protocol != IPPROTO_TCP) {
    return;
  }

  /// tcp
  tcp = (struct tcphdr *)((char *)iphead + iphead->ihl * 4);
  if (NULL == tcp) {
    return;
  }

  /// 80+8080
  if ((ntohs(tcp->dest) != 80) && (ntohs(tcp->dest) != 8080)) {
    return;
  }

  Length = htons(iphead->tot_len) - iphead->ihl * 4 - tcp->doff * 4;
  if (Length < 20 || Length > 3000) {
    return;
  }

  Data = (char *)tcp + tcp->doff * 4;

  /// GET请求
  if (ntohl(*(unsigned int *)Data) != VALUE_GET) {
    return;
  }

  // 解析主域名
  if (!mParser->parseHttp(Data, Length, &host)) {
    return;
  }

  printf("IP: %x %s/%s plen:%d\n", iphead->saddr, host.host, host.path, host.plen);

  /// 便于演示，仅拦截path=18的请求
  if (host.plen = CHECK_PATH_LEN) {
    // 伪造响应
    mFaker->sendHttpResponse((char *)iphead, g_Response);
  }
}

int PacketSniffer::RawSniffer(const char *ethn) {
  int n;
  char buffer[BUF_LEN];

  int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
  assert(sock != -1);

  // nic=eth0
  struct ifreq ifr;
  strcpy(ifr.ifr_name, ethn);
  ioctl(sock, SIOCGIFFLAGS, &ifr);

  // promisc
  ifr.ifr_flags |= IFF_PROMISC;
  ioctl(sock, SIOCGIFFLAGS, &ifr);

  // 设置非阻塞模式
  int flags = fcntl(sock, F_GETFL, 0);
  fcntl(sock, F_SETFL, flags | O_NONBLOCK);

  while (keepRunning) {
    bzero(buffer, BUF_LEN);
    n = recvfrom(sock, buffer, BUF_LEN, 0, NULL, NULL);

    if (n > 0) {
      // 回调处理
      this->HandleFrame(buffer);
    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
      // 无数据时短暂休眠
      usleep(1000);
    }
  }

  close(sock);
  return 0;
}

#ifdef _ENABLE_PCAP
#include <pcap.h>

// Libpcap回调函数
void GetPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
  PacketSniffer *pSniffer = (PacketSniffer *)arg;
  
  // 仅处理有效长度的包
  if (pkthdr->caplen > 0) {
    pSniffer->HandleFrame((char *)packet);
  }
}

#endif // _ENABLE_PCAP

int PacketSniffer::PcapSniffer(char *eth) {
#ifdef _ENABLE_PCAP
  printf("pcap sniffer ...\n");
  char errBuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  const char *device = pcap_lookupdev(errBuf);
  if (device == NULL) {
      fprintf(stderr, "Couldn't find default device: %s\n", errBuf);
      return 1;
  }

  handle = pcap_open_live(eth, BUFSIZ, 1, 1000, errBuf);
  if (!handle) {
    printf("ERROR: open pcap %s\n", errBuf);
    exit(1);
  }

  // 设置缓冲区大小为2MB
  if (pcap_set_buffer_size(handle, 2 * 1024 * 1024) != 0) {
    printf("WARNING: Failed to set pcap buffer size\n");
  }

  // 设置非阻塞模式
  if (pcap_setnonblock(handle, 1, errBuf) != 0) {
    printf("WARNING: Failed to set pcap non-blocking mode\n");
  }
 
  while (keepRunning) {
    int count = pcap_dispatch(handle, 10, GetPacket, (u_char *)this);
    if (count < 0) {
      fprintf(stderr, "Error capturing packets: %s\n", pcap_geterr(handle));
      break;
    } else if (count == 0) {
      usleep(10000);
    }
  }

  pcap_close(handle);
#endif // _ENABLE_PCAP

  return 0;
}
