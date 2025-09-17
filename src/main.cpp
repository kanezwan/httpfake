#include "packet_sniffer.h"
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * @brief �������
 * ������ʾhttp�ٳּ���ԭ��������ָ��ԴIP��·������Ϊ25�����󣬿���ʵ������޸�
 *
 * ע���������ݰ�ȫ���������ڷǷ�֮Ŀ��
 */
int main(int argc, char **argv) {
  if (argc < 2) {
    printf("Usage: %s eth0 type\n", basename(argv[0]));
    printf("\t\teth0: The nic will be sniffed\n");
    printf("\t\ttype: How to sample flow, 1.rawsocket 2.libpcap\n");
    return 1;
  }

  // �ɼ���
  PacketSniffer pSniffer;
  pSniffer.Start(argv[1], atoi(argv[2]));
  
  return 0;
}
