#include "stdafx.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <WinSock2.h>
#pragma comment(lib,"Ws2_32.lib")
#define H_IP 0x0800
#define H_ARP 0x0806
#define H_RARP 0x0835

void packet_hd(u_char * parameter, const struct pcap_pkthdr * hd, const u_char * data);
//무한루프에서 쓸 함수
void gotoxy(int x, int y);
void start();
void delay(clock_t n);

int mode_select;

typedef struct E_header
{
	u_char des[6];//수신자
	u_char src[6];//송신자
	short int ptc;
}E_header;

typedef struct ip_ads
{
	u_char ip1;
	u_char ip2;
	u_char ip3;
	u_char ip4;
}ip_ads;

typedef struct IP_header
{
	u_char header_length : 4;
	u_char version : 4;
	u_char service;
	u_short total;
	u_short id;
	u_short flag;

	u_char TTL;
	u_char protocol;

	u_short checksum;

	ip_ads sendadd;
	ip_ads desadd;

	u_int optionpadding;
}IP_header;

typedef struct checksumm
{
	u_short part1;
	u_short part2;
	u_short part3;
	u_short part4;
	u_short part5;
	u_short checksum;
	u_short part6;
	u_short part7;
	u_short part8;
	u_short part9;
}checksumm;
pcap_if_t *alldev;
pcap_if_t *dev;
pcap_t *usedev;
pcap_dumper_t * dumpfile;
int main(int argc, char **argv)
{
	system("mode con cols=75 lines=20");
	CONSOLE_CURSOR_INFO cursorInfo = { 0, };
	char error[256];
	int i = 0;
	int mode = 0;
	char md = 0;
	u_char packet[10000];
	cursorInfo.dwSize = 1;
	cursorInfo.bVisible = FALSE;
	SetConsoleCursorInfo(GetStdHandle(STD_OUTPUT_HANDLE), &cursorInfo);
	start();
	gotoxy(1, 1);

	if (mode_select == 'b')
	{
		return 1;
	}
	else
	{
		system("cls");
		if ((pcap_findalldevs(&alldev, error)) == EOF)
		{
			printf("사용가능한 장치가 없습니다.\n");
		}

		int count = 0;
		for (dev = alldev; dev != NULL; dev = dev->next)
		{
			printf(" %d 번 네트워크 카드\n", count);
			printf("어댑터 정보 : %s\n", dev->name);
			printf("어댑터 설명 : %s\n", dev->description);
			printf("--------------------------------------------------------\n");
			count = count + 1;
		}
		printf("패킷을 수집할 네트워크 카드를 선택 하세요 : ");
		dev = alldev;

		int choice;
		scanf_s("%d", &choice);
		for (count = 0; count < choice; count++)
		{
			dev = dev->next;
		}

		usedev = pcap_open_live(dev->name, 65536, 0, 2, error);
		if (usedev == 0)
		{
			printf("pcap_live_open 실패%s\n", error);
		}

		pcap_freealldevs(alldev);

		dumpfile = pcap_dump_open(usedev, argv[1]);
		if (dumpfile == 0)
		{
			printf("패킷 덤프 실패\n"); return 0;
		}

		printf("\n1. 패킷 캡쳐\n");
		printf("2. ping flooding\n");

		scanf_s("%d", &mode);

		switch (mode)
		{
		case 1:
		{
			while (1)
			{
				pcap_loop(usedev, 0, packet_hd, (u_char *)dumpfile);
				printf("재시작 하시겠습니까 : (y/n)");
				scanf_s(" %c", &md, sizeof(md));

				if (md == 'y')
				{
					continue;
				}
				else if (md == 'n')
				{
					pcap_dump_close(dumpfile);
					pcap_close(usedev);
					break;
				}
			}
			break;
		}
		case 2:
		{
			memset(packet, 0, sizeof(packet));
			E_header e;
			IP_header ip;
			int length = 0;
			int s = 0;

			e.des[0] = 0x20;
			e.des[1] = 0x21;
			e.des[2] = 0x22;
			e.des[3] = 0x23;
			e.des[4] = 0x24;
			e.des[5] = 0x25;

			e.src[0] = 0x10;
			e.src[1] = 0x11;
			e.src[2] = 0x12;
			e.src[3] = 0x13;
			e.src[4] = 0x14;
			e.src[5] = 0x15;

			e.ptc = htons(H_IP);

			memcpy(packet, &e, sizeof(e));
			length += sizeof(e);
			memset(&ip, 0x10, sizeof(ip));
			ip.header_length = sizeof(ip) / 4;

			memcpy(packet + length, &ip, sizeof(ip));
			length += sizeof(ip);

			if (length < 64)
			{
				for (i = length;i < 64;i++)
				{
					packet[i] = rand() % 254;
				}
			}

			while (1)
			{
				if (kbhit() == 0)
				{
					if (pcap_sendpacket(usedev, packet, 1500) != 0)
					{
						fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(usedev));
						return 1;
					}
					gotoxy(20, 20);printf("%d번 전송중 (a누르면 종료)", ++i);
				}
				else
				{
					if (_getch() == 'a')
					{
						break;
					}
				}
			}

			break;
		}
		default:
		{
			printf("error");
			break;
		}
		}
	}
	return 0;
}

void packet_hd(u_char * param, const struct pcap_pkthdr * h, const u_char * data)
{

	char input;
	pcap_dump(param, h, data);

	if (kbhit() == 0)
	{
		E_header * eh = (E_header *)data;
		short int type = ntohs(eh->ptc);

		printf("다음번 패킷 : %04x\n", eh->ptc);

		printf("----------------------------------------------\n");
		printf("송신 맥주소 : %02x-%02x-%02x-%02x-%02x-%02x\n", eh->src[0], eh->src[1], eh->src[2], eh->src[3], eh->src[4], eh->src[5]);
		printf("수신 맥주소 : %02x-%02x-%02x-%02x-%02x-%02x\n", eh->des[0], eh->des[1], eh->des[2], eh->des[3], eh->des[4], eh->des[5]);
		IP_header * ih = (IP_header*)(data + 14);
		checksumm * cs = (checksumm*)(data + 14);
		if (type == H_IP)
		{
			int sc = ntohs(cs->part1) + ntohs(cs->part2) + ntohs(cs->part3) + ntohs(cs->part4) + ntohs(cs->part5) + ntohs(cs->part6) + ntohs(cs->part7) + ntohs(cs->part8) + ntohs(cs->part9);
			u_short movebit = sc >> 16;
			sc -= (movebit * 65536);
			printf("체크섬 : %04x\n", ntohs(cs->checksum));
			if (ntohs(cs->checksum) == (u_short)~(sc + movebit))
				printf("정상패킷\n");
			else
				printf("손상된 패킷입니다.\n:");
			printf("IP버전 : %d\n", ih->version);
			if (0x4000 == ((ntohs(ih->flag)) & 0x4000))
				printf("단편화 되지 않은 패킷\n");
			else
				printf("정상 단편화 패킷\n");
			if (0x2000 == ((ntohs(ih->flag)) & 0x2000))
				printf("단편화된 패킷이 더 있음\n");
			else
				printf("마지막 단편화 패킷\n");
			printf("패킷 ID : %d\n", ntohs(ih->id));
			printf("서비스 : %04x\n", ih->service);
			printf("헤더 길이 : %d\n", (ih->header_length) * 4);
			printf("전체 크기 : %d\n", ntohs(ih->header_length));
			switch (ih->protocol)
			{
			case 1:printf("프로토콜 : ICMP\n");break;
			case 2:printf("프로토콜 : IGMP\n");break;
			case 4:printf("프로토콜 : IPv4\n");break;
			case 6:printf("프로토콜 : TCP\n");break;
			case 17:printf("프로토콜 : UDP\n");break;
			case 41:printf("프로토콜 : IPv6\n");break;
			default: printf("프로토콜 : %d\n", ih->protocol);break;
			}
			printf("TTL : %d\n", ih->TTL);
			printf("프래그먼트오프셋 : %d바이트\n", (0x1FFF & ntohs(ih->flag) * 8));
			printf("옵션-패딩 : %d\n", ih->optionpadding);
			printf("송신IP주소 : %d.%d.%d.%d\n", ih->sendadd.ip1, ih->sendadd.ip2, ih->sendadd.ip3, ih->sendadd.ip4);
			printf("수신IP주소 : %d.%d.%d.%d\n", ih->desadd.ip1, ih->desadd.ip2, ih->desadd.ip3, ih->desadd.ip4);

		}
		else if (type == H_ARP)
		{
			printf("프로토콜 : ARP\n");
		}
		else if (type == H_RARP)
			printf("프로토콜 : RARP\n");
	}
	else
	{
		input = _getch();

		switch (input)
		{
		case 'x':pcap_breakloop(usedev);break;
		}
	}
}
void gotoxy(int x, int y)
{
	COORD Pos = { x - 1, y - 1 };
	SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), Pos);
}
void start()
{
	int i = 0;
	gotoxy(10, 5);
	for (i;i < 30;i++)
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
		printf("■");
		delay(20);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 8);
	}
	for (i = 6;i < 11;i++)
	{
		gotoxy(68, i);
		delay(30);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
		printf("■");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 8);
	}
	for (i = 0;i < 29;i++)
	{
		gotoxy(68 - (i * 2), 11);
		delay(20);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
		printf("■");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11);
	}
	for (i = 11;i >= 6;i--)
	{
		gotoxy(10, i);
		delay(30);
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
		printf("■");

		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11);
	}
	while (1)
	{
		if (kbhit() == 0)
		{
			int r;
			srand((int)time(NULL));
			r = 1 + rand() % 15;
			gotoxy(33, 8); printf("Packet Sniffer");SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), r);
			gotoxy(36, 14);printf("a.시작");
			gotoxy(36, 15);printf("b.종료");
		}
		else
		{
			mode_select = _getch();
			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
			break;
		}
	}
}
void delay(clock_t n)
{
	clock_t start = clock();
	while (clock() - start < n);
}