/*
* THIS FILE IS FOR IPv6 TEST
*/
// system support
#include "sysinclude.h"

extern void ipv6_DiscardPkt(char* pBuffer,int type);

extern void ipv6_SendtoLower(char*pBuffer,int length);

extern void ipv6_SendtoUp(char *pBuffer,int length);

extern void getIpv6Address(ipv6_addr *paddr);

// implemented by students

//1.实现ipv6分组的基本接收处理功能
int stud_ipv6_recv(char *pBuffer, unsigned short length)
{
	//版本号4位,不到一个字节
	int version = (int)pBuffer[0] >> 4;
	//hoplimit是无符号整数
	unsigned int hopLimit = (unsigned int)pBuffer[7];
	ipv6_addr *dstAddr = (ipv6_addr*)(pBuffer + 24);
	
	if (version != 6)
	{
		//丢弃错误分组,错误类型:版本号错
		ipv6_DiscardPkt(pBuffer, STUD_IPV6_TEST_VERSION_ERROR);
		return 1;
	}

	if (hopLimit <= 0)
	{
		//丢弃错误分组,错误类型:跳数限制错
		ipv6_DiscardPkt(pBuffer, STUD_IPV6_TEST_HOPLIMIT_ERROR);
		return 1;
	}

	ipv6_addr *paddr = new ipv6_addr;
	getIpv6Address(paddr);
	for (int i = 0; i < 4; i++)
	{
		//ipv6结构中dwAddr有4个,分别检查
		if (paddr->dwAddr[i] != dstAddr->dwAddr[i])
		{
			//丢弃错误分组,错误类型:目的地址错
			ipv6_DiscardPkt(pBuffer, STUD_IPV6_TEST_DESTINATION_ERROR);
			return 1;
		}
	}
	
	//如果没有错误,就提交给上层协议
	ipv6_SendtoUp(pBuffer, length);
	return 0;
}

//2.实现ipv6分组的封装和发送
int stud_ipv6_Upsend(char *pData, unsigned short len, 
					 ipv6_addr *srcAddr, ipv6_addr *dstAddr, 
					 char hoplimit, char nexthead)
{
	char send[len + 40];

	//只有这一项需要转化字节序
	short int sendLen = htons(len);
	
	//Traffic Class和Flow Label没有
	send[0] = 0x60;
	memcpy(send+4, &sendLen, sizeof(short int));
	memcpy(send+6, &nexthead, sizeof(char));
	memcpy(send+7, &hoplimit, sizeof(char));
	memcpy(send+8, srcAddr, sizeof(ipv6_addr));
	memcpy(send+24, dstAddr, sizeof(ipv6_addr));
	memcpy(send+40, pData, len);

	ipv6_SendtoLower(send, len+40);
	
	return 0;
}
