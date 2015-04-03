/*
* THIS FILE IS FOR IP FORWARD TEST
*/
#include "sysInclude.h"

#include <vector>
#include <iostream>

using namespace std;

// system support
extern void fwd_LocalRcv(char *pBuffer, int length);

//发送分组
extern void fwd_SendtoLower(char *pBuffer, int length, unsigned int nexthop);

//丢弃分组
extern void fwd_DiscardPkt(char *pBuffer, int type);

extern unsigned int getIpv4Address( );

// implemented by students

struct routeTableItem
{
	unsigned int destIP;
	unsigned int mask;
	unsigned int masklen;
	unsigned int nexthop;
};
vector<routeTableItem> m_table;

//路由初始化函数
void stud_Route_Init()
{
	m_table.clear();
	return;
}

//路由添加函数
void stud_route_add(stud_route_msg *proute)
{
	//新建表项
	routeTableItem newTableItem;
	//每项数据都需要先转换字节顺序,网络转主机ntohl
	newTableItem.masklen = ntohl(proute->masklen);
	//移位获得掩码,前面全1,后面全0
	newTableItem.mask = (1<<31)>>(ntohl(proute->masklen)-1);
	//与掩码相与获得目的IP,后几位清0
	newTableItem.destIP = ntohl(proute->dest)&newTableItem.mask;
	newTableItem.nexthop = ntohl(proute->nexthop);
	//添加表项
	m_table.push_back(newTableItem);
	return;
}

//转发处理函数
int stud_fwd_deal(char *pBuffer, int length)
{
	//报头长度
	int IHL = pBuffer[0] & 0xf;//只有4位长
	//IP包被路由器丢弃之前允许通过的最大网段数量
	int TTL = (int)pBuffer[8];//获得TTL
	int destIP = ntohl(*(unsigned int*)(pBuffer+16));//获得目的地址
	
	//1.判定是否为本机接收的分组,如果是则调用fwd_LocalRcv()
	//本项需要先判断,如果成功返回0
	if(destIP == getIpv4Address())
	{
		fwd_LocalRcv(pBuffer, length);
		return 0;
	}
	
	//如果没有到达,而且TTL = 0,就不能再传递了
	if(TTL <= 0)
	{
		fwd_DiscardPkt(pBuffer, STUD_FORWARD_TEST_TTLERROR);
		return 1;
	}
	
	bool isMatch = false;
	//记录最长匹配
	unsigned int longestMatchLen = 0;
	//记录匹配所在位置
	int bestMatch = 0;
	
	//遍历找到最长的匹配
	for(int i = 0; i < m_table.size(); i ++)
	{
		//表项IP,destIP是掩码过的,这里也要再算掩码
		if(m_table[i].masklen > longestMatchLen && m_table[i].destIP == (destIP & m_table[i].mask))
		{
			bestMatch = i;
			isMatch = true;
			longestMatchLen = m_table[i].masklen;
		}
	}
	
	if(isMatch)
	{
		char *buffer = new char[length];  
        memcpy(buffer,pBuffer,length);
		//之前验证过TTL大于等于1
        buffer[8]--; //TTL - 1
		int sum = 0;  
        unsigned short int localCheckSum = 0;

		//报文头的长度等于IHL的值乘以4,因此乘以2就能够按16位求和
        for(int j = 0; j < 2 * IHL; j ++)
        {
			//第五位是checkSum,不用加入
            if (j == 5)
				continue;
            sum = sum + (buffer[j*2]<<8) + (buffer[j*2+1]);
        }

		//求反码
		while((unsigned(sum) >> 16) != 0)
		{
			sum = unsigned(sum) >> 16 + sum & 0xffff;
		}
           	localCheckSum = htons(0xffff - (unsigned short int)sum);
		

		//把和校验更新到buffer
		memcpy(buffer+10, &localCheckSum, sizeof(unsigned short));
		
		//4.查找成功,调用fwd_SendtoLower()完成分组转发
		fwd_SendtoLower(buffer, length, m_table[bestMatch].nexthop);
		return 0;
	}
	else
	{
		//3.查找失败,调用fwd_DiscardPkt()
		fwd_DiscardPkt(pBuffer, STUD_FORWARD_TEST_NOROUTE);
		return 1;
	}
	return 1;
}
