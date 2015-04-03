/*
* THIS FILE IS FOR IP FORWARD TEST
*/
#include "sysInclude.h"

#include <vector>
#include <iostream>

using namespace std;

// system support
extern void fwd_LocalRcv(char *pBuffer, int length);

//���ͷ���
extern void fwd_SendtoLower(char *pBuffer, int length, unsigned int nexthop);

//��������
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

//·�ɳ�ʼ������
void stud_Route_Init()
{
	m_table.clear();
	return;
}

//·����Ӻ���
void stud_route_add(stud_route_msg *proute)
{
	//�½�����
	routeTableItem newTableItem;
	//ÿ�����ݶ���Ҫ��ת���ֽ�˳��,����ת����ntohl
	newTableItem.masklen = ntohl(proute->masklen);
	//��λ�������,ǰ��ȫ1,����ȫ0
	newTableItem.mask = (1<<31)>>(ntohl(proute->masklen)-1);
	//������������Ŀ��IP,��λ��0
	newTableItem.destIP = ntohl(proute->dest)&newTableItem.mask;
	newTableItem.nexthop = ntohl(proute->nexthop);
	//��ӱ���
	m_table.push_back(newTableItem);
	return;
}

//ת��������
int stud_fwd_deal(char *pBuffer, int length)
{
	//��ͷ����
	int IHL = pBuffer[0] & 0xf;//ֻ��4λ��
	//IP����·��������֮ǰ����ͨ���������������
	int TTL = (int)pBuffer[8];//���TTL
	int destIP = ntohl(*(unsigned int*)(pBuffer+16));//���Ŀ�ĵ�ַ
	
	//1.�ж��Ƿ�Ϊ�������յķ���,����������fwd_LocalRcv()
	//������Ҫ���ж�,����ɹ�����0
	if(destIP == getIpv4Address())
	{
		fwd_LocalRcv(pBuffer, length);
		return 0;
	}
	
	//���û�е���,����TTL = 0,�Ͳ����ٴ�����
	if(TTL <= 0)
	{
		fwd_DiscardPkt(pBuffer, STUD_FORWARD_TEST_TTLERROR);
		return 1;
	}
	
	bool isMatch = false;
	//��¼�ƥ��
	unsigned int longestMatchLen = 0;
	//��¼ƥ������λ��
	int bestMatch = 0;
	
	//�����ҵ����ƥ��
	for(int i = 0; i < m_table.size(); i ++)
	{
		//����IP,destIP���������,����ҲҪ��������
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
		//֮ǰ��֤��TTL���ڵ���1
        buffer[8]--; //TTL - 1
		int sum = 0;  
        unsigned short int localCheckSum = 0;

		//����ͷ�ĳ��ȵ���IHL��ֵ����4,��˳���2���ܹ���16λ���
        for(int j = 0; j < 2 * IHL; j ++)
        {
			//����λ��checkSum,���ü���
            if (j == 5)
				continue;
            sum = sum + (buffer[j*2]<<8) + (buffer[j*2+1]);
        }

		//����
		while((unsigned(sum) >> 16) != 0)
		{
			sum = unsigned(sum) >> 16 + sum & 0xffff;
		}
           	localCheckSum = htons(0xffff - (unsigned short int)sum);
		

		//�Ѻ�У����µ�buffer
		memcpy(buffer+10, &localCheckSum, sizeof(unsigned short));
		
		//4.���ҳɹ�,����fwd_SendtoLower()��ɷ���ת��
		fwd_SendtoLower(buffer, length, m_table[bestMatch].nexthop);
		return 0;
	}
	else
	{
		//3.����ʧ��,����fwd_DiscardPkt()
		fwd_DiscardPkt(pBuffer, STUD_FORWARD_TEST_NOROUTE);
		return 1;
	}
	return 1;
}
