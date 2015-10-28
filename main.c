#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <pthread.h>
//----- RewritePacket()
#include <netinet/tcp.h>
#include <netinet/udp.h>
//-----
#include "mydef.h"
#include "mystruct.h"
#include "myprotocol.h"
#include "ifutil.h"
#include "netutil.h"
#include "checksum.h"
#include "debug.h"



// --- Global Variable ---
const char *NameDev1="eth0";    // Router Side
const char *NameDev2="eth1";    // AP Side: 192.168.30~
const char *IpAp1="192.168.30.1";
// const char *IpAp2="192.168.40.1";


int DebugOut=OFF;
int EndFlag=OFF;
int StatusFlag=STA_DISCOVER;

char *routerMacAddr="dc:fb:02:aa:64:fa";
char *routerIpAddr="192.168.20.1";
char raspMacAddr[SIZE_MAC];
char raspIpAddr[SIZE_IP];
char dev1MacAddr[SIZE_MAC];
char dev2MacAddr[SIZE_MAC];
char dev1IpAddr[SIZE_MAC];
char dev2IpAddr[SIZE_IP];

DEVICE	Device[2];



int AnalyzePacket(int deviceNo,u_char *data,int size)
{
  u_char *ptr;
  int lest;
  struct ether_header *eh;
  
  ptr=data;
  lest=size;
  if(size<sizeof(struct ether_header)){
    DebugPrintf("[%d]:lest(%d)<sizeof(struct ether_header)\n",deviceNo,size);
    return(-1);
  }
  eh=(struct ether_header *)ptr;
  ptr+=sizeof(struct ether_header);
  lest-=sizeof(struct ether_header);
  DebugPrintf("[%d]",deviceNo);
  if(DebugOut){
    PrintEtherHeader(eh,stderr);
  }

  // Init AP
  if(ntohs(eh->ether_type)==MYPROTOCOL){
    MYPROTO *myproto;
    myproto=(MYPROTO *)ptr;
    ptr+=sizeof(MYPROTO);
    lest-=sizeof(MYPROTO);

    char *dmac="ff:ff:ff:ff:ff:ff";
    char *sip="00H.00H.00H.00H";
    char *dip="FF.FF.FF.FF";

    switch(ntohs(myproto->type)){
    case    INITAP:;
      char init_dMacAddr[18];
      char init_sMacAddr[18];
      my_ether_ntoa_r(eh->ether_dhost, init_dMacAddr, sizeof(init_dMacAddr));

      if((strncmp(init_dMacAddr, dmac, SIZE_MAC)==0) &&
	 (myproto->ip_src==inet_addr(sip)) &&
	 (myproto->ip_dst==inet_addr(dip))
	 ){
	printf("--- Recieve Init AP Packet ----\n");
	my_ether_ntoa_r(eh->ether_shost, init_sMacAddr, sizeof(init_sMacAddr));
	
	printf("--- Send Build AP Packet ------\n");
	printf("Build [%s] Access Point.\nThis Mac Address is \"%s\"\n", IpAp1, init_sMacAddr);
	create_myprotocol(Device[1].soc, dev2MacAddr, init_sMacAddr, dev2IpAddr, (char *)IpAp1, INITAP);

	return(-1);
      }
      break;
    case   DISCOVER:;
      char disc_dMacAddr[18];
      char disc_sMacAddr[18];
      my_ether_ntoa_r(eh->ether_dhost, disc_dMacAddr, sizeof(disc_dMacAddr));
      if((strncmp(disc_dMacAddr, dev2MacAddr, SIZE_MAC)==0) &&
	 (myproto->ip_src==inet_addr(sip)) &&
	 (myproto->ip_dst==inet_addr(dip))
	 ){
	printf("--- Recieve Discover Packet ---\n");
	my_ether_ntoa_r(eh->ether_shost, disc_sMacAddr, sizeof(disc_sMacAddr));

	printf("--- Send Offer Packet ---------\n");
	// --- Make Alloc IP Address ----- //
	strncpy(raspIpAddr, IpAp1, SIZE_IP);
	plusIpAddr(raspIpAddr, 10);
	// ------------------------------- //
	create_myprotocol(Device[1].soc, dev2MacAddr, disc_sMacAddr, dev2IpAddr, raspIpAddr, OFFER);

	return(-1);
      }
    case   APPROVAL:;
      char app_dMacAddr[18];
      my_ether_ntoa_r(eh->ether_dhost, app_dMacAddr, sizeof(app_dMacAddr));
      if((strncmp(app_dMacAddr, dev2MacAddr, SIZE_MAC)==0) &&
	 (myproto->ip_dst==inet_addr(dev2IpAddr))
	 ){
	printf("--- Recieve Approval Packet ---\n");
	my_ether_ntoa_r(eh->ether_shost, raspMacAddr, sizeof(raspMacAddr));
	return(-1);
      }
    default:
      break;
    }
  }
  return(0);
}

int RewritePacket (int deviceNo, u_char *data, int size) {
  u_char *ptr;
  struct ether_header *eh;
  int lest, len;
  
  ptr=data;
  lest=size;
  
  if(lest<sizeof(struct ether_header)){
    DebugPrintf("[%d]:lest(%d)<sizeof(struct ether_header)\n",deviceNo,lest);
    return(-1);
  }

  eh=(struct ether_header *)ptr;
  ptr+=sizeof(struct ether_header);
  lest-=sizeof(struct ether_header);

  char dMacAddr[18];
  char sMacAddr[18];

  // Get dMAC, sMAC
  my_ether_ntoa_r(eh->ether_dhost, dMacAddr, sizeof(dMacAddr));
  my_ether_ntoa_r(eh->ether_shost, sMacAddr, sizeof(sMacAddr));
  
  // AP -> Router
  if(strncmp(sMacAddr, raspMacAddr, SIZE_MAC)==0){
    my_ether_aton_r(dev1MacAddr, eh->ether_shost);
    my_ether_aton_r(routerMacAddr, eh->ether_dhost);
    
    // Case: IP
    if (ntohs(eh->ether_type)==ETHERTYPE_IP) {
      struct iphdr *iphdr;
      u_char option[1500];
      int optLen;
      
      iphdr=(struct iphdr *)ptr;
      ptr+=sizeof(struct iphdr);
      lest-=sizeof(struct iphdr);
      optLen=iphdr->ihl*4-sizeof(struct iphdr);
      if(optLen>0){
	memcpy(option, ptr, optLen);
	ptr+=optLen;
	lest-=optLen;
      }
      
      // Rewrite IP Address
      if(iphdr->saddr==inet_addr("192.168.30.11")){
	iphdr->saddr=inet_addr(dev1IpAddr);
      }
      iphdr->check=0;
      iphdr->check=calcChecksum2((u_char *)iphdr, sizeof(struct iphdr), option, optLen);
      
      // Case : TCP
      if(iphdr->protocol==IPPROTO_TCP){
	struct tcphdr *tcphdr;
	
	len=ntohs(iphdr->tot_len)-iphdr->ihl*4;
	tcphdr=(struct tcphdr *)ptr;
	tcphdr->check=0;
	tcphdr->check=checkIPDATAchecksum(iphdr, ptr, len);
      }
      // Case : UDP
      if(iphdr->protocol==IPPROTO_UDP){
	struct udphdr* udphdr;
	
	len=ntohs(iphdr->tot_len)-iphdr->ihl*4;
	udphdr=(struct udphdr *)ptr;
	udphdr->check=0;
      }
    }
  }
  // Router -> AP
  else if (strncmp(dMacAddr, dev1MacAddr, SIZE_MAC)==0) {
    my_ether_aton_r(raspMacAddr, eh->ether_dhost);
    my_ether_aton_r(dev2MacAddr, eh->ether_shost);

    // Case: IP
    if (ntohs(eh->ether_type)==ETHERTYPE_IP) {
      struct iphdr *iphdr;
      u_char option[1500];
      int optLen;
      
      iphdr=(struct iphdr *)ptr;
      ptr+=sizeof(struct iphdr);
      lest-=sizeof(struct iphdr);
      optLen=iphdr->ihl*4-sizeof(struct iphdr);
      if(optLen>0){
	memcpy(option, ptr, optLen);
	ptr+=optLen;
	lest-=optLen;
      }
      
      // Rewrite IP Address
      if(iphdr->daddr==inet_addr(dev1IpAddr)){
	iphdr->daddr=inet_addr("192.168.30.11");
      }
      iphdr->check=0;
      iphdr->check=calcChecksum2((u_char *)iphdr, sizeof(struct iphdr), option, optLen);
      
      // Case : TCP
      if(iphdr->protocol==IPPROTO_TCP){
	struct tcphdr *tcphdr;
	
	len=ntohs(iphdr->tot_len)-iphdr->ihl*4;
	tcphdr=(struct tcphdr *)ptr;
	tcphdr->check=0;
	tcphdr->check=checkIPDATAchecksum(iphdr, ptr, len);
      }
      // Case : UDP
      if(iphdr->protocol==IPPROTO_UDP){
	struct udphdr* udphdr;
	
	len=ntohs(iphdr->tot_len)-iphdr->ihl*4;
	udphdr=(struct udphdr *)ptr;
	udphdr->check=0;
      }
    }
  }
  return(0);
}

int Bridge()
{
  struct pollfd	targets[2];
  int	nready,i,size;
  u_char	buf[2048];

  // WLAN1
  targets[0].fd=Device[0].soc;
  targets[0].events=POLLIN|POLLERR;
  // ETH1
  targets[1].fd=Device[1].soc;
  targets[1].events=POLLIN|POLLERR;

  while(EndFlag==0){
    switch(nready=poll(targets,2,100)){
    case	-1:
      if(errno!=EINTR){
	perror("poll");
      }
      break;
    case	0:
      break;
    default:
      for(i=0;i<2;i++){
	if(targets[i].revents&(POLLIN|POLLERR)){
	  if((size=read(Device[i].soc,buf,sizeof(buf)))<=0){
	    perror("read");
	  }
	  else{
	    if(AnalyzePacket(i,buf,size)!=-1 && RewritePacket(i,buf,size)!=-1){
	      if((size=write(Device[(!i)].soc,buf,size))<=0){
		//perror("write");
	      }
	    }
	  }
	}
      }
      break;
    }
  }

  return(0);
}

int DisableIpForward()
{
  FILE *fp;
  if((fp=fopen("/proc/sys/net/ipv4/ip_forward","w"))==NULL){
    DebugPrintf("cannot write /proc/sys/net/ipv4/ip_forward\n");
    return(-1);
  }
  fputs("0",fp);
  fclose(fp);

  return(0);
}

void EndSignal(int sig)
{
  EndFlag=ON;
}

void *thread1 (void *args) {
  DebugPrintf("Create Thread1\n");
  Bridge();
  return NULL;
}

int main(int argc,char *argv[],char *envp[])
{
  pthread_t th1;
  
  //getArpCache();
  
  // Make Dev2 IP ADDR
  strncpy(dev2IpAddr, IpAp1, SIZE_IP);
  plusIpAddr(dev2IpAddr,2);
  // Init Interface IP Address
  if(chgIfIp(NameDev2, inet_addr(dev2IpAddr))!=0){
    DebugPrintf("chgIfIp:error:%s\n",NameDev2);
    return(-1);
  }

  // Get IP and Mac Address
  getIfMac(NameDev1, dev1MacAddr);
  getIfMac(NameDev2, dev2MacAddr);
  getIfIp(NameDev1, dev1IpAddr);

  // Debug Print
  printf("Mac Address of [%s] on [%s] is \"%s\"\n", dev1IpAddr, NameDev1, dev1MacAddr);
  printf("Mac Address of [%s] on [%s] is \"%s\"\n", dev2IpAddr, NameDev2, dev2MacAddr);

  // Init Socket
  if((Device[0].soc=InitRawSocket(NameDev1,1,0))==-1){
    DebugPrintf("InitRawSocket:error:%s\n",NameDev1);
    return(-1);
  }
  DebugPrintf("%s OK\n",NameDev1);

  if((Device[1].soc=InitRawSocket(NameDev2,1,0))==-1){
    DebugPrintf("InitRawSocket:error:%s\n",NameDev2);
    return(-1);
  }
  DebugPrintf("%s OK\n",NameDev2);

  DisableIpForward();

  signal(SIGINT,EndSignal);
  signal(SIGTERM,EndSignal);
  signal(SIGQUIT,EndSignal);

  signal(SIGPIPE,SIG_IGN);
  signal(SIGTTIN,SIG_IGN);
  signal(SIGTTOU,SIG_IGN);

  DebugPrintf("bridge start\n");
  int status;
  if ((status = pthread_create(&th1, NULL, thread1, NULL)) != 0) {
    printf("pthread_create%s\n", strerror(status));
  }
  DebugPrintf("bridge end\n");

  pthread_join(th1, NULL);

  close(Device[0].soc);
  close(Device[1].soc);

  return(0);
}
