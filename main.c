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
#include "myprotocol.h"
#include "netutil.h"
#include "checksum.h"
#include "debug.h"
#include "device.h"
#include "accesspoint.h"



// --- Global Variable --- //
Device       device1;
Device       device2;
Device       *device[]={&device1, &device2};
AccessPoint  ap1;
AccessPoint *ap[]={&ap1};
int          DebugOut=OFF;
int          EndFlag=OFF;
// --- Constant ---------- //
const char *NAME_DEV1="eth0";         // Connect Router
const char *NAME_DEV2="eth1";         // Connect AP1
const char *IP_AP1="192.168.30.1";    // IP Address of AP1



int chkMyProtoPacket(int deviceNo,u_char *data,int size)
{
  u_char *ptr;
  int     lest;
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

  if(ntohs(eh->ether_type)==MYPROTOCOL){
    MYPROTO *myproto;
    myproto=(MYPROTO *)ptr;
    ptr+=sizeof(MYPROTO);
    lest-=sizeof(MYPROTO);

    char *CHK_MAC="ff:ff:ff:ff:ff:ff";
    char *CHK_SIP="00H.00H.00H.00H";
    char *CHK_DIP="FF.FF.FF.FF";
    char  dMacAddr[SIZE_MAC];
    char  sMacAddr[SIZE_MAC];

    switch(ntohs(myproto->type)){
    case    INITAP:;
      my_ether_ntoa_r(eh->ether_dhost, dMacAddr, sizeof(dMacAddr));

      if((strncmp(dMacAddr, CHK_MAC, SIZE_MAC)==0) &&
	 (myproto->ip_src==inet_addr(CHK_SIP)) &&
	 (myproto->ip_dst==inet_addr(CHK_DIP))){
	printf("--- Recieve Init AP Packet ----\n");
	my_ether_ntoa_r(eh->ether_shost, sMacAddr, sizeof(sMacAddr));
	printf("--- Send Build AP Packet ------\n");
	printf("Build [%s] Access Point\nThis Mac Address is \"%s\"\n", AccessPoint_getAddr(ap[deviceNo-1]), sMacAddr);
	create_myprotocol(Device_getSoc(device[deviceNo]),
			  Device_getMacAddr(device[deviceNo]), sMacAddr,
			  Device_getIpAddr(device[deviceNo]), (char *)AccessPoint_getAddr(ap[deviceNo-1]),
			  INITAP);
	return(-1);
      }
      break;
      /*
    case   DISCOVER:;
      my_ether_ntoa_r(eh->ether_dhost, dMacAddr, sizeof(dMacAddr));

      if((strncmp(dMacAddr, Device_getMacAddr(device[1]), SIZE_MAC)==0) &&
	 (myproto->ip_src==inet_addr(CHK_SIP)) &&
	 (myproto->ip_dst==inet_addr(CHK_DIP))){
	printf("--- Recieve Discover Packet ---\n");
	my_ether_ntoa_r(eh->ether_shost, sMacAddr, sizeof(sMacAddr));
	printf("--- Send Offer Packet ---------\n");
	create_myprotocol(Device_getSoc(device[1]),
			  Device_getMacAddr(device[1]), sMacAddr,
			  Device_getIpAddr(device[1]), AccessPoint_resrvAllocAddr(ap[deviceNo-1], sMacAddr),
			  OFFER);
	return(-1);
      }
      break;
    case   APPROVAL:;
      my_ether_ntoa_r(eh->ether_dhost, dMacAddr, sizeof(dMacAddr));
      if((strncmp(dMacAddr, Device_getMacAddr(device[1]), SIZE_MAC)==0) &&
	 (myproto->ip_dst==inet_addr(Device_getIpAddr(device[1])))){
	printf("--- Recieve Approval Packet ---\n");
	my_ether_ntoa_r(eh->ether_shost, sMacAddr, sizeof(sMacAddr));
	AccessPoint_cfmAllocAddr(ap[deviceNo-1], sMacAddr);
	return(-1);
      }
      */
    default:
      break;
    }
  }
  return(0);
}

/*
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
*/

int Bridge()
{
  struct pollfd	targets[2];
  int	        nready,i,size;
  u_char	buf[2048];

  // "eth0"
  targets[0].fd=Device_getSoc(device[0]);
  targets[0].events=POLLIN|POLLERR;
  // "eth1"
  targets[1].fd=Device_getSoc(device[1]);
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
	  if((size=read(Device_getSoc(device[i]),buf,sizeof(buf)))<=0){
	    perror("read");
	  }
	  else{
	    if(chkMyProtoPacket(i,buf,size)!=-1){
	      //if((size=write(Device_getSoc(device[!i]),buf,size))<=0){
		//perror("write");
	      //}
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

  // Initialize
  Device_init(device[0], NAME_DEV1);
  Device_init(device[1], NAME_DEV2);
  AccessPoint_init(ap[0], IP_AP1);

  // Alloc IP Address
  Device_setIpAddr(device[1], AccessPoint_getResrvAddr2(ap[0]));

  // (Debug): Print Device Information
  Device_printInfo(device[0]);
  Device_printInfo(device[1]);

  // Disable IPv4 IP Forward
  DisableIpForward();

  // Signal Handler
  signal(SIGINT,EndSignal);
  signal(SIGTERM,EndSignal);
  signal(SIGQUIT,EndSignal);
  signal(SIGPIPE,SIG_IGN);
  signal(SIGTTIN,SIG_IGN);
  signal(SIGTTOU,SIG_IGN);

  // Bridge between "eth0" and "eth1"
  int status;
  if ((status = pthread_create(&th1, NULL, thread1, NULL)) != 0) {
    printf("pthread_create%s\n", strerror(status));
  }
  pthread_join(th1, NULL);

  Device_del(device[0]);
  Device_del(device[1]);

  return(0);
}
