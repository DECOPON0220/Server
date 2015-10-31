#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mydef.h"
#include "accesspoint.h"



void AccessPoint_init(AccessPoint *this, const char *ipaddr)
{
  strcpy(this->addr, ipaddr);
  strcpy(this->raddr1, this->addr);
  strcpy(this->raddr2, this->addr);
  func_getAddAddr(this->raddr1, 1);
  func_getAddAddr(this->raddr2, 2);
  func_initAllocAddr(this->alloc);
}

char *AccessPoint_resrvAllocAddr(AccessPoint *this, char *macaddr)
{
  func_resrvAllocAddr(this, macaddr);
  return(func_getAllocAddr(this->alloc, macaddr));
}

void AccessPoint_cfmAllocAddr(AccessPoint *this, char *macaddr)
{
  int i;
  for(i=0;i<NUM_ALLOC_IP;i++){
    if(strncmp(this->alloc[i].macaddr, macaddr, SIZE_MAC)==0){
      this->alloc[i].flag=ON;
      return;
    }
  }
  return;
}

char *AccessPoint_getAddr(AccessPoint *this)
{
  return(this->addr);
}

char *AccessPoint_getResrvAddr1(AccessPoint *this)
{
  return(this->raddr1);
}

char *AccessPoint_getResrvAddr2(AccessPoint *this)
{
  return(this->raddr2);
}

void AccessPoint_delAllocAddr(AccessPoint *this, char *macaddr)
{
  int i;
  for(i=0;i<NUM_ALLOC_IP;i++){
    if(strncmp(this->alloc[i].macaddr, macaddr, SIZE_MAC)==0){
      this->alloc[i].flag=OFF;
      memset(this->alloc[i].ipaddr, '\0', SIZE_IP);
      memset(this->alloc[i].macaddr, '\0', SIZE_MAC);
      return;
    }
  }
}

void AccessPoint_printAllocAddr(AccessPoint *this)
{
  int i;
  for(i=0;i<NUM_ALLOC_IP;i++){
    if(this->alloc[i].flag==ON){
      printf("Mac Address of [%s] is \"%s\"\n",
	     this->alloc[i].ipaddr, this->alloc[i].macaddr);
    }
  } 
}

char *func_getAddAddr(char *ipaddr, int addNum)
{
  int lenIp, f_octet;

  lenIp=strlen(ipaddr);
  ipaddr+=lenIp-1;
  f_octet=atoi(ipaddr);
  f_octet+=addNum;
  sprintf(ipaddr,"%d",f_octet);
  ipaddr-=lenIp-1;
  
  return(ipaddr);
}

void func_initAllocAddr(AllocAddr *this)
{
  int i;
  for(i=0;i<NUM_ALLOC_IP;i++){
    this[i].flag=OFF;
  }
}

void func_resrvAllocAddr(AccessPoint *this, char *macaddr)
{
  int i;
  for(i=0;i<NUM_ALLOC_IP;i++){
    if(this->alloc[i].flag==OFF){
      strcpy(this->alloc[i].ipaddr, this->addr);
      func_getAddAddr(this->alloc[i].ipaddr, i+3);
      strcpy(this->alloc[i].macaddr, macaddr);
      return;
    }
    //----------------
    // if Client > 255 
    //----------------
  }
}

char *func_getAllocAddr(AllocAddr *this, char *macaddr)
{
  int i;
  for(i=0;i<NUM_ALLOC_IP;i++){
    if(strncmp(this[i].macaddr, macaddr, SIZE_MAC)==0){
      return(this[i].ipaddr);
    }
  }

  return("error");
}
