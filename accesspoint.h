#define NUM_ALLOC_IP 252

typedef struct {
  int  flag;
  char ipaddr[SIZE_IP];
  char macaddr[SIZE_MAC];
}AllocAddr;

typedef struct {
  char addr[SIZE_IP];
  char raddr1[SIZE_IP];
  char raddr2[SIZE_IP];
  AllocAddr alloc[NUM_ALLOC_IP];
}AccessPoint;



void  AccessPoint_init(AccessPoint *this, const char *ipaddr);
char *AccessPoint_resrvAllocAddr(AccessPoint *this, char *macaddr);
void  AccessPoint_cfmAllocAddr(AccessPoint *this, char *macaddr);
char *AccessPoint_getAddr(AccessPoint *this);
char *AccessPoint_getResrvAddr1(AccessPoint *this);
char *AccessPoint_getResrvAddr2(AccessPoint *this);
void  AccessPoint_delAllocAddr(AccessPoint *this, char *macaddr);
void  AccessPoint_printAllocAddr(AccessPoint *this);
char *func_getAddAddr(char *ipaddr, int addNum);
void  func_initAllocAddr(AllocAddr *this);
void  func_resrvAllocAddr(AccessPoint *this, char *macaddr);
char *func_getAllocAddr(AllocAddr *this, char *macaddr);
