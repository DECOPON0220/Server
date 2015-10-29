typedef struct{
  u_int32_t ip_src;
  u_int32_t ip_dst;
  u_short   type;
  unsigned char rasp_mac;
}MYPROTO;

#define DISCOVER     0x1001
#define OFFER        0x1002
#define APPROVAL     0x1003
#define INITAP       0x1006
#define MYPROTOCOL   0x1010



void make_ethernet(struct ether_header *eth,unsigned char *ether_dhost,
		   unsigned char *ether_shost,u_int16_t ether_type);
void make_mydhcp(MYPROTO *myproto,char *sip,char *dip,u_short type);
void create_myprotocol(int soc,char *smac,char *dmac,char *sip,
		       char *dip,u_short type);
int  chkMyProtocol(u_char *data, char *smac, char *dmac, char *sip,
		  char *dip, u_short type, int size);
