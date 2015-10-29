typedef struct {
  char name[SIZE_NAME];
  int  soc;
  char macaddr[SIZE_MAC];
  char ipaddr[SIZE_IP];
}Device;



void  Device_init(Device *this, const char *name);
void  Device_setIpAddr(Device *this, char *ipaddr);
char *Device_getName(Device *this);
int   Device_getSoc(Device *this);
char *Device_getIpAddr(Device *this);
char *Device_getMacAddr(Device *this);
void  Device_printInfo(Device *this);
void  Device_del(Device *this);
void  p_func_setSocket(Device *this);
void  p_func_setMacAddr(Device *this);
void  p_func_setIpAddr(Device *this);
void  p_func_confIpAddr(char *name, char *ip);
struct ifreq *p_func_getDeviceInfo(char *name, struct ifreq *ifreq, int flavor);
