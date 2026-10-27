int service_register();
void service_main(int argc, char *argv[]);
void service_controlhandler(DWORD request);
int service_install(int argc, char *argv[]);
int service_remove(void);
