#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "adiosdpi.h"
#include "service.h"

#define SERVICE_NAME "AdiosDPI"

static SERVICE_STATUS ServiceStatus;
static SERVICE_STATUS_HANDLE hStatus;
static int service_argc = 0;
static char **service_argv = NULL;

int service_register(int argc, char *argv[])
{
    int i, ret;
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)service_main},
        {NULL, NULL}
    };
    /*
     * Save argc & argv as service_main is called with different
     * arguments, which are passed from "start" command, not
     * from the program command line.
     * We don't need this behaviour.
     *
     * Note that if StartServiceCtrlDispatcher() succeedes
     * it does not return until the service is stopped,
     * so we should copy all arguments first and then
     * handle the failure.
     */
    if (!service_argc && !service_argv) {
        service_argc = argc;
        service_argv = calloc((size_t)(argc + 1), sizeof(void*));
        for (i = 0; i < argc; i++) {
            service_argv[i] = strdup(argv[i]);
        }
    }

    ret = StartServiceCtrlDispatcher(ServiceTable);

    if (service_argc && service_argv) {
        for (i = 0; i < service_argc; i++) {
            free(service_argv[i]);
        }
        free(service_argv);
    }

    return ret;
}

void service_main(int argc __attribute__((unused)),
                  char *argv[] __attribute__((unused)))
{
    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS; 
    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 1;
    ServiceStatus.dwWaitHint = 0;

    hStatus = RegisterServiceCtrlHandler(
        SERVICE_NAME,
        (LPHANDLER_FUNCTION)service_controlhandler);
    if (hStatus == (SERVICE_STATUS_HANDLE)0)
    {
        // Registering Control Handler failed
        return;
    }

    SetServiceStatus(hStatus, &ServiceStatus);

    // Calling main with saved argc & argv
    ServiceStatus.dwWin32ExitCode = (DWORD)main(service_argc, service_argv);
    ServiceStatus.dwCurrentState  = SERVICE_STOPPED;
    SetServiceStatus(hStatus, &ServiceStatus);
    return;
}

// Control handler function
void service_controlhandler(DWORD request)
{
    switch(request)
    {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            deinit_all();
            ServiceStatus.dwWin32ExitCode = 0;
            ServiceStatus.dwCurrentState  = SERVICE_STOPPED;
        default:
            break;
    }
    // Report current status
    SetServiceStatus(hStatus, &ServiceStatus);
    return;
}

/* Appends one argument to a command line, quoted if it has blanks. Returns 0 if it does not fit. */
static int append_arg(char *cmd, size_t size, const char *arg)
{
    int quote = !*arg || strchr(arg, ' ') || strchr(arg, '\t');
    size_t need = strlen(cmd) + strlen(arg) + (quote ? 2 : 0) + 2;

    if (strchr(arg, '"') || need > size || (quote && arg[strlen(arg) - 1] == '\\'))
        return 0;
    strcat(cmd, " ");
    if (quote)
        strcat(cmd, "\"");
    strcat(cmd, arg);
    if (quote)
        strcat(cmd, "\"");
    return 1;
}

int service_install(int argc, char *argv[])
{
    char path[MAX_PATH], cmd[4096];
    SERVICE_DESCRIPTION description = {"DPI circumvention (AdiosDPI)"};
    SC_HANDLE scm, svc;
    DWORD err;
    int i;

    if (!GetModuleFileName(NULL, path, sizeof(path))) {
        puts("Can't find the path of this program.");
        return 1;
    }
    snprintf(cmd, sizeof(cmd), "\"%s\"", path);
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--install") == 0)
            continue;
        if (!append_arg(cmd, sizeof(cmd), argv[i])) {
            printf("Can't pass the argument \"%s\" to the service.\n", argv[i]);
            return 1;
        }
    }

    scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        printf("Can't open the service manager (error %lu). Run as administrator.\n", GetLastError());
        return 1;
    }
    svc = CreateService(scm, SERVICE_NAME, SERVICE_NAME, SERVICE_ALL_ACCESS,
                        SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                        SERVICE_ERROR_NORMAL, cmd, NULL, NULL, NULL, NULL, NULL);
    if (!svc) {
        err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS)
            puts("The AdiosDPI service is already installed. Run --remove first.");
        else
            printf("Can't create the service (error %lu).\n", err);
        CloseServiceHandle(scm);
        return 1;
    }
    ChangeServiceConfig2(svc, SERVICE_CONFIG_DESCRIPTION, &description);
    if (StartService(svc, 0, NULL))
        puts("The AdiosDPI service is installed and running. It starts with Windows.");
    else
        printf("The AdiosDPI service is installed, but it did not start (error %lu).\n", GetLastError());
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

int service_remove(void)
{
    SERVICE_STATUS status;
    SC_HANDLE scm, svc;
    DWORD err;
    int i, ret = 0;

    scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        printf("Can't open the service manager (error %lu). Run as administrator.\n", GetLastError());
        return 1;
    }
    svc = OpenService(scm, SERVICE_NAME, DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!svc) {
        err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST)
            puts("The AdiosDPI service is not installed.");
        else
            printf("Can't open the service (error %lu).\n", err);
        CloseServiceHandle(scm);
        return err == ERROR_SERVICE_DOES_NOT_EXIST ? 0 : 1;
    }
    ControlService(svc, SERVICE_CONTROL_STOP, &status);
    for (i = 0; i < 50 && QueryServiceStatus(svc, &status) &&
                status.dwCurrentState != SERVICE_STOPPED; i++)
        Sleep(200);
    if (DeleteService(svc)) {
        puts("The AdiosDPI service is stopped and removed.");
    }
    else {
        printf("Can't remove the service (error %lu).\n", GetLastError());
        ret = 1;
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ret;
}
