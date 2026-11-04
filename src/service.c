#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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
            /* service_main() reports SERVICE_STOPPED once main() has returned. */
            shutdown_all();
            ServiceStatus.dwWin32ExitCode = 0;
            ServiceStatus.dwCurrentState  = SERVICE_STOP_PENDING;
            ServiceStatus.dwWaitHint      = 10000;
        default:
            break;
    }
    // Report current status
    SetServiceStatus(hStatus, &ServiceStatus);
    return;
}

#define INSTALL_DIR_NAME "AdiosDPI"

/*
 * The service runs as SYSTEM, so it must start from a folder that only administrators
 * can write to (an unzipped download is usually writable by every user, who could then
 * swap the exe). Program Files is that folder.
 */
static int install_dir(char *dir, size_t size)
{
    const char *programs = getenv("ProgramW6432");

    if (!programs)
        programs = getenv("ProgramFiles");
    if (!programs)
        return 0;
    snprintf(dir, size, "%s\\" INSTALL_DIR_NAME, programs);
    return 1;
}

/* Copies this program and the WinDivert files next to it into dir; the new exe path goes to installed. */
static int copy_files(const char *exe, const char *dir, char *installed, size_t size)
{
    static const char *patterns[] = {"WinDivert*.dll", "WinDivert*.sys"};
    char folder[MAX_PATH], pattern[MAX_PATH], src[MAX_PATH], dst[MAX_PATH];
    const char *name = strrchr(exe, '\\');
    int drivers = 0;
    size_t p;

    if (!name)
        return 0;
    snprintf(installed, size, "%s\\%s", dir, name + 1);
    if (_stricmp(exe, installed) == 0)
        return 1;                       /* already running from the install folder */
    snprintf(folder, sizeof(folder), "%.*s", (int)(name - exe), exe);
    CreateDirectory(dir, NULL);
    if (!CopyFile(exe, installed, FALSE))
        return 0;
    for (p = 0; p < sizeof(patterns) / sizeof(*patterns); p++) {
        WIN32_FIND_DATA fd;
        HANDLE find;

        snprintf(pattern, sizeof(pattern), "%s\\%s", folder, patterns[p]);
        find = FindFirstFile(pattern, &fd);
        if (find == INVALID_HANDLE_VALUE)
            continue;
        do {
            snprintf(src, sizeof(src), "%s\\%s", folder, fd.cFileName);
            snprintf(dst, sizeof(dst), "%s\\%s", dir, fd.cFileName);
            if (!CopyFile(src, dst, FALSE)) {
                FindClose(find);
                return 0;
            }
            if (p == 1)
                drivers++;
        } while (FindNextFile(find, &fd));
        FindClose(find);
    }
    if (!drivers) {
        puts("The WinDivert driver file (WinDivert64.sys) was not found next to the program.");
        return 0;
    }
    printf("Copied the program to %s\n", dir);
    return 1;
}

/* Deletes what copy_files() put in the install folder. Returns 1 when nothing is left. */
static int remove_files(void)
{
    char dir[MAX_PATH], pattern[MAX_PATH], file[MAX_PATH], self[MAX_PATH];
    WIN32_FIND_DATA fd;
    HANDLE find, driver_manager, driver;
    SERVICE_STATUS status;
    int left = 0, tries;

    if (!install_dir(dir, sizeof(dir)))
        return 1;
    GetModuleFileName(NULL, self, sizeof(self));

    /* The driver stays loaded after its last user is gone and keeps its file locked. */
    driver_manager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (driver_manager) {
        driver = OpenService(driver_manager, "WinDivert", SERVICE_STOP);
        if (driver) {
            ControlService(driver, SERVICE_CONTROL_STOP, &status);
            CloseServiceHandle(driver);
        }
        CloseServiceHandle(driver_manager);
        Sleep(500);
    }

    snprintf(pattern, sizeof(pattern), "%s\\*", dir);
    find = FindFirstFile(pattern, &fd);
    if (find == INVALID_HANDLE_VALUE)
        return 1;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;
        snprintf(file, sizeof(file), "%s\\%s", dir, fd.cFileName);
        if (_stricmp(file, self) == 0) {
            left = 1;                   /* can't delete the program that is running */
            continue;
        }
        for (tries = 0; tries < 5 && !DeleteFile(file); tries++)
            Sleep(200);
        if (tries == 5)
            left = 1;
    } while (FindNextFile(find, &fd));
    FindClose(find);
    if (!left)
        RemoveDirectory(dir);
    return !left;
}

/* Is argv[i] a file name the service will have to open? It starts in the System32 folder. */
static int is_file_arg(char *argv[], int i)
{
    return strcmp(argv[i - 1], "--blacklist") == 0 || strncmp(argv[i], "--blacklist=", 12) == 0;
}

/* Turns the file name in arg (or in --blacklist=name) into a full path to a file that exists. */
static int resolve_file_arg(const char *arg, char *out, size_t size)
{
    const char *prefix = strncmp(arg, "--blacklist=", 12) == 0 ? "--blacklist=" : "";
    const char *name = arg + strlen(prefix);
    char full[MAX_PATH];

    if (!GetFullPathName(name, sizeof(full), full, NULL) ||
        GetFileAttributes(full) == INVALID_FILE_ATTRIBUTES) {
        printf("Can't find the file \"%s\".\n", name);
        return 0;
    }
    snprintf(out, size, "%s%s", prefix, full);
    return 1;
}

/* Appends one argument to a command line, quoted if it has blanks. Returns 0 if it does not fit. */
static int append_arg(char *cmd, size_t size, const char *arg)
{
    int quote = !*arg || strchr(arg, ' ') || strchr(arg, '\t');
    size_t need = strlen(cmd) + strlen(arg) + (quote ? 2 : 0) + 2;

    if (strchr(arg, '"') || need > size || (quote && *arg && arg[strlen(arg) - 1] == '\\'))
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
    char path[MAX_PATH], dir[MAX_PATH], installed[MAX_PATH], cmd[4096], full[4096 + MAX_PATH];
    SERVICE_DESCRIPTION description = {"DPI circumvention (AdiosDPI)"};
    SC_HANDLE scm, svc;
    DWORD err;
    int i;

    if (!GetModuleFileName(NULL, path, sizeof(path))) {
        puts("Can't find the path of this program.");
        return 1;
    }
    cmd[0] = '\0';
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--install") == 0)
            continue;
        const char *arg = argv[i];
        char resolved[MAX_PATH + 16];

        if (is_file_arg(argv, i)) {
            if (!resolve_file_arg(argv[i], resolved, sizeof(resolved)))
                return 1;
            arg = resolved;
        }
        if (!append_arg(cmd, sizeof(cmd), arg)) {
            printf("Can't pass the argument \"%s\" to the service.\n", argv[i]);
            return 1;
        }
    }

    /* Copy only after every argument is known to be good, so a failed install leaves nothing behind. */
    if (!install_dir(dir, sizeof(dir)) || !copy_files(path, dir, installed, sizeof(installed))) {
        puts("Can't copy the program to the install folder (run as administrator).");
        return 1;
    }
    snprintf(full, sizeof(full), "\"%s\"%s", installed, cmd);

    scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        printf("Can't open the service manager (error %lu). Run as administrator.\n", GetLastError());
        return 1;
    }
    svc = CreateService(scm, SERVICE_NAME, SERVICE_NAME, SERVICE_ALL_ACCESS,
                        SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                        SERVICE_ERROR_NORMAL, full, NULL, NULL, NULL, NULL, NULL);
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
        if (!remove_files())
            puts("Some files stay in the install folder; delete it after a restart.");
    }
    else {
        printf("Can't remove the service (error %lu).\n", GetLastError());
        ret = 1;
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ret;
}

/* Prints the state of the service. Stores the process id of a running service in *pid. */
int service_status(DWORD *pid)
{
    SERVICE_STATUS_PROCESS status;
    QUERY_SERVICE_CONFIG *config = NULL;
    SC_HANDLE scm, svc;
    DWORD needed = 0;
    const char *state;

    *pid = 0;
    scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    svc = scm ? OpenService(scm, SERVICE_NAME, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS) : NULL;
    if (!svc) {
        puts("Service  : not installed (--install adds it)");
        if (scm)
            CloseServiceHandle(scm);
        return 0;
    }
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(status), &needed)) {
        state = status.dwCurrentState == SERVICE_RUNNING ? "running" :
                status.dwCurrentState == SERVICE_STOPPED ? "stopped" : "changing state";
        if (status.dwCurrentState == SERVICE_RUNNING)
            *pid = status.dwProcessId;
    }
    else {
        state = "state unknown";
    }
    QueryServiceConfig(svc, NULL, 0, &needed);
    if (needed && (config = malloc(needed)) != NULL && QueryServiceConfig(svc, config, needed, &needed))
        printf("Service  : %s, %s\n  command: %s\n", state,
               config->dwStartType == SERVICE_AUTO_START ? "starts with Windows" : "does not start with Windows",
               config->lpBinaryPathName);
    else
        printf("Service  : %s\n", state);
    free(config);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}
