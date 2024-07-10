#include <Windows.h>
#include <stdio.h>

#include "Common.h"


// if injecting the dll into a cli process
// if not, then comment it:

#define TARGET_CLI_PROCESSES	

#ifndef TARGET_CLI_PROCESSES
#define TARGET_GUI_PROCESSES
#endif // !TARGET_CLI_PROCESSES




HANDLE		g_hConsole		= NULL;

// create a console screen to write to
HANDLE CreateOutputConsole() {

	if (g_hConsole != NULL){
		return g_hConsole;
	}

#ifdef TARGET_GUI_PROCESSES
	
	if (!FreeConsole()) {
		return NULL;
	}
	if (!AllocConsole()) {
		return NULL;
	}

#endif // TARGET_GUI_PROCESSES

	if ((g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE)) == NULL) {
		return NULL;
	}

	return g_hConsole;
}






VOID ReportError(LPCSTR lpFunctionName, DWORD dwError) {

	PRINT("[!] \"%s\" Failed With Error : %d \n", lpFunctionName, dwError);
	MessageBoxA(NULL, "", "", MB_OK);
}



