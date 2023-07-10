// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>

#include <Shlwapi.h>
#include <psapi.h>


#pragma comment(lib, "Shlwapi.lib")


//-------------------------------------------------------------------------------------------------------------------------------------------


BOOL ExeDigitsInNameCheck() {

	CHAR	Path					[MAX_PATH * 3];
	CHAR	cName					[MAX_PATH];
	DWORD   dwNumberOfDigits		= NULL;

	// getting the current filename (with the full path)
	if (!GetModuleFileNameA(NULL, Path, MAX_PATH * 3)) {
		printf("\n\t[!] GetModuleFileNameA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	
	// to prevent a buffer overflow - getting the filename from the full path
	if (lstrlenA(PathFindFileNameA(Path)) < MAX_PATH)
		lstrcpyA(cName, PathFindFileNameA(Path));

	// counting number of digits
	for (int i = 0; i < lstrlenA(cName); i++){
		if (isdigit(cName[i]))
			dwNumberOfDigits++;
	}

	// max 3 digits allowed 
	if (dwNumberOfDigits > 3){
		return TRUE;
	}

	return FALSE;
}

//-------------------------------------------------------------------------------------------------------------------------------------------


BOOL IsVenvByHardwareCheck() {

	SYSTEM_INFO		SysInfo			= { 0 };
	MEMORYSTATUSEX	MemStatus		= { .dwLength = sizeof(MEMORYSTATUSEX) };
	HKEY			hKey			= NULL;
	DWORD			dwUsbNumber		= NULL;
	DWORD			dwRegErr		= NULL;

//	CPU CHECK
	GetSystemInfo(&SysInfo);

	// less than 2 processors
	if (SysInfo.dwNumberOfProcessors < 2){
		return TRUE;
	}
	
//	RAM CHECK
	if (!GlobalMemoryStatusEx(&MemStatus)) {
		printf("\n\t[!] GlobalMemoryStatusEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// less than 2 gb of ram
	if ((DWORD)MemStatus.ullTotalPhys < (DWORD)(2 * 1073741824)) {
		return TRUE;
	}

	
// NUMBER OF USB's EVER MOUNTED
	if ((dwRegErr = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Enum\\USBSTOR", NULL, KEY_READ, &hKey)) != ERROR_SUCCESS) {
		printf("\n\t[!] RegOpenKeyExA Failed With Error : %d | 0x%0.8X \n", dwRegErr, dwRegErr);
		return FALSE;
	}

	if ((dwRegErr = RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &dwUsbNumber, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) != ERROR_SUCCESS) {
		printf("\n\t[!] RegQueryInfoKeyA Failed With Error : %d | 0x%0.8X \n", dwRegErr, dwRegErr);
		return FALSE;
	}
	
	// less than 2 usb's ever mounted 
	if (dwUsbNumber < 2) {
		return TRUE;
	}
	
	RegCloseKey(hKey);

	
	return FALSE;
}



//-------------------------------------------------------------------------------------------------------------------------------------------


// the callback function called whenever 'EnumDisplayMonitors' detects an display
BOOL CALLBACK ResolutionCallback(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lpRect, LPARAM ldata) {
	
	int				X		= 0,
					Y		= 0;
	MONITORINFO		MI		= { .cbSize = sizeof(MONITORINFO) };

	if (!GetMonitorInfoW(hMonitor, &MI)) {
		printf("\n\t[!] GetMonitorInfoW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	// calculating the X coordinates of the desplay
	X = MI.rcMonitor.right - MI.rcMonitor.left;
	
	// calculating the Y coordinates of the desplay
	Y = MI.rcMonitor.top - MI.rcMonitor.bottom;

	// if numbers are in negative value, reverse them 
	if (X < 0)
		X = -X;
	if (Y < 0)
		Y = -Y;

	/*
	if not :
		-	1920x1080	-	1920x1200	-	1920x1600	-	1920x900
		-	2560x1080	-	2560x1200	-	2560x1600	-	1920x900
		-	1440x1080	-	1440x1200	-	1440x1600	-	1920x900
	*/
	
	if ((X != 1920 && X != 2560 && X != 1440) || (Y != 1080 && Y != 1200 && Y != 1600 && Y != 900))
		*((BOOL*)ldata) = TRUE;

	return TRUE;
}


BOOL CheckMachineResolution() {

	BOOL	SANDBOX		= FALSE;

	EnumDisplayMonitors(NULL, NULL, (MONITORENUMPROC)ResolutionCallback, (LPARAM)(&SANDBOX));
	
	return SANDBOX;
}


//-------------------------------------------------------------------------------------------------------------------------------------------

BOOL CheckMachineProcesses() {

	DWORD		adwProcesses		[1024];
	DWORD		dwReturnLen			= NULL,
				dwNmbrOfPids		= NULL;


	if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen)) {
		printf("\n\t[!] EnumProcesses Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	dwNmbrOfPids = dwReturnLen / sizeof(DWORD);

	if (dwNmbrOfPids < 50)	// less than 50 process, its a sandbox 
		return TRUE;

	return FALSE;
}

//-------------------------------------------------------------------------------------------------------------------------------------------


int main() {
	
	printf("[#] Press <Enter> To Start ... ");
	getchar();


//---------------------------------------------
//	tech 1 :

	printf("\n[#] Running ExeDigitsInNameCheck ... ");
	if (ExeDigitsInNameCheck())
		printf("<<!>> ExeDigitsInNameCheck Detected A Virtual Environment <<!>> \n");
	else
		printf("[+] DONE \n");

//---------------------------------------------
//	tech 2 :

	printf("\n[#] Running CheckMachineResolution ... ");
	if (CheckMachineResolution())
		printf("<<!>> CheckMachineResolution Detected A Virtual Environment <<!>> \n");
	else
		printf("[+] DONE \n");

//---------------------------------------------
//	tech 3 :

	printf("\n[#] Running IsVenvByHardwareCheck ... ");
	if (IsVenvByHardwareCheck())
		printf("<<!>> IsVenvByHardwareCheck Detected A Virtual Environment <<!>> \n");
	else
		printf("[+] DONE \n");

//---------------------------------------------
//	tech 4 :

	printf("\n[#] Running CheckMachineProcesses ... ");
	if (CheckMachineProcesses())
		printf("<<!>> CheckMachineProcesses Detected A Virtual Environment <<!>> \n");
	else
		printf("[+] DONE \n");

	printf("\n[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}

