// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>


/*

examples on the 'ftMinutes' parameter :
		- 1.5 ; minute and half
		- 0.5 ; half a minute
		-  1  ; minute
		- 0.1 ; 6 seconds
		- 0.3 ; 18 seconds
		
*/

//----------------------------------------------------------------------------------------------------------------------------------------------------------
// tech 1: using NtDelayExecution


typedef NTSTATUS (NTAPI *fnNtDelayExecution)(
	BOOLEAN              Alertable,
	PLARGE_INTEGER       DelayInterval
);

BOOL DelayExecutionVia_NtDE(FLOAT ftMinutes) {

	// converting minutes to milliseconds
	DWORD				dwMilliSeconds		= ftMinutes * 60000;
	LARGE_INTEGER		DelayInterval		= { 0 };
	LONGLONG			Delay				= NULL;
	NTSTATUS			STATUS				= NULL;
	fnNtDelayExecution	pNtDelayExecution	= (fnNtDelayExecution)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtDelayExecution");
	DWORD				_T0					= NULL, 
						_T1					= NULL;

	printf("[i] Delaying Execution Using \"NtDelayExecution\" For %0.3d Seconds", (dwMilliSeconds / 1000));
	
	// converting from milliseconds to the 100-nanosecond - negative time interval
	Delay = dwMilliSeconds * 10000;
	DelayInterval.QuadPart = - Delay;

	_T0 = GetTickCount64();

	// sleeping for 'dwMilliSeconds' ms 
	if ((STATUS = pNtDelayExecution(FALSE, &DelayInterval)) != 0x00 && STATUS != STATUS_TIMEOUT) {
		printf("[!] NtDelayExecution Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	
	_T1 = GetTickCount64();

	// slept for at least 'dwMilliSeconds' ms, then 'DelayExecutionVia_NtDE' succeeded, otherwize it failed
	if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
		return FALSE;

	printf("\n\t>> _T1 - _T0 = %d \n", (DWORD)(_T1 - _T0));

	printf("[+] DONE \n");

	return TRUE;
}


//----------------------------------------------------------------------------------------------------------------------------------------------------------
// tech 2: using WaitForSingleObject


BOOL DelayExecutionVia_WFSO(FLOAT ftMinutes) {

	// converting minutes to milliseconds
	DWORD	dwMilliSeconds	= ftMinutes * 60000;
	HANDLE	hEvent			= CreateEvent(NULL, NULL, NULL, NULL);
	DWORD	_T0				= NULL,
			_T1				= NULL;


	printf("[i] Delaying Execution Using \"WaitForSingleObject\" For %0.3d Seconds", (dwMilliSeconds / 1000));
	
	_T0 = GetTickCount64();

	// sleeping for 'dwMilliSeconds' ms 
	if (WaitForSingleObject(hEvent, dwMilliSeconds) == WAIT_FAILED) {
		printf("[!] WaitForSingleObject Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	_T1 = GetTickCount64();

	// slept for at least 'dwMilliSeconds' ms, then 'DelayExecutionVia_WFSO' succeeded, otherwize it failed
	if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
		return FALSE;

	printf("\n\t>> _T1 - _T0 = %d \n", (DWORD)(_T1 - _T0));

	printf("[+] DONE \n");

	CloseHandle(hEvent);

	return TRUE;
}


//----------------------------------------------------------------------------------------------------------------------------------------------------------
// tech 3: using MsgWaitForMultipleObjectsEx


BOOL DelayExecutionVia_MWFMOEx(FLOAT ftMinutes) {

	// converting minutes to milliseconds
	DWORD	dwMilliSeconds	= ftMinutes * 60000;
	HANDLE	hEvent			= CreateEvent(NULL, NULL, NULL, NULL);
	DWORD	_T0				= NULL,
			_T1				= NULL;


	printf("[i] Delaying Execution Using \"MsgWaitForMultipleObjectsEx\" For %0.3d Seconds", (dwMilliSeconds / 1000));
	
	_T0 = GetTickCount64();

	// sleeping for 'dwMilliSeconds' ms 
	if (MsgWaitForMultipleObjectsEx(1, &hEvent, dwMilliSeconds, QS_HOTKEY, NULL) == WAIT_FAILED) {
		printf("[!] MsgWaitForMultipleObjectsEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	_T1 = GetTickCount64();

	// slept for at least 'dwMilliSeconds' ms, then 'DelayExecutionVia_MWFMOEx' succeeded, otherwize it failed
	if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
		return FALSE;

	printf("\n\t>> _T1 - _T0 = %d \n", (DWORD)(_T1 - _T0));

	printf("[+] DONE \n");

	CloseHandle(hEvent);

	return TRUE;
}


//----------------------------------------------------------------------------------------------------------------------------------------------------------
// tech 4: using NtWaitForSingleObject


typedef NTSTATUS (NTAPI* fnNtWaitForSingleObject)(
	HANDLE         Handle,
	BOOLEAN        Alertable,
	PLARGE_INTEGER Timeout
);

BOOL DelayExecutionVia_NtWFSO(FLOAT ftMinutes) {

	// converting minutes to milliseconds
	DWORD					dwMilliSeconds			= ftMinutes * 60000;
	HANDLE					hEvent					= CreateEvent(NULL, NULL, NULL, NULL);
	LONGLONG				Delay					= NULL;
	NTSTATUS				STATUS					= NULL;
	LARGE_INTEGER			DelayInterval			= { 0 };
	fnNtWaitForSingleObject	pNtWaitForSingleObject	= (fnNtWaitForSingleObject)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtWaitForSingleObject");
	DWORD					_T0						= NULL,
							_T1						= NULL;


	printf("[i] Delaying Execution Using \"NtWaitForSingleObject\" For %0.3d Seconds", (dwMilliSeconds / 1000));
	
	// converting from milliseconds to the 100-nanosecond - negative time interval
	Delay = dwMilliSeconds * 10000;
	DelayInterval.QuadPart = - Delay;

	_T0 = GetTickCount64();

	// sleeping for 'dwMilliSeconds' ms 
	if ((STATUS = pNtWaitForSingleObject(hEvent, FALSE, &DelayInterval)) != 0x00 && STATUS != STATUS_TIMEOUT) {
		printf("[!] NtWaitForSingleObject Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	_T1 = GetTickCount64();
	
	// slept for at least 'dwMilliSeconds' ms, then 'DelayExecutionVia_NtWFSO' succeeded, otherwize it failed
	if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
		return FALSE;

	printf("\n\t>> _T1 - _T0 = %d \n", (DWORD)(_T1 - _T0));

	printf("[+] DONE \n");

	CloseHandle(hEvent);
	
	return TRUE;
}


//----------------------------------------------------------------------------------------------------------------------------------------------------------



int main() {
	
//-----------------------------------
// tech 1:


	printf("-------------------------------------------------------------------\n");
	if (!DelayExecutionVia_NtDE(0.1)) {
		printf("\n\t\t<<!>> DelayExecutionVia_NtDE FAILED <<!>>\n");
	}
	
//-----------------------------------
// tech 2:

	printf("-------------------------------------------------------------------\n");
	if (!DelayExecutionVia_WFSO(0.1)) {
		printf("\n\t\t<<!>> DelayExecutionVia_WFSO FAILED <<!>>\n");
	}

//-----------------------------------
// tech 3:

	printf("-------------------------------------------------------------------\n");
	if (!DelayExecutionVia_MWFMOEx(0.1)) {
		printf("\n\t\t<<!>> DelayExecutionVia_MWFMOEx FAILED <<!>>\n");
	}

//-----------------------------------
// tech 4:

	printf("-------------------------------------------------------------------\n");
	if (!DelayExecutionVia_NtWFSO(0.1)) {
		printf("\n\t\t<<!>> DelayExecutionVia_NtWFSO FAILED <<!>>\n");
	}

//-----------------------------------



	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}





