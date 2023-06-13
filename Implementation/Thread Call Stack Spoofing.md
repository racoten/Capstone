```cs
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ThreadStackSpoofing
{
    class Program
    {
        static void Main(string[] args)
        {
            var targetProcessName = "targetProcess.exe";
            var targetThreadId = 1234; // replace with the thread ID of the target process
            
            var targetProcess = Process.GetProcessesByName(targetProcessName)[0];
            var targetThread = targetProcess.Threads[targetThreadId];
            
            var context = new CONTEXT
            {
                ContextFlags = CONTEXT_FLAGS.CONTEXT_ALL,
            };
            
            GetThreadContext(targetThread.Handle, ref context);
            
            // modify the thread context as desired
            
            SetThreadContext(targetThread.Handle, ref context);
        }
        
        [DllImport("kernel32.dll")]
        public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);
        
        [DllImport("kernel32.dll")]
        public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);
        
        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT
        {
            public uint ContextFlags;
            public uint Dr0;
            public uint Dr1;
            public uint Dr2;
            public uint Dr3;
            public uint Dr6;
            public uint Dr7;
            public FLOATING_SAVE_AREA FloatSave;
            public uint SegGs;
            public uint SegFs;
            public uint SegEs;
            public uint SegDs;
            public uint Edi;
            public uint Esi;
            public uint Ebx;
            public uint Edx;
            public uint Ecx;
            public uint Eax;
            public uint Ebp;
            public uint Eip;
            public uint SegCs;
            public uint EFlags;
            public uint Esp;
            public uint SegSs;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] ExtendedRegisters;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        public struct FLOATING_SAVE_AREA
        {
            public uint ControlWord;
            public uint StatusWord;
            public uint TagWord;
            public uint ErrorOffset;
            public uint ErrorSelector;
            public uint DataOffset;
            public uint DataSelector;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;
            public uint Cr0NpxState;
        }
        
        public enum CONTEXT_FLAGS : uint
        {
            CONTEXT_AMD64 = 0x00100000,
            CONTEXT_CONTROL = CONTEXT_FLAGS.CONTEXT_AMD64 | 0x00000001,
            CONTEXT_INTEGER = CONTEXT_FLAGS.CONTEXT_AMD64 | 0x00000002,
            CONTEXT_SEGMENTS = CONTEXT_FLAGS.CONTEXT_AMD64 | 0x00000004,
            CONTEXT_FLOATING_POINT = CONTEXT_FLAGS.CONTEXT_AMD64 | 0x00000008,
            CONTEXT_DEBUG_REGISTERS = CONTEXT_FLAGS.CONTEXT_AMD64 | 0x00000010,
            CONTEXT_FULL = CONTEXT_FLAGS.CONTEXT_CONTROL | CONTEXT_FLAGS.CONTEXT_INTEGER | CONTEXT_FLAGS.CONTEXT_FLOATING_POINT,
            CONTEXT_FULL = CONTEXT_FLAGS.CONTEXT_CONTROL | CONTEXT_FLAGS.CONTEXT_INTEGER | CONTEXT_FLAGS.CONTEXT_FLOATING_POINT | CONTEXT_FLAGS.CONTEXT_SEGMENTS | CONTEXT_FLAGS.CONTEXT_DEBUG_REGISTERS,
        }
    }
}
```