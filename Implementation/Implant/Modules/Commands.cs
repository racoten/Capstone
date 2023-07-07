using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
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
            string result;
            switch (command)
            {
                case "cwd":
                    result = GetCurrentDir();
                    break;
                case "cd":
                    result = SetCurrentDir(args);
                    break;
                default:
                    result = "Command not found";
                    break;
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
