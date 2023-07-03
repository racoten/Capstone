namespace CapstoneInterface
{
    partial class Dashboard
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Dashboard));
            this.fileTab = new System.Windows.Forms.TabControl();
            this.tabPage1 = new System.Windows.Forms.TabPage();
            this.richTextBox1 = new System.Windows.Forms.RichTextBox();
            this.btnEditImplant = new System.Windows.Forms.Button();
            this.tabPage2 = new System.Windows.Forms.TabPage();
            this.txtConsoleOutput = new System.Windows.Forms.RichTextBox();
            this.button1 = new System.Windows.Forms.Button();
            this.dataGridView1 = new System.Windows.Forms.DataGridView();
            this.btnProcesses = new System.Windows.Forms.Button();
            this.btnConsole = new System.Windows.Forms.Button();
            this.btnRunCommand = new System.Windows.Forms.Button();
            this.txtCommand = new System.Windows.Forms.TextBox();
            this.tabPage3 = new System.Windows.Forms.TabPage();
            this.btnGetData = new System.Windows.Forms.Button();
            this.dataGridView2 = new System.Windows.Forms.DataGridView();
            this.tabPage4 = new System.Windows.Forms.TabPage();
            this.btnGenerateImplantShellcode = new System.Windows.Forms.Button();
            this.txtPayloadGen = new System.Windows.Forms.TextBox();
            this.btnBundlePayload = new System.Windows.Forms.Button();
            this.btnPayloadGenerate = new System.Windows.Forms.Button();
            this.tabChat = new System.Windows.Forms.TabPage();
            this.textBox3 = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.btnSendMessage = new System.Windows.Forms.Button();
            this.txtMessageInput = new System.Windows.Forms.TextBox();
            this.lblMessage = new System.Windows.Forms.Label();
            this.txtMessagesBox = new System.Windows.Forms.TextBox();
            this.label3 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.lblOperator = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.btnSignOut = new System.Windows.Forms.Button();
            this.label5 = new System.Windows.Forms.Label();
            this.lblServer = new System.Windows.Forms.Label();
            this.fileTab.SuspendLayout();
            this.tabPage1.SuspendLayout();
            this.tabPage2.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.dataGridView1)).BeginInit();
            this.tabPage3.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.dataGridView2)).BeginInit();
            this.tabPage4.SuspendLayout();
            this.tabChat.SuspendLayout();
            this.SuspendLayout();
            // 
            // fileTab
            // 
            this.fileTab.Controls.Add(this.tabPage1);
            this.fileTab.Controls.Add(this.tabPage2);
            this.fileTab.Controls.Add(this.tabPage3);
            this.fileTab.Controls.Add(this.tabPage4);
            this.fileTab.Controls.Add(this.tabChat);
            this.fileTab.Location = new System.Drawing.Point(17, 37);
            this.fileTab.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.fileTab.Name = "fileTab";
            this.fileTab.SelectedIndex = 0;
            this.fileTab.Size = new System.Drawing.Size(1492, 1029);
            this.fileTab.TabIndex = 0;
            // 
            // tabPage1
            // 
            this.tabPage1.Controls.Add(this.richTextBox1);
            this.tabPage1.Controls.Add(this.btnEditImplant);
            this.tabPage1.Location = new System.Drawing.Point(4, 25);
            this.tabPage1.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabPage1.Name = "tabPage1";
            this.tabPage1.Padding = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabPage1.Size = new System.Drawing.Size(1484, 1000);
            this.tabPage1.TabIndex = 0;
            this.tabPage1.Text = "File";
            this.tabPage1.UseVisualStyleBackColor = true;
            // 
            // richTextBox1
            // 
            this.richTextBox1.Location = new System.Drawing.Point(8, 63);
            this.richTextBox1.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.richTextBox1.Name = "richTextBox1";
            this.richTextBox1.Size = new System.Drawing.Size(1464, 928);
            this.richTextBox1.TabIndex = 2;
            this.richTextBox1.Text = "";
            // 
            // btnEditImplant
            // 
            this.btnEditImplant.Location = new System.Drawing.Point(8, 27);
            this.btnEditImplant.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnEditImplant.Name = "btnEditImplant";
            this.btnEditImplant.Size = new System.Drawing.Size(100, 28);
            this.btnEditImplant.TabIndex = 1;
            this.btnEditImplant.Text = "Edit";
            this.btnEditImplant.UseVisualStyleBackColor = true;
            this.btnEditImplant.Click += new System.EventHandler(this.btnEditImplant_Click);
            // 
            // tabPage2
            // 
            this.tabPage2.Controls.Add(this.txtConsoleOutput);
            this.tabPage2.Controls.Add(this.button1);
            this.tabPage2.Controls.Add(this.dataGridView1);
            this.tabPage2.Controls.Add(this.btnProcesses);
            this.tabPage2.Controls.Add(this.btnConsole);
            this.tabPage2.Controls.Add(this.btnRunCommand);
            this.tabPage2.Controls.Add(this.txtCommand);
            this.tabPage2.Location = new System.Drawing.Point(4, 25);
            this.tabPage2.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabPage2.Name = "tabPage2";
            this.tabPage2.Padding = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabPage2.Size = new System.Drawing.Size(1484, 1000);
            this.tabPage2.TabIndex = 1;
            this.tabPage2.Text = "Server";
            this.tabPage2.UseVisualStyleBackColor = true;
            // 
            // txtConsoleOutput
            // 
            this.txtConsoleOutput.BackColor = System.Drawing.Color.Black;
            this.txtConsoleOutput.Font = new System.Drawing.Font("Consolas", 10F);
            this.txtConsoleOutput.ForeColor = System.Drawing.Color.White;
            this.txtConsoleOutput.Location = new System.Drawing.Point(9, 121);
            this.txtConsoleOutput.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.txtConsoleOutput.Name = "txtConsoleOutput";
            this.txtConsoleOutput.Size = new System.Drawing.Size(1463, 580);
            this.txtConsoleOutput.TabIndex = 9;
            this.txtConsoleOutput.Text = "";
            // 
            // button1
            // 
            this.button1.Location = new System.Drawing.Point(9, 709);
            this.button1.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(100, 28);
            this.button1.TabIndex = 8;
            this.button1.Text = "Add Info";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // dataGridView1
            // 
            this.dataGridView1.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.dataGridView1.Location = new System.Drawing.Point(9, 745);
            this.dataGridView1.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.dataGridView1.Name = "dataGridView1";
            this.dataGridView1.Size = new System.Drawing.Size(1464, 245);
            this.dataGridView1.TabIndex = 7;
            this.dataGridView1.CellContentClick += new System.Windows.Forms.DataGridViewCellEventHandler(this.dataGridView1_CellContentClick);
            // 
            // btnProcesses
            // 
            this.btnProcesses.Location = new System.Drawing.Point(115, 84);
            this.btnProcesses.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnProcesses.Name = "btnProcesses";
            this.btnProcesses.Size = new System.Drawing.Size(100, 28);
            this.btnProcesses.TabIndex = 5;
            this.btnProcesses.Text = "Process";
            this.btnProcesses.UseVisualStyleBackColor = true;
            this.btnProcesses.Click += new System.EventHandler(this.btnProcesses_Click);
            // 
            // btnConsole
            // 
            this.btnConsole.Location = new System.Drawing.Point(7, 84);
            this.btnConsole.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnConsole.Name = "btnConsole";
            this.btnConsole.Size = new System.Drawing.Size(100, 28);
            this.btnConsole.TabIndex = 4;
            this.btnConsole.Text = "Console";
            this.btnConsole.UseVisualStyleBackColor = true;
            this.btnConsole.Click += new System.EventHandler(this.btnConsole_Click);
            // 
            // btnRunCommand
            // 
            this.btnRunCommand.Location = new System.Drawing.Point(525, 4);
            this.btnRunCommand.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnRunCommand.Name = "btnRunCommand";
            this.btnRunCommand.Size = new System.Drawing.Size(107, 46);
            this.btnRunCommand.TabIndex = 3;
            this.btnRunCommand.Text = "Run";
            this.btnRunCommand.UseVisualStyleBackColor = true;
            this.btnRunCommand.Click += new System.EventHandler(this.btnRunCommand_Click);
            // 
            // txtCommand
            // 
            this.txtCommand.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txtCommand.Location = new System.Drawing.Point(7, 9);
            this.txtCommand.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.txtCommand.Multiline = true;
            this.txtCommand.Name = "txtCommand";
            this.txtCommand.Size = new System.Drawing.Size(455, 40);
            this.txtCommand.TabIndex = 2;
            // 
            // tabPage3
            // 
            this.tabPage3.Controls.Add(this.btnGetData);
            this.tabPage3.Controls.Add(this.dataGridView2);
            this.tabPage3.Location = new System.Drawing.Point(4, 25);
            this.tabPage3.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabPage3.Name = "tabPage3";
            this.tabPage3.Padding = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabPage3.Size = new System.Drawing.Size(1484, 1000);
            this.tabPage3.TabIndex = 2;
            this.tabPage3.Text = "Action";
            this.tabPage3.UseVisualStyleBackColor = true;
            // 
            // btnGetData
            // 
            this.btnGetData.Location = new System.Drawing.Point(711, 38);
            this.btnGetData.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnGetData.Name = "btnGetData";
            this.btnGetData.Size = new System.Drawing.Size(100, 28);
            this.btnGetData.TabIndex = 1;
            this.btnGetData.Text = "Get Data";
            this.btnGetData.UseVisualStyleBackColor = true;
            this.btnGetData.Click += new System.EventHandler(this.btnGetData_ClickAsync);
            // 
            // dataGridView2
            // 
            this.dataGridView2.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.dataGridView2.Location = new System.Drawing.Point(9, 92);
            this.dataGridView2.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.dataGridView2.Name = "dataGridView2";
            this.dataGridView2.Size = new System.Drawing.Size(1448, 822);
            this.dataGridView2.TabIndex = 0;
            // 
            // tabPage4
            // 
            this.tabPage4.Controls.Add(this.btnGenerateImplantShellcode);
            this.tabPage4.Controls.Add(this.txtPayloadGen);
            this.tabPage4.Controls.Add(this.btnBundlePayload);
            this.tabPage4.Controls.Add(this.btnPayloadGenerate);
            this.tabPage4.Location = new System.Drawing.Point(4, 25);
            this.tabPage4.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabPage4.Name = "tabPage4";
            this.tabPage4.Padding = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabPage4.Size = new System.Drawing.Size(1484, 1000);
            this.tabPage4.TabIndex = 3;
            this.tabPage4.Text = "Payloads";
            this.tabPage4.UseVisualStyleBackColor = true;
            // 
            // btnGenerateImplantShellcode
            // 
            this.btnGenerateImplantShellcode.Location = new System.Drawing.Point(776, 7);
            this.btnGenerateImplantShellcode.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnGenerateImplantShellcode.Name = "btnGenerateImplantShellcode";
            this.btnGenerateImplantShellcode.Size = new System.Drawing.Size(201, 30);
            this.btnGenerateImplantShellcode.TabIndex = 3;
            this.btnGenerateImplantShellcode.Text = "Generate Implant Shellcode";
            this.btnGenerateImplantShellcode.UseVisualStyleBackColor = true;
            this.btnGenerateImplantShellcode.Click += new System.EventHandler(this.btnGenerateImplantShellcode_Click);
            // 
            // txtPayloadGen
            // 
            this.txtPayloadGen.Location = new System.Drawing.Point(13, 58);
            this.txtPayloadGen.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.txtPayloadGen.Multiline = true;
            this.txtPayloadGen.Name = "txtPayloadGen";
            this.txtPayloadGen.Size = new System.Drawing.Size(1459, 954);
            this.txtPayloadGen.TabIndex = 2;
            // 
            // btnBundlePayload
            // 
            this.btnBundlePayload.Location = new System.Drawing.Point(641, 7);
            this.btnBundlePayload.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnBundlePayload.Name = "btnBundlePayload";
            this.btnBundlePayload.Size = new System.Drawing.Size(125, 30);
            this.btnBundlePayload.TabIndex = 1;
            this.btnBundlePayload.Text = "Bundle Payload";
            this.btnBundlePayload.UseVisualStyleBackColor = true;
            this.btnBundlePayload.Click += new System.EventHandler(this.btnBundlePayload_Click);
            // 
            // btnPayloadGenerate
            // 
            this.btnPayloadGenerate.Location = new System.Drawing.Point(463, 9);
            this.btnPayloadGenerate.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnPayloadGenerate.Name = "btnPayloadGenerate";
            this.btnPayloadGenerate.Size = new System.Drawing.Size(169, 28);
            this.btnPayloadGenerate.TabIndex = 0;
            this.btnPayloadGenerate.Text = "Generate Payload Stub";
            this.btnPayloadGenerate.UseVisualStyleBackColor = true;
            this.btnPayloadGenerate.Click += new System.EventHandler(this.btnPayloadGenerate_Click);
            // 
            // tabChat
            // 
            this.tabChat.Controls.Add(this.textBox3);
            this.tabChat.Controls.Add(this.label4);
            this.tabChat.Controls.Add(this.btnSendMessage);
            this.tabChat.Controls.Add(this.txtMessageInput);
            this.tabChat.Controls.Add(this.lblMessage);
            this.tabChat.Controls.Add(this.txtMessagesBox);
            this.tabChat.Controls.Add(this.label3);
            this.tabChat.Location = new System.Drawing.Point(4, 25);
            this.tabChat.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabChat.Name = "tabChat";
            this.tabChat.Padding = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.tabChat.Size = new System.Drawing.Size(1484, 1000);
            this.tabChat.TabIndex = 4;
            this.tabChat.Text = "Chat";
            this.tabChat.UseVisualStyleBackColor = true;
            // 
            // textBox3
            // 
            this.textBox3.BackColor = System.Drawing.SystemColors.InactiveCaption;
            this.textBox3.Font = new System.Drawing.Font("MS UI Gothic", 12F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.textBox3.ForeColor = System.Drawing.SystemColors.MenuHighlight;
            this.textBox3.Location = new System.Drawing.Point(988, 167);
            this.textBox3.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.textBox3.Multiline = true;
            this.textBox3.Name = "textBox3";
            this.textBox3.Size = new System.Drawing.Size(361, 821);
            this.textBox3.TabIndex = 6;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Font = new System.Drawing.Font("Consolas", 12F, ((System.Drawing.FontStyle)((System.Drawing.FontStyle.Bold | System.Drawing.FontStyle.Italic))), System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label4.Location = new System.Drawing.Point(1089, 122);
            this.label4.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(117, 19);
            this.label4.TabIndex = 5;
            this.label4.Text = "Users Online";
            // 
            // btnSendMessage
            // 
            this.btnSendMessage.Location = new System.Drawing.Point(585, 122);
            this.btnSendMessage.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnSendMessage.Name = "btnSendMessage";
            this.btnSendMessage.Size = new System.Drawing.Size(55, 28);
            this.btnSendMessage.TabIndex = 4;
            this.btnSendMessage.Text = "Send";
            this.btnSendMessage.UseVisualStyleBackColor = true;
            this.btnSendMessage.Click += new System.EventHandler(this.btnSendMessage_Click);
            // 
            // txtMessageInput
            // 
            this.txtMessageInput.Location = new System.Drawing.Point(125, 123);
            this.txtMessageInput.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.txtMessageInput.Multiline = true;
            this.txtMessageInput.Name = "txtMessageInput";
            this.txtMessageInput.Size = new System.Drawing.Size(451, 24);
            this.txtMessageInput.TabIndex = 3;
            // 
            // lblMessage
            // 
            this.lblMessage.AutoSize = true;
            this.lblMessage.Font = new System.Drawing.Font("Consolas", 12F, ((System.Drawing.FontStyle)((System.Drawing.FontStyle.Bold | System.Drawing.FontStyle.Italic))), System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblMessage.Location = new System.Drawing.Point(9, 122);
            this.lblMessage.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.lblMessage.Name = "lblMessage";
            this.lblMessage.Size = new System.Drawing.Size(81, 19);
            this.lblMessage.TabIndex = 2;
            this.lblMessage.Text = "Message:";
            // 
            // txtMessagesBox
            // 
            this.txtMessagesBox.BackColor = System.Drawing.SystemColors.InfoText;
            this.txtMessagesBox.Font = new System.Drawing.Font("MS UI Gothic", 12F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txtMessagesBox.ForeColor = System.Drawing.Color.Lime;
            this.txtMessagesBox.Location = new System.Drawing.Point(4, 167);
            this.txtMessagesBox.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.txtMessagesBox.Multiline = true;
            this.txtMessagesBox.Name = "txtMessagesBox";
            this.txtMessagesBox.Size = new System.Drawing.Size(759, 821);
            this.txtMessagesBox.TabIndex = 1;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Font = new System.Drawing.Font("Consolas", 15.75F, ((System.Drawing.FontStyle)((System.Drawing.FontStyle.Bold | System.Drawing.FontStyle.Italic))), System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label3.Location = new System.Drawing.Point(672, 28);
            this.label3.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(142, 24);
            this.label3.TabIndex = 0;
            this.label3.Text = "Server Chat";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Font = new System.Drawing.Font("Microsoft Sans Serif", 14.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label1.Location = new System.Drawing.Point(987, 7);
            this.label1.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(173, 24);
            this.label1.TabIndex = 1;
            this.label1.Text = "Current Operator:";
            // 
            // lblOperator
            // 
            this.lblOperator.AutoSize = true;
            this.lblOperator.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, ((System.Drawing.FontStyle)((System.Drawing.FontStyle.Bold | System.Drawing.FontStyle.Italic))), System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblOperator.Location = new System.Drawing.Point(1225, 11);
            this.lblOperator.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.lblOperator.Name = "lblOperator";
            this.lblOperator.Size = new System.Drawing.Size(0, 20);
            this.lblOperator.TabIndex = 2;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Font = new System.Drawing.Font("Microsoft Sans Serif", 14.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label2.Location = new System.Drawing.Point(17, 4);
            this.label2.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(577, 24);
            this.label2.TabIndex = 3;
            this.label2.Text = "Welcome to the Adversary Emulation Framework Dashboard!";
            // 
            // btnSignOut
            // 
            this.btnSignOut.Location = new System.Drawing.Point(1404, 15);
            this.btnSignOut.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnSignOut.Name = "btnSignOut";
            this.btnSignOut.Size = new System.Drawing.Size(100, 28);
            this.btnSignOut.TabIndex = 4;
            this.btnSignOut.Text = "Sign Out";
            this.btnSignOut.UseVisualStyleBackColor = true;
            this.btnSignOut.Click += new System.EventHandler(this.btnSignOut_Click);
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(795, 4);
            this.label5.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(65, 16);
            this.label5.TabIndex = 2;
            this.label5.Text = "Server At:";
            // 
            // lblServer
            // 
            this.lblServer.AutoSize = true;
            this.lblServer.Location = new System.Drawing.Point(807, 27);
            this.lblServer.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.lblServer.Name = "lblServer";
            this.lblServer.Size = new System.Drawing.Size(0, 16);
            this.lblServer.TabIndex = 5;
            // 
            // Dashboard
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1527, 1061);
            this.Controls.Add(this.lblServer);
            this.Controls.Add(this.label5);
            this.Controls.Add(this.btnSignOut);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.lblOperator);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.fileTab);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.Name = "Dashboard";
            this.Text = "Dashboard";
            this.Load += new System.EventHandler(this.Dashboard_Load);
            this.fileTab.ResumeLayout(false);
            this.tabPage1.ResumeLayout(false);
            this.tabPage2.ResumeLayout(false);
            this.tabPage2.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.dataGridView1)).EndInit();
            this.tabPage3.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.dataGridView2)).EndInit();
            this.tabPage4.ResumeLayout(false);
            this.tabPage4.PerformLayout();
            this.tabChat.ResumeLayout(false);
            this.tabChat.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.TabControl fileTab;
        private System.Windows.Forms.TabPage tabPage1;
        private System.Windows.Forms.TabPage tabPage3;
        private System.Windows.Forms.TabPage tabPage4;
        private System.Windows.Forms.Button btnGetData;
        private System.Windows.Forms.DataGridView dataGridView2;
        private System.Windows.Forms.Button btnPayloadGenerate;
        private System.Windows.Forms.TextBox txtPayloadGen;
        private System.Windows.Forms.Button btnBundlePayload;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label lblOperator;
        private System.Windows.Forms.Button btnEditImplant;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Button btnSignOut;
        private System.Windows.Forms.TabPage tabChat;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.TextBox txtMessagesBox;
        private System.Windows.Forms.TextBox txtMessageInput;
        private System.Windows.Forms.Label lblMessage;
        private System.Windows.Forms.Button btnSendMessage;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.TextBox textBox3;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.Label lblServer;
        private System.Windows.Forms.Button btnGenerateImplantShellcode;
        private System.Windows.Forms.TabPage tabPage2;
        private System.Windows.Forms.Button button1;
        private System.Windows.Forms.DataGridView dataGridView1;
        private System.Windows.Forms.Button btnProcesses;
        private System.Windows.Forms.Button btnConsole;
        private System.Windows.Forms.Button btnRunCommand;
        private System.Windows.Forms.TextBox txtCommand;
        private System.Windows.Forms.RichTextBox richTextBox1;
        private System.Windows.Forms.RichTextBox txtConsoleOutput;
    }
}