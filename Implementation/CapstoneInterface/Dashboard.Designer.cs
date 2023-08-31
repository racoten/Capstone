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
            this.fileTab.Location = new System.Drawing.Point(13, 30);
            this.fileTab.Name = "fileTab";
            this.fileTab.SelectedIndex = 0;
            this.fileTab.Size = new System.Drawing.Size(1119, 836);
            this.fileTab.TabIndex = 0;
            // 
            // tabPage1
            // 
            this.tabPage1.Controls.Add(this.richTextBox1);
            this.tabPage1.Controls.Add(this.btnEditImplant);
            this.tabPage1.Location = new System.Drawing.Point(4, 22);
            this.tabPage1.Name = "tabPage1";
            this.tabPage1.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage1.Size = new System.Drawing.Size(1111, 810);
            this.tabPage1.TabIndex = 0;
            this.tabPage1.Text = "File";
            this.tabPage1.UseVisualStyleBackColor = true;
            // 
            // richTextBox1
            // 
            this.richTextBox1.Location = new System.Drawing.Point(6, 51);
            this.richTextBox1.Name = "richTextBox1";
            this.richTextBox1.Size = new System.Drawing.Size(1099, 755);
            this.richTextBox1.TabIndex = 2;
            this.richTextBox1.Text = "";
            // 
            // btnEditImplant
            // 
            this.btnEditImplant.Location = new System.Drawing.Point(6, 22);
            this.btnEditImplant.Name = "btnEditImplant";
            this.btnEditImplant.Size = new System.Drawing.Size(75, 23);
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
            this.tabPage2.Location = new System.Drawing.Point(4, 22);
            this.tabPage2.Name = "tabPage2";
            this.tabPage2.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage2.Size = new System.Drawing.Size(1111, 810);
            this.tabPage2.TabIndex = 1;
            this.tabPage2.Text = "Server";
            this.tabPage2.UseVisualStyleBackColor = true;
            // 
            // txtConsoleOutput
            // 
            this.txtConsoleOutput.BackColor = System.Drawing.Color.Black;
            this.txtConsoleOutput.Font = new System.Drawing.Font("Consolas", 10F);
            this.txtConsoleOutput.ForeColor = System.Drawing.Color.White;
            this.txtConsoleOutput.Location = new System.Drawing.Point(7, 98);
            this.txtConsoleOutput.Name = "txtConsoleOutput";
            this.txtConsoleOutput.Size = new System.Drawing.Size(1098, 472);
            this.txtConsoleOutput.TabIndex = 9;
            this.txtConsoleOutput.Text = "";
            this.txtConsoleOutput.TextChanged += new System.EventHandler(this.txtConsoleOutput_TextChanged_1);
            // 
            // button1
            // 
            this.button1.Location = new System.Drawing.Point(7, 576);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(75, 23);
            this.button1.TabIndex = 8;
            this.button1.Text = "Add Info";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // dataGridView1
            // 
            this.dataGridView1.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.dataGridView1.Location = new System.Drawing.Point(7, 605);
            this.dataGridView1.Name = "dataGridView1";
            this.dataGridView1.Size = new System.Drawing.Size(1098, 199);
            this.dataGridView1.TabIndex = 7;
            this.dataGridView1.CellContentClick += new System.Windows.Forms.DataGridViewCellEventHandler(this.dataGridView1_CellContentClick);
            // 
            // btnProcesses
            // 
            this.btnProcesses.Location = new System.Drawing.Point(86, 68);
            this.btnProcesses.Name = "btnProcesses";
            this.btnProcesses.Size = new System.Drawing.Size(75, 23);
            this.btnProcesses.TabIndex = 5;
            this.btnProcesses.Text = "Process";
            this.btnProcesses.UseVisualStyleBackColor = true;
            this.btnProcesses.Click += new System.EventHandler(this.btnProcesses_Click);
            // 
            // btnConsole
            // 
            this.btnConsole.Location = new System.Drawing.Point(5, 68);
            this.btnConsole.Name = "btnConsole";
            this.btnConsole.Size = new System.Drawing.Size(75, 23);
            this.btnConsole.TabIndex = 4;
            this.btnConsole.Text = "Console";
            this.btnConsole.UseVisualStyleBackColor = true;
            this.btnConsole.Click += new System.EventHandler(this.btnConsole_Click);
            // 
            // btnRunCommand
            // 
            this.btnRunCommand.Location = new System.Drawing.Point(394, 3);
            this.btnRunCommand.Name = "btnRunCommand";
            this.btnRunCommand.Size = new System.Drawing.Size(80, 37);
            this.btnRunCommand.TabIndex = 3;
            this.btnRunCommand.Text = "Run";
            this.btnRunCommand.UseVisualStyleBackColor = true;
            this.btnRunCommand.Click += new System.EventHandler(this.btnRunCommand_Click);
            // 
            // txtCommand
            // 
            this.txtCommand.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txtCommand.Location = new System.Drawing.Point(5, 7);
            this.txtCommand.Multiline = true;
            this.txtCommand.Name = "txtCommand";
            this.txtCommand.Size = new System.Drawing.Size(342, 33);
            this.txtCommand.TabIndex = 2;
            // 
            // tabPage3
            // 
            this.tabPage3.Controls.Add(this.btnGetData);
            this.tabPage3.Controls.Add(this.dataGridView2);
            this.tabPage3.Location = new System.Drawing.Point(4, 22);
            this.tabPage3.Name = "tabPage3";
            this.tabPage3.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage3.Size = new System.Drawing.Size(1111, 810);
            this.tabPage3.TabIndex = 2;
            this.tabPage3.Text = "Action";
            this.tabPage3.UseVisualStyleBackColor = true;
            // 
            // btnGetData
            // 
            this.btnGetData.Location = new System.Drawing.Point(533, 31);
            this.btnGetData.Name = "btnGetData";
            this.btnGetData.Size = new System.Drawing.Size(75, 23);
            this.btnGetData.TabIndex = 1;
            this.btnGetData.Text = "Get Data";
            this.btnGetData.UseVisualStyleBackColor = true;
            this.btnGetData.Click += new System.EventHandler(this.btnGetData_ClickAsync);
            // 
            // dataGridView2
            // 
            this.dataGridView2.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.dataGridView2.Location = new System.Drawing.Point(7, 75);
            this.dataGridView2.Name = "dataGridView2";
            this.dataGridView2.Size = new System.Drawing.Size(1086, 668);
            this.dataGridView2.TabIndex = 0;
            // 
            // tabPage4
            // 
            this.tabPage4.Controls.Add(this.btnGenerateImplantShellcode);
            this.tabPage4.Controls.Add(this.txtPayloadGen);
            this.tabPage4.Controls.Add(this.btnBundlePayload);
            this.tabPage4.Controls.Add(this.btnPayloadGenerate);
            this.tabPage4.Location = new System.Drawing.Point(4, 22);
            this.tabPage4.Name = "tabPage4";
            this.tabPage4.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage4.Size = new System.Drawing.Size(1111, 810);
            this.tabPage4.TabIndex = 3;
            this.tabPage4.Text = "Payloads";
            this.tabPage4.UseVisualStyleBackColor = true;
            // 
            // btnGenerateImplantShellcode
            // 
            this.btnGenerateImplantShellcode.Location = new System.Drawing.Point(582, 6);
            this.btnGenerateImplantShellcode.Name = "btnGenerateImplantShellcode";
            this.btnGenerateImplantShellcode.Size = new System.Drawing.Size(151, 24);
            this.btnGenerateImplantShellcode.TabIndex = 3;
            this.btnGenerateImplantShellcode.Text = "Generate Implant Shellcode";
            this.btnGenerateImplantShellcode.UseVisualStyleBackColor = true;
            this.btnGenerateImplantShellcode.Click += new System.EventHandler(this.btnGenerateImplantShellcode_Click);
            // 
            // txtPayloadGen
            // 
            this.txtPayloadGen.Location = new System.Drawing.Point(10, 47);
            this.txtPayloadGen.Multiline = true;
            this.txtPayloadGen.Name = "txtPayloadGen";
            this.txtPayloadGen.Size = new System.Drawing.Size(1095, 776);
            this.txtPayloadGen.TabIndex = 2;
            // 
            // btnBundlePayload
            // 
            this.btnBundlePayload.Location = new System.Drawing.Point(481, 6);
            this.btnBundlePayload.Name = "btnBundlePayload";
            this.btnBundlePayload.Size = new System.Drawing.Size(94, 24);
            this.btnBundlePayload.TabIndex = 1;
            this.btnBundlePayload.Text = "Bundle Payload";
            this.btnBundlePayload.UseVisualStyleBackColor = true;
            this.btnBundlePayload.Click += new System.EventHandler(this.btnBundlePayload_Click);
            // 
            // btnPayloadGenerate
            // 
            this.btnPayloadGenerate.Location = new System.Drawing.Point(347, 7);
            this.btnPayloadGenerate.Name = "btnPayloadGenerate";
            this.btnPayloadGenerate.Size = new System.Drawing.Size(127, 23);
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
            this.tabChat.Location = new System.Drawing.Point(4, 22);
            this.tabChat.Name = "tabChat";
            this.tabChat.Padding = new System.Windows.Forms.Padding(3);
            this.tabChat.Size = new System.Drawing.Size(1111, 810);
            this.tabChat.TabIndex = 4;
            this.tabChat.Text = "Chat";
            this.tabChat.UseVisualStyleBackColor = true;
            // 
            // textBox3
            // 
            this.textBox3.BackColor = System.Drawing.SystemColors.InactiveCaption;
            this.textBox3.Font = new System.Drawing.Font("MS UI Gothic", 12F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.textBox3.ForeColor = System.Drawing.SystemColors.MenuHighlight;
            this.textBox3.Location = new System.Drawing.Point(741, 136);
            this.textBox3.Multiline = true;
            this.textBox3.Name = "textBox3";
            this.textBox3.Size = new System.Drawing.Size(272, 668);
            this.textBox3.TabIndex = 6;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Font = new System.Drawing.Font("Consolas", 12F, ((System.Drawing.FontStyle)((System.Drawing.FontStyle.Bold | System.Drawing.FontStyle.Italic))), System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label4.Location = new System.Drawing.Point(817, 99);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(117, 19);
            this.label4.TabIndex = 5;
            this.label4.Text = "Users Online";
            // 
            // btnSendMessage
            // 
            this.btnSendMessage.Location = new System.Drawing.Point(439, 99);
            this.btnSendMessage.Name = "btnSendMessage";
            this.btnSendMessage.Size = new System.Drawing.Size(41, 23);
            this.btnSendMessage.TabIndex = 4;
            this.btnSendMessage.Text = "Send";
            this.btnSendMessage.UseVisualStyleBackColor = true;
            this.btnSendMessage.Click += new System.EventHandler(this.btnSendMessage_Click);
            // 
            // txtMessageInput
            // 
            this.txtMessageInput.Location = new System.Drawing.Point(94, 100);
            this.txtMessageInput.Name = "txtMessageInput";
            this.txtMessageInput.Size = new System.Drawing.Size(339, 20);
            this.txtMessageInput.TabIndex = 3;
            // 
            // lblMessage
            // 
            this.lblMessage.AutoSize = true;
            this.lblMessage.Font = new System.Drawing.Font("Consolas", 12F, ((System.Drawing.FontStyle)((System.Drawing.FontStyle.Bold | System.Drawing.FontStyle.Italic))), System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblMessage.Location = new System.Drawing.Point(7, 99);
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
            this.txtMessagesBox.Location = new System.Drawing.Point(3, 136);
            this.txtMessagesBox.Multiline = true;
            this.txtMessagesBox.Name = "txtMessagesBox";
            this.txtMessagesBox.Size = new System.Drawing.Size(570, 668);
            this.txtMessagesBox.TabIndex = 1;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Font = new System.Drawing.Font("Consolas", 15.75F, ((System.Drawing.FontStyle)((System.Drawing.FontStyle.Bold | System.Drawing.FontStyle.Italic))), System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label3.Location = new System.Drawing.Point(504, 23);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(142, 24);
            this.label3.TabIndex = 0;
            this.label3.Text = "Server Chat";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Font = new System.Drawing.Font("Microsoft Sans Serif", 14.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label1.Location = new System.Drawing.Point(740, 6);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(173, 24);
            this.label1.TabIndex = 1;
            this.label1.Text = "Current Operator:";
            // 
            // lblOperator
            // 
            this.lblOperator.AutoSize = true;
            this.lblOperator.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, ((System.Drawing.FontStyle)((System.Drawing.FontStyle.Bold | System.Drawing.FontStyle.Italic))), System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblOperator.Location = new System.Drawing.Point(919, 9);
            this.lblOperator.Name = "lblOperator";
            this.lblOperator.Size = new System.Drawing.Size(0, 20);
            this.lblOperator.TabIndex = 2;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Font = new System.Drawing.Font("Microsoft Sans Serif", 14.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label2.Location = new System.Drawing.Point(13, 3);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(577, 24);
            this.label2.TabIndex = 3;
            this.label2.Text = "Welcome to the Adversary Emulation Framework Dashboard!";
            // 
            // btnSignOut
            // 
            this.btnSignOut.Location = new System.Drawing.Point(1053, 12);
            this.btnSignOut.Name = "btnSignOut";
            this.btnSignOut.Size = new System.Drawing.Size(75, 23);
            this.btnSignOut.TabIndex = 4;
            this.btnSignOut.Text = "Sign Out";
            this.btnSignOut.UseVisualStyleBackColor = true;
            this.btnSignOut.Click += new System.EventHandler(this.btnSignOut_Click);
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(596, 3);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(54, 13);
            this.label5.TabIndex = 2;
            this.label5.Text = "Server At:";
            // 
            // lblServer
            // 
            this.lblServer.AutoSize = true;
            this.lblServer.Location = new System.Drawing.Point(605, 22);
            this.lblServer.Name = "lblServer";
            this.lblServer.Size = new System.Drawing.Size(0, 13);
            this.lblServer.TabIndex = 5;
            // 
            // Dashboard
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1145, 862);
            this.Controls.Add(this.lblServer);
            this.Controls.Add(this.label5);
            this.Controls.Add(this.btnSignOut);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.lblOperator);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.fileTab);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
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