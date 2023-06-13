namespace CapstoneInterface
{
    partial class Cradle
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
            this.label1 = new System.Windows.Forms.Label();
            this.txtHolder = new System.Windows.Forms.TextBox();
            this.SuspendLayout();
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Font = new System.Drawing.Font("Microsoft Sans Serif", 15.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label1.Location = new System.Drawing.Point(108, 9);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(304, 25);
            this.label1.TabIndex = 0;
            this.label1.Text = "Here is your Download Cradle!";
            // 
            // txtHolder
            // 
            this.txtHolder.Location = new System.Drawing.Point(48, 37);
            this.txtHolder.Multiline = true;
            this.txtHolder.Name = "txtHolder";
            this.txtHolder.Size = new System.Drawing.Size(428, 74);
            this.txtHolder.TabIndex = 1;
            this.txtHolder.TextChanged += new System.EventHandler(this.txtHolder_TextChanged);
            // 
            // Cradle
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(521, 123);
            this.Controls.Add(this.txtHolder);
            this.Controls.Add(this.label1);
            this.Name = "Cradle";
            this.Text = "Cradle";
            this.Load += new System.EventHandler(this.Cradle_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox txtHolder;
    }
}