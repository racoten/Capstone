using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace CapstoneInterface
{
    // Server class is responsible for the server form of the application.
    public partial class Server : Form
    {
        // Default constructor for the Server.
        public Server()
        {
            InitializeComponent();
        }

        // Event handler for the button click.
        private void button1_Click(object sender, EventArgs e)
        {
            // Setting the host and port properties of the formLogin class.
            formLogin.host = txtHost.Text;
            formLogin.port = txtPort.Text;
            this.Close(); // Closing the current form.
        }
    }
}
