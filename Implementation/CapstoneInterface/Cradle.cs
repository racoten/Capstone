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
    public partial class Cradle : Form
    {
        public string payload { get; set; }
        public Cradle()
        {
            InitializeComponent();
        }

        private void txtHolder_TextChanged(object sender, EventArgs e)
        {

        }

        private void Cradle_Load(object sender, EventArgs e)
        {
            txtHolder.Text = payload;
        }
    }
}
