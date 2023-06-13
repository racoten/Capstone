using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace CapstoneInterface
{
    public partial class formLogin : Form
    {
        public static string username = "";
        public formLogin()
        {
            InitializeComponent();
        }

        public static string host { get; set; }
        public static string port { get; set; }

        public class OperatorRegister
        {
            public string FirstName { get; set; }
            public string LastName { get; set; }
            public string Username { get; set; }
            public string Password { get; set; }
            public string Email { get; set; }
            public string PhoneNumber { get; set; }
        }

        private void label1_Click(object sender, EventArgs e)
        {

        }

        private void Form1_Load(object sender, EventArgs e)
        {
            picHackerGif.BackColor = Color.Transparent;

            Server server = new Server();
            server.ShowDialog();

            lblHost.Text = host;
            lblPort.Text = port;
        }

        public class LoginRequest
        {
            public string Username { get; set; }
            public string Password { get; set; }
        }

        private async void btnLogin_Click(object sender, EventArgs e)
        {

            Dashboard dashboard = new Dashboard();
            


            HttpClient client = new HttpClient();
            LoginRequest request = new LoginRequest
            {
                Username = txtUsername.Text,
                Password = txtPassword.Text
            };

            dashboard.host = host;
            dashboard.port = port;


            string jsonRequest = JsonConvert.SerializeObject(request);

            var content = new StringContent(jsonRequest, Encoding.UTF8, "application/json");

            HttpResponseMessage response = await client.PostAsync("http://" + host + ":" + port + "/operators/login", content);

            if (response.IsSuccessStatusCode)
            {
                string responseString = await response.Content.ReadAsStringAsync();
                if (responseString == "Login successful")
                {
                    dashboard.operatorName = txtUsername.Text;
                    this.Hide();
                    dashboard.Closed += (s, args) => this.Close();
                    dashboard.Show();
                }
            }
        }


        private async void btnRegister_Click(object sender, EventArgs e)
        {
            var url = "http://" + host + ":" + port + "/operators/register";
            var firstName = txtFName.Text;
            var lastName = txtLName.Text;
            var username = txtUsernameRegister.Text;
            var password = txtPasswordRegister.Text;
            var email = txtEmail.Text;
            var phoneNumber = txtNumber.Text;

            var response = await SendRegistrationData(url, firstName, lastName, username, password, email, phoneNumber);

            // Handle the response here
            if (response.Contains("registered successfully"))
            {
                Dashboard dashboard = new Dashboard();
                
                dashboard.host = host;
                dashboard.port = port;
                
                dashboard.operatorName = txtUsernameRegister.Text;
                this.Hide();
                dashboard.Closed += (s, args) => this.Close();
                dashboard.Show();
            }
        }

        public static async Task<string> SendRegistrationData(string url, string firstName, string lastName, string username, string password, string email, string phoneNumber)
        {
            // Create a new instance of OperatorRegister and fill it with the input data
            var operatorRegister = new OperatorRegister
            {
                FirstName = firstName,
                LastName = lastName,
                Username = username,
                Password = password,
                Email = email,
                PhoneNumber = phoneNumber
            };

            // Serialize the OperatorRegister object to JSON
            var json = JsonConvert.SerializeObject(operatorRegister);

            // Create a new HttpClient instance
            using (var client = new HttpClient())
            {
                // Create a new StringContent object containing the serialized JSON data
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                // Send a POST request to the specified URL with the serialized JSON data in the request body
                var response = await client.PostAsync(url, content);

                // Read the response content as a string and return it
                return await response.Content.ReadAsStringAsync();
            }
        }

        private void pictureBox2_Click(object sender, EventArgs e)
        {

        }
    }
}
