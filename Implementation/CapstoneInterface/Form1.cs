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
    // formLogin class is responsible for the login form of the application.
    public partial class formLogin : Form
    {
        // Variable to hold the current username.
        public static string username = "";

        // Default constructor for the formLogin.
        public formLogin()
        {
            InitializeComponent();
        }

        // Host and port properties for the server.
        public static string host { get; set; }
        public static string port { get; set; }

        // OperatorRegister class to hold registration details for an operator.
        public class OperatorRegister
        {
            public string FirstName { get; set; }
            public string LastName { get; set; }
            public string Username { get; set; }
            public string Password { get; set; }
            public string Email { get; set; }
            public string PhoneNumber { get; set; }
        }

        // Click event for the label.
        private void label1_Click(object sender, EventArgs e)
        {
            // No implementation, placeholder.
        }

        // Form load event.
        private void Form1_Load(object sender, EventArgs e)
        {
            picHackerGif.BackColor = Color.Transparent; // Setting the gif's background color as transparent.

            Server server = new Server(); // Instance of the Server class.
            server.ShowDialog(); // Showing the server dialog.

            lblHost.Text = host; // Setting the host text label.
            lblPort.Text = port; // Setting the port text label.
        }

        // LoginRequest class to hold login request details.
        public class LoginRequest
        {
            public string Username { get; set; }
            public string Password { get; set; }
        }

        // Click event for the login button.
        private async void btnLogin_Click(object sender, EventArgs e)
        {
            Dashboard dashboard = new Dashboard(); // Instance of the Dashboard class.
            
            HttpClient client = new HttpClient(); // Instance of the HttpClient class for sending HTTP requests.
            LoginRequest request = new LoginRequest // Instance of LoginRequest class.
            {
                Username = txtUsername.Text, // Getting the username text.
                Password = txtPassword.Text // Getting the password text.
            };

            dashboard.host = host; // Setting the dashboard host.
            dashboard.port = port; // Setting the dashboard port.

            string jsonRequest = JsonConvert.SerializeObject(request); // Serializing the request object to JSON.

            // Creating a new string content instance.
            var content = new StringContent(jsonRequest, Encoding.UTF8, "application/json");

            // Sending a post request to the login endpoint.
            HttpResponseMessage response = await client.PostAsync("http://" + host + ":" + port + "/operators/login", content);

            if (response.IsSuccessStatusCode) // Checking if the response status is successful.
            {
                string responseString = await response.Content.ReadAsStringAsync(); // Reading the response string.
                if (responseString == "Login successful") // Checking if the login was successful.
                {
                    dashboard.operatorName = txtUsername.Text; // Setting the operator name.
                    this.Hide(); // Hiding the current form.
                    dashboard.Closed += (s, args) => this.Close(); // Setting the form close event handler.
                    dashboard.Show(); // Showing the dashboard.
                }
            }
        }

        // Click event for the register button.
        private async void btnRegister_Click(object sender, EventArgs e)
        {
            // Preparing the URL and inputs for the registration.
            var url = "http://" + host + ":" + port + "/operators/register";
            var firstName = txtFName.Text;
            var lastName = txtLName.Text;
            var username = txtUsernameRegister.Text;
            var password = txtPasswordRegister.Text;
            var email = txtEmail.Text;
            var phoneNumber = txtNumber.Text;

            // Sending the registration data and receiving the response.
            var response = await SendRegistrationData(url, firstName, lastName, username, password, email, phoneNumber);

            // Handle the response here
            if (response.Contains("registered successfully"))
            {
                // If registration is successful, initialize a new dashboard, set its host, port and operatorName, hide the current form and show the dashboard.
                Dashboard dashboard = new Dashboard();
                
                dashboard.host = host;
                dashboard.port = port;
                
                dashboard.operatorName = txtUsernameRegister.Text;
                this.Hide();
                dashboard.Closed += (s, args) => this.Close();
                dashboard.Show();
            }
        }

        // Method to send registration data to the server.
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

        // Click event for the picture box.
        private void pictureBox2_Click(object sender, EventArgs e)
        {
            // No implementation, placeholder.
        }
    }
}
