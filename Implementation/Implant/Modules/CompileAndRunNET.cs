using System;
using System.CodeDom.Compiler;
using Microsoft.CSharp;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Reflection;

namespace NewImplant.Modules
{
    public static class CompileAndRunNET
    {
        public static void ExecuteCS(string code, string Class, string method) {
            // Assume cs_sourcecode contains a simple C# Hello World which will be used to compile
            Console.WriteLine("Compiling CS...");
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
                Console.WriteLine("Compilation successful");

                // Invoke the Main method of HelloWorld
                Assembly assembly = results.CompiledAssembly;
                Type program = assembly.GetType(Class);
                MethodInfo main = program.GetMethod(method);

                Console.WriteLine("Executing: " + Class + "." + method + " For\n\n\n");
                Console.WriteLine(code);

                main.Invoke(null, null);  // Assuming the Main method doesn't need any arguments
            }
        }
    }
}
