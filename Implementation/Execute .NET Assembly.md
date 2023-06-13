```cs
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;

namespace Agent.Internal
{
	public static class Execute
	{
		public static string ExecuteAssembly(byte[] asm, string[] args = null)
		{
			if (args is null)
				args = new string[] {};

			var currentOut = Console.Out;
			var currentError = Console.Error;

			var memoryStream = new MemoryStream();
			var streamWriter = new StreamWriter(memoryStream);

			Console.SetOut(streamWriter);
			Console.SetOut(streamWriter);

			var assembly = Assembly.Load(asm);
			assembly.EntryPoint.Invoke(null, new object[] { args });

			Console.Out.Flush();
			Console.Error.Flush();

			var output = Encoding.UTF8.GetString(ms.ToArray());

			Console.SetOut(currentOut);
			Console.SetError(currentError);

			streamWriter.Dispose();
			memoryStream.Dispose();
			
			return output;
		}
	}
}
```