using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using SharpDbg.Interop;

namespace SharpDbg.Models
{
    public class NativeProcess
    {
        public Dictionary<string, List<ImportedFunction>> Imports { get; } = new Dictionary<string, List<ImportedFunction>>();

        public IntPtr ProcessHandle { get; }
        public IntPtr Address { get; }
        public uint ProcessId { get; set; }
        public IntPtr BaseOfImage { get; set; }

        public IntPtr AddressOfCode => Address.Add(MainModule.NtHeader.OptionalHeader.BaseOfCode);

        public NativeModule MainModule { get; private set; }
        public List<NativeModule> Modules { get; } 

        public Process Process { get; }

        public NativeProcess(IntPtr processHandle, IntPtr baseOfImage)
        {
            ProcessHandle = processHandle;
            ProcessId = Kernel32.GetProcessId(processHandle);
            Address = baseOfImage;

            Process = Process.GetProcessById((int) ProcessId);
            MainModule = new NativeModule(processHandle, baseOfImage);
            Modules = new List<NativeModule> { MainModule };
        }

        public void LoadModules()
        {
            foreach (ProcessModule module in Process.Modules)
            {
                if (module.BaseAddress == MainModule.BaseAddress)
                    continue;

                Modules.Add(new NativeModule(ProcessHandle, module.BaseAddress));
            }
        }

        public void LoadImports()
        {
            int descriptorSize = Marshal.SizeOf<IMAGE_IMPORT_DESCRIPTOR>();
            int thunkSize = Marshal.SizeOf<IMAGE_THUNK_DATA>();

            IMAGE_DATA_DIRECTORY importDirectory =  MainModule.NtHeader.OptionalHeader.ImportTable;
            if (importDirectory.Size > 0)
            {
                int i = 0;
                IMAGE_IMPORT_DESCRIPTOR importDescriptor = NativeHelpers.GetRemoteStructure<IMAGE_IMPORT_DESCRIPTOR>(ProcessHandle, Address.Add(importDirectory.VirtualAddress));
                while (importDescriptor.Name != 0)
                {
                    string moduleName = NativeHelpers.GetRemoteString(ProcessHandle, Address.Add(importDescriptor.Name));
                    Imports.Add(moduleName, new List<ImportedFunction>());
                    IMAGE_THUNK_DATA data = NativeHelpers.GetRemoteStructure<IMAGE_THUNK_DATA>(ProcessHandle, Address.Add(importDescriptor.FirstThunk));
                    int j = 0;
                    while (data.AddressOfData > 0)
                    {
                        string import = NativeHelpers.GetRemoteString(ProcessHandle, Address.Add(data.AddressOfData + (uint)Marshal.OffsetOf<IMAGE_IMPORT_BY_NAME>("Name")));
                        Imports[moduleName].Add(new ImportedFunction { Name = import, NameRVA = data.AddressOfData + (uint)Marshal.OffsetOf<IMAGE_IMPORT_BY_NAME>("Name"), RVA = importDescriptor.FirstThunk + (uint)(j * thunkSize) });

                        j++;
                        data = NativeHelpers.GetRemoteStructure<IMAGE_THUNK_DATA>(ProcessHandle, Address.Add(importDescriptor.FirstThunk + (uint)(j * thunkSize)));
                    }

                    i++;
                    importDescriptor = NativeHelpers.GetRemoteStructure<IMAGE_IMPORT_DESCRIPTOR>(ProcessHandle, Address.Add(importDirectory.VirtualAddress + (uint)(i * descriptorSize)));
                }
            }
        }

        public void UpdateImports()
        {
            foreach (ImportedFunction function in Imports.Keys.SelectMany(key => Imports[key]))
            {
                function.OriginalAddress = NativeHelpers.GetRemoteDWord(ProcessHandle, Address.Add(function.RVA));
            }
        }

        public string GetImportByAddress(uint address)
        {
            foreach (string key in Imports.Keys)
            {
                foreach (ImportedFunction function in Imports[key])
                {
                    if (function.OriginalAddress == address)
                        return key + "!" + function.Name;
                }
            }

            return null;
        }
    }
}
