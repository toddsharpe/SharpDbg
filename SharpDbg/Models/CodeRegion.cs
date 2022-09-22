using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using SharpDbg.Interop;

namespace SharpDbg.Models
{
    public class CodeRegion
    {
        public ProcessModule Module { get; private set; }

        public uint Address { get; private set; }
        public uint Size { get; private set; }
        public byte[] Code { get; private set; }

        private readonly IntPtr _process;
        public bool IsMain { get; }
        public CodeRegion(IntPtr process, ProcessModule module, bool isMain = false)
        {
            Module = module;
            _process = process;
            IsMain = isMain;

            Load();
        }

        private void Load()
        {
            IntPtr address = Module.BaseAddress;
            var DosHeader = NativeHelpers.GetRemoteStructure<IMAGE_DOS_HEADER>(_process, address);
            var NtHeader = NativeHelpers.GetRemoteStructure<IMAGE_NT_HEADERS32>(_process, address.Add(DosHeader.e_lfanew));

            Address = (uint) address + NtHeader.OptionalHeader.BaseOfCode;
            Size = NtHeader.OptionalHeader.SizeOfCode;

            uint bytes = 0;
            Code = new byte[Size];
            bool result = Kernel32.ReadProcessMemory(_process, (IntPtr)Address, Code, Code.Length, ref bytes);
            if (!result)
                throw new Exception();
        }

    }
}
