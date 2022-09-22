using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using SharpDbg.Interop;

namespace SharpDbg.Models
{
    public class NativeModule
    {
        public IntPtr ProcessHandle { get; }
        public IntPtr BaseAddress { get; }
        private RemoteStruct<IMAGE_DOS_HEADER> _remoteDosHeader { get; }
        private RemoteStruct<IMAGE_NT_HEADERS32> _remoteNtHeader { get; }

        public IMAGE_DOS_HEADER DosHeader => _remoteDosHeader.Data;
        public IMAGE_NT_HEADERS32 NtHeader => _remoteNtHeader.Data;

        public uint AddressOfCode => (uint)BaseAddress.Add(NtHeader.OptionalHeader.BaseOfCode);
        public uint EntryPoint => (uint) BaseAddress.Add(NtHeader.OptionalHeader.AddressOfEntryPoint);

        public NativeModule(IntPtr processHandle, IntPtr baseAddress)
        {
            ProcessHandle = processHandle;
            BaseAddress = baseAddress;

            _remoteDosHeader = new RemoteStruct<IMAGE_DOS_HEADER>(processHandle, baseAddress);
            _remoteNtHeader = new RemoteStruct<IMAGE_NT_HEADERS32>(processHandle, baseAddress.Add(DosHeader.e_lfanew));
        }

        public NativeModuleSection GetSection(string name)
        {
            RemoteStruct<IMAGE_SECTION_HEADER> header = new RemoteStruct<IMAGE_SECTION_HEADER>(ProcessHandle, IMAGE_FIRST_SECTION(_remoteNtHeader));
            for (int i = 0; i < NtHeader.FileHeader.NumberOfSections; i++)
            {
                NativeModuleSection section = new NativeModuleSection(ProcessHandle, BaseAddress, header);
                if (section.Name == name)
                    return section;

                header = header.GetNextStruct();
            }

            return null;
        }

        public NativeModuleSection GetCodeSection()
        {
            return GetSection(".text");
        }

        public NativeModuleSection GetRODataSection()
        {
            return GetSection(".rdata");
        }

        private static IntPtr IMAGE_FIRST_SECTION(RemoteStruct<IMAGE_NT_HEADERS32> remoteNtHeader)
        {
            return remoteNtHeader.Address.Add(Marshal.OffsetOf<IMAGE_NT_HEADERS32>("OptionalHeader")).Add(remoteNtHeader.Data.FileHeader.SizeOfOptionalHeader);
        }

    }
}
