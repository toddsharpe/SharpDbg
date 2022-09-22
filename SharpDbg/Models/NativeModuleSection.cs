using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpDbg.Interop;

namespace SharpDbg.Models
{
    public class NativeModuleSection
    {
        public string Name { get; }
        public byte[] Data { get; }

        public NativeModuleSection(IntPtr processHandle, IntPtr baseAddress, IMAGE_SECTION_HEADER header)
        {
            Name = header.SectionName;

            uint bytes = 0;
            Data = new byte[header.SizeOfRawData];
            bool result = Kernel32.ReadProcessMemory(processHandle, baseAddress.Add(header.VirtualAddress), Data, Data.Length, ref bytes);
            if (!result)
                throw new Exception();
        }
    }
}
