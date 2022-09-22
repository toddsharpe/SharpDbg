using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpDbg.Interop;

namespace SharpDbg.Models
{
    class Breakpoint
    {
        public const byte PatchByte = 0xCC;
        public static readonly byte[] PatchBuffer = new byte[] { PatchByte };

        public uint Address { get; }
        public bool IsEnabled { get; private set; }

        public int Length => PatchBuffer.Length;

        private readonly byte[] _instructionBuffer;
        private readonly IntPtr _processHandle;

        public Breakpoint(IntPtr processHandle, uint address)
        {
            _processHandle = processHandle;
            Address = address;
            _instructionBuffer = new byte[PatchBuffer.Length];
        }

        public void Enable()
        {
            uint bytes = 0;

            //Read and save instruction
            bool result = Kernel32.ReadProcessMemory(_processHandle, (IntPtr)Address, _instructionBuffer, _instructionBuffer.Length, ref bytes);
            if (!result)
                throw new Exception();

            //Write break instruction
            result = Kernel32.WriteProcessMemory(_processHandle, (IntPtr)Address, PatchBuffer, PatchBuffer.Length, ref bytes);
            if (!result)
                throw new Exception();

            IsEnabled = true;
        }

        public void Disable()
        {
            uint bytes = 0;

            //Write original instruction
            bool result = Kernel32.WriteProcessMemory(_processHandle, (IntPtr)Address, _instructionBuffer, _instructionBuffer.Length, ref bytes);
            if (!result)
                throw new Exception();

            IsEnabled = false;
        }
    }
}
