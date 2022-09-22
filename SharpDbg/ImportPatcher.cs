using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using SharpDbg.Interop;
using SharpDbg.Models;

namespace SharpDbg
{
    class ImportPatcher
    {
        //TODO: this code causes access violation on exit
        private static readonly byte[] PatchBytes = new byte[]
        {
            0x68, 0xAA, 0xAA, 0xAA, 0xAA,//Function name string
            0xFF, 0x15, 0xCC, 0xCC, 0xCC, 0xCC,//call Debug function address
            0xE8, 0xBB, 0xBB, 0xBB, 0xBB,//call Original address
            0xC3
        };

        public static byte[] MakePatchBytes(ImportedFunction function, ImportedFunction debugFunction, uint processBaseAddress)
        {
            //Copy it
            byte[] patch = new byte[PatchBytes.Length];
            Array.Copy(PatchBytes, patch, patch.Length);

            //Overwrite function name pointer
            byte[] namePtrBytes = BitConverter.GetBytes((int) (processBaseAddress + function.NameRVA));
            Array.Copy(namePtrBytes, 0, patch, 1, namePtrBytes.Length);

            //Overwrite debug function address
            byte[] debugAddress = BitConverter.GetBytes((int)(processBaseAddress + debugFunction.RVA));
            Array.Copy(debugAddress, 0, patch, 7, debugAddress.Length);

            //Overwrite original address
            byte[] originalAddress = BitConverter.GetBytes((int)(processBaseAddress + function.RVA));
            Array.Copy(originalAddress, 0, patch, 12, namePtrBytes.Length);


            //Return
            return patch;
        }

        public static void PatchImport(IntPtr processHandle, uint processBaseAddress, ImportedFunction function, ImportedFunction debugFunction)
        {
            byte[] bytes = MakePatchBytes(function, debugFunction, processBaseAddress);
            uint bytesWritten = 0;

            //Write bytes into process
            IntPtr address = Kernel32.VirtualAllocEx(processHandle, IntPtr.Zero, (uint)bytes.Length, AllocationType.MEM_COMMIT | AllocationType.MEM_RESERVE, MemoryProtection.PAGE_EXECUTE_READWRITE);
            bool result = Kernel32.WriteProcessMemory(processHandle, address, bytes, bytes.Length, ref bytesWritten);
            if (!result)
            {
                var error = Marshal.GetLastWin32Error();
            }

            //Set access to this import table
            MemoryProtection old;
            result = Kernel32.VirtualProtectEx(processHandle, (IntPtr) (processBaseAddress + function.RVA), 4, MemoryProtection.PAGE_EXECUTE_READWRITE, out old);
            if (!result)
            {
                var error = Marshal.GetLastWin32Error();
            }

            //Overwrite import table with new address
            byte[] addressBytes = BitConverter.GetBytes((int) address);
            result = Kernel32.WriteProcessMemory(processHandle, (IntPtr) (processBaseAddress + function.RVA), addressBytes, addressBytes.Length, ref bytesWritten);
            if (!result)
            {
                var error = Marshal.GetLastWin32Error();
            }
        }
    }
}
