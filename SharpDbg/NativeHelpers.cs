using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using SharpDbg.Interop;

namespace SharpDbg
{
    public static class NativeHelpers
    {
        public static IntPtr Add(this IntPtr address, IntPtr delta)
        {
            return (IntPtr)((uint)address + (uint)delta);
        }

        public static IntPtr Add(this IntPtr address, uint delta)
        {
            return (IntPtr) ((uint) address + delta);
        }

        public static IntPtr Add(this IntPtr address, int delta)
        {
            return (IntPtr)((uint)address + delta);
        }

        public static T GetRemoteStructure<T>(IntPtr process, IntPtr address) where T : struct
        {
            int size = Marshal.SizeOf<T>();
            byte[] buffer = new byte[size];
            uint bytesRead = 0;

            bool success = Kernel32.ReadProcessMemory(process, address, buffer, size, ref bytesRead);
            if (!success)
            {
                var error = Marshal.GetLastWin32Error();
                throw new Exception();
            }

            return StructHelper.DeserializeStruct<T>(buffer);
        }

        public static string GetRemoteString(IntPtr process, IntPtr address)
        {
            StringBuilder s = new StringBuilder();

            uint bytesRead = 0;
            byte[] buffer = new byte[1];
            uint i = 0;
            while (true)
            {
                bool success = Kernel32.ReadProcessMemory(process, address.Add(i), buffer, 1, ref bytesRead);
                if (!success)
                    throw new Exception();

                if (buffer[0] == '\0')
                    break;

                s.Append((char)buffer[0]);
                i++;

                if (i > 50)
                    break;
            }
            return s.ToString();
        }


        public static uint GetRemoteDWord(IntPtr process, IntPtr address)
        {
            byte[] buffer = new byte[4];
            uint bytesRead = 0;

            bool success = Kernel32.ReadProcessMemory(process, address, buffer, buffer.Length, ref bytesRead);
            if (!success)
                throw new Exception();

            return BitConverter.ToUInt32(buffer, 0);
        }
    }
}
