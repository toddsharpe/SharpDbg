using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SharpDbg
{
    //From ProjectDOS
    public static class StructHelper
    {
        public static byte[] SerializeStruct<T>(T structure) where T : struct
        {
            int size = Marshal.SizeOf(typeof(T));

            Byte[] ret = new Byte[size];
            IntPtr buff = Marshal.AllocHGlobal(size);

            Marshal.StructureToPtr(structure, buff, true);
            Marshal.Copy(buff, ret, 0, size);
            Marshal.FreeHGlobal(buff);

            return ret;
        }

        public static T DeserializeStruct<T>(byte[] data) where T : struct
        {
            int size = Marshal.SizeOf(typeof(T));

            IntPtr buff = Marshal.AllocHGlobal(size);
            Marshal.Copy(data, 0, buff, size);

            T ret = (T)Marshal.PtrToStructure(buff, typeof(T));
            Marshal.FreeHGlobal(buff);

            return ret;
        }

        public static byte[] SerializeStructArray<T>(T[] array) where T : struct
        {
            return array.Select(SerializeStruct).SelectMany(i => i).ToArray();
        }

        public static T[] DeserializeStructArray<T>(byte[] data) where T : struct
        {
            int size = Marshal.SizeOf(typeof(T));
            byte[] buffer = new byte[size];

            List<T> list = new List<T>();
            for (int i = 0; i < data.Length; i += size)
            {
                Array.Copy(data, i, buffer, 0, size);
                list.Add(DeserializeStruct<T>(buffer));
            }

            return list.ToArray();
        }
    }
}
