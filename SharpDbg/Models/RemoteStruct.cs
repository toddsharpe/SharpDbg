using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SharpDbg.Models
{
    public class RemoteStruct<T> where T : struct 
    {
        public IntPtr Address { get; }
        public T Data { get; }
        private readonly IntPtr _processHandle;

        public RemoteStruct(IntPtr processHandle, IntPtr address)
        {
            _processHandle = processHandle;
            Address = address;
            Data = NativeHelpers.GetRemoteStructure<T>(processHandle, address);
        }

        public static implicit operator T(RemoteStruct<T> remote)
        {
            return remote.Data;
        }

        public RemoteStruct<T> GetNextStruct()
        {
            return new RemoteStruct<T>(_processHandle, Address.Add(Marshal.SizeOf<T>()));
        }
    }
}
