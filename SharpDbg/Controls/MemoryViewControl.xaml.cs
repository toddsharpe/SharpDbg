using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using SharpDbg.Interop;
using SharpDbg.Models;

namespace SharpDbg.Controls
{
    /// <summary>
    /// Interaction logic for MemoryViewControl.xaml
    /// </summary>
    public partial class MemoryViewControl : UserControl
    {
        public MemoryViewControl()
        {
            InitializeComponent();
        }

        public void SetModule(NativeProcess process)
        {
            uint count = 0;
            byte[] bytes = new byte[process.MainModule.NtHeader.OptionalHeader.SizeOfImage];
            if (!Kernel32.ReadProcessMemory(process.ProcessHandle, (IntPtr)process.MainModule.NtHeader.OptionalHeader.ImageBase, bytes, bytes.Length, ref count))
                throw new Exception();

            ByteViewer.SetBytes(bytes);
        }
    }
}
