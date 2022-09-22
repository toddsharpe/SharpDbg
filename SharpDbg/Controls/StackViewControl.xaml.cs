using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
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
using SharpDbg.ViewModels;

namespace SharpDbg.Controls
{
    /// <summary>
    /// Interaction logic for StackViewControl.xaml
    /// </summary>
    public partial class StackViewControl : UserControl
    {
        private const int Rows = 10;

        private ObservableCollection<StackElementViewModel> _collection;
        public StackViewControl()
        {
            InitializeComponent();

            
        }

        public void SetESP(uint esp, NativeProcess process)
        {
            uint read = 0;
            byte[] buffer = new byte[4];
            _collection = new ObservableCollection<StackElementViewModel>();
            int halfway = Rows / 2;
            for (int i = -halfway; i < Rows; i++)
            {
                StackElementViewModel model = new StackElementViewModel();
                model.Offset = i*4;
                model.Address = (uint)(esp + model.Offset);

                bool result = Kernel32.ReadProcessMemory(process.ProcessHandle, (IntPtr) model.Address, buffer, buffer.Length, ref read);
                if (!result)
                    throw new Exception();
                model.Value = BitConverter.ToUInt32(buffer, 0);
                try
                {
                    model.Reference = NativeHelpers.GetRemoteString(process.ProcessHandle, (IntPtr)model.Value);
                }
                catch (Exception)
                {
                    
                }

                _collection.Add(model);
            }

            StackDataGrid.ItemsSource = _collection;
        }
    }
}
