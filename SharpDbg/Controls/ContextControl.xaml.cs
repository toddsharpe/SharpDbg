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

namespace SharpDbg.Controls
{
    /// <summary>
    /// Interaction logic for ContextControl.xaml
    /// </summary>
    public partial class ContextControl : UserControl
    {
        private CONTEXT _context;
        public ObservableCollection<RegisterViewModel> Registers { get; }

        public ContextControl()
        {
            InitializeComponent();

            Registers = new ObservableCollection<RegisterViewModel>
            {
                new RegisterViewModel { Name = "EAX" },
                new RegisterViewModel { Name = "EBX" },
                new RegisterViewModel { Name = "ECX" },
                new RegisterViewModel { Name = "EDX" },
                new RegisterViewModel { Name = "ESP" },
                new RegisterViewModel { Name = "EBP" },
                new RegisterViewModel { Name = "ESI" },
                new RegisterViewModel { Name = "EDI" },
                new RegisterViewModel { Name = "EIP" }
            };
            RegistersGrid.ItemsSource = Registers;
        }

        public void SetContext(CONTEXT context)
        {
            _context = context;

            //Set registers
            Registers[0].Value = context.Eax;
            Registers[1].Value = context.Ebx;
            Registers[2].Value = context.Ecx;
            Registers[3].Value = context.Edx;
            Registers[4].Value = context.Esp;
            Registers[5].Value = context.Ebp;
            Registers[6].Value = context.Esi;
            Registers[7].Value = context.Edi;
            Registers[8].Value = context.Eip;
        }
    }
}
