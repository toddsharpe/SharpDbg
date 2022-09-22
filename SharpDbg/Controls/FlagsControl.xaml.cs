using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
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
using SharpDbg.Annotations;

namespace SharpDbg.Controls
{
    /// <summary>
    /// Interaction logic for FlagsControl.xaml
    /// </summary>
    public partial class FlagsControl : UserControl
    {
        public ObservableCollection<FlagViewModel> Flags { get; }

        private uint _value;

        public FlagsControl()
        {
            InitializeComponent();
            
            //Create the rows
            Flags = new ObservableCollection<FlagViewModel>
            {
                new FlagViewModel {Bit = 0, Abbreviation = "CF", Description = "Carry"},
                new FlagViewModel {Bit = 1, Abbreviation = "R ", Description = "Reserved"},
                new FlagViewModel {Bit = 2, Abbreviation = "PF", Description = "Parity"},
                new FlagViewModel {Bit = 3, Abbreviation = "", Description = "Reserved"},
                new FlagViewModel {Bit = 4, Abbreviation = "AF", Description = "Adjust"},
                new FlagViewModel {Bit = 5, Abbreviation = "", Description = "Reserved"},
                new FlagViewModel {Bit = 6, Abbreviation = "ZF", Description = "Zero"},
                new FlagViewModel {Bit = 7, Abbreviation = "SF", Description = "Sign"},
                new FlagViewModel {Bit = 8, Abbreviation = "TF", Description = "Trap"},
                new FlagViewModel {Bit = 9, Abbreviation = "IF", Description = "Interrupt"},
                new FlagViewModel {Bit = 10, Abbreviation = "DF", Description = "Direction"},
                new FlagViewModel {Bit = 11, Abbreviation = "OF", Description = "OVerflow"},
                new FlagViewModel {Bit = 12, Abbreviation = "IOPL", Description = "IO Privledge"},
                new FlagViewModel {Bit = 13, Abbreviation = "IOPL", Description = "IO Privledge"},
                new FlagViewModel {Bit = 14, Abbreviation = "NT", Description = "Nested Task"},
                new FlagViewModel {Bit = 15, Abbreviation = "", Description = "Reserved"}
            };

            DataGrid.ItemsSource = Flags;
        }

        public void SetFlags(uint value)
        {
            _value = value;

            int mask = 1;
            for (int i = 0; i < 16; i++)
            {
                Flags[i].Value = ((mask & value) != 0);
                mask = mask << 1;
            }
        }
    }
}
