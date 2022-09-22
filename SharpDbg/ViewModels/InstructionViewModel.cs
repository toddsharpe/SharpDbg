using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Media;
using SharpDbg.Controls;
using SharpDisasm;

namespace SharpDbg.ViewModels
{
    public class InstructionViewModel : BaseViewModel
    {
        public ulong Address { get; private set; }
        public Brush AddressBrush { get; private set; } = Brushes.White;

        public string BytesString { get; private set; }
        public string InstructionString { get; private set; }
        private string _referenceString;

        public string ReferenceString
        {
            get
            {
                return _referenceString;
            }
            set
            {
                if (_referenceString != value)
                {
                    _referenceString = value;
                    Changed = true;
                    OnPropertyChanged();
                }
                else
                {
                    Changed = false;
                }
            }
        }

        public Instruction Instruction { get; private set; }

        public InstructionViewModel(Instruction instruction)
        {
            Address = instruction.Offset;
            BytesString = BitConverter.ToString(instruction.Bytes).Replace('-', ' ');
            try
            {
                InstructionString = instruction.ToString();
            }
            catch (Exception)
            {
                InstructionString = null;
            }
            Instruction = instruction;
        }

        public void Highlight()
        {
            AddressBrush = Brushes.Yellow;
            OnPropertyChanged(nameof(AddressBrush));
        }

        public void RemoveHighlight()
        {
            AddressBrush = Brushes.White;
            OnPropertyChanged(nameof(AddressBrush));
        }
    }
}
