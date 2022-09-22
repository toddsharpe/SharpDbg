using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpDbg.Controls
{
    public class RegisterViewModel : BaseViewModel
    {
        public string Name { get; set; }
        private uint _value;

        public uint Value
        {
            get
            {
                return _value;
            }
            set
            {
                if (_value != value)
                {
                    _value = value;
                    Changed = true;
                    OnPropertyChanged();
                }
                else
                {
                    Changed = false;
                }
            }
        }
    }
}
