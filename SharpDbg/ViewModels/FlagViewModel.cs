using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpDbg.Controls
{
    public class FlagViewModel : BaseViewModel
    {
        public int Bit { get; set; }
        public string Abbreviation { get; set; }
        public string Description { get; set; }

        private bool? _value;
        public bool? Value
        {
            get { return _value; }
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
