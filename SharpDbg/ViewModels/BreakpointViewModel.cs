using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpDbg.Controls;

namespace SharpDbg.ViewModels
{
    public class BreakpointViewModel : BaseViewModel
    {
        private bool _isEnabled;

        public bool IsEnabled
        {
            get
            {
                return _isEnabled;
            }
            set
            {
                if (_isEnabled != value)
                {
                    _isEnabled = value;
                    OnPropertyChanged();
                }
            }
        }

        public uint Address { get; set; }

        public string Label { get; set; }

        private int _hitCount;

        public int HitCount
        {
            get { return _hitCount; }
            set
            {
                if (_hitCount != value)
                {
                    _hitCount = value;
                    Changed = true;
                    OnPropertyChanged();
                }
            }
        }

        public BreakpointViewModel(uint address)
        {
            Address = address;
            _isEnabled = true;
            _hitCount = 0;
        }
    }
}
