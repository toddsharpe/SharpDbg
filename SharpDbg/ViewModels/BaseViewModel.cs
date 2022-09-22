using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Media;
using SharpDbg.Annotations;

namespace SharpDbg.Controls
{
    public abstract class BaseViewModel : INotifyPropertyChanged
    {
        private bool _changed;

        public bool Changed
        {
            get { return _changed; }
            set
            {
                if (_changed != value)
                {
                    _changed = value;
                    OnPropertyChanged();
                    Brush = _changed ? Brushes.Red : Brushes.Black;
                    OnPropertyChanged(nameof(Brush));
                }
            }
        }

        public Brush Brush { get; set; } = Brushes.Black;

        public event PropertyChangedEventHandler PropertyChanged;

        [NotifyPropertyChangedInvocator]
        protected virtual void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
