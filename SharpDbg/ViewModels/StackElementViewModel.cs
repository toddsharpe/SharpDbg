using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.RightsManagement;
using System.Text;
using System.Threading.Tasks;
using SharpDbg.Controls;

namespace SharpDbg.ViewModels
{
    public class StackElementViewModel : BaseViewModel
    {
        public int Offset { get; set; }
        public uint Address { get; set; }
        public uint Value { get; set; }
        public string Reference { get; set; }
    }
}
