using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpDbg.Models
{
    public class ImportedFunction
    {
        public string Name { get; set; }
        public uint NameRVA { get; set; }//Pointer to name
        public uint RVA { get; set; }//Pointer to address location
        public uint OriginalAddress { get; set; }
    }
}
