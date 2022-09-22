using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpDisasm;

namespace SharpDbg.Models
{
    public class BasicBlock
    {
        public uint Address { get; set; }
        public List<Instruction> Instructions { get; set; } = new List<Instruction>();
        public BasicBlock TrueBanch { get; set; }
        public BasicBlock FalseBranch { get; set; }
        public BasicBlock UnconditionalBranch { get; set; }
        public int Size { get; set; }
    }
}
