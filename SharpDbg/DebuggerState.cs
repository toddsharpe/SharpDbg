using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpDbg
{
    public enum DebuggerState
    {
        NotRunning,
        ProcessOpened,
        Running,
        Breakpoint,
        Singlestep
    }
}
