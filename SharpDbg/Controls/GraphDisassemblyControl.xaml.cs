using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
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
using SharpDbg.Models;
using SharpDisasm;
using SharpDisasm.Translators;
using SharpDisasm.Udis86;

namespace SharpDbg.Controls
{
    /// <summary>
    /// Interaction logic for GraphDisassemblyControl.xaml
    /// </summary>
    public partial class GraphDisassemblyControl : UserControl
    {
        public GraphDisassemblyControl()
        {
            InitializeComponent();
        }

        public void SetModule(NativeModule module)
        {
            NativeModuleSection codeSection = module.GetCodeSection();
            var disasm = new Disassembler(codeSection.Data, ArchitectureMode.x86_32, module.AddressOfCode, true);
            GraphGenerator generator = new GraphGenerator(disasm.Disassemble().ToList(), module.EntryPoint);
            //generator.Generate(); // TODO: Enable
        }
    }
}
