using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Cryptography;
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
using SharpDbg.ViewModels;
using SharpDisasm;
using SharpDisasm.Udis86;

namespace SharpDbg.Controls
{
    /// <summary>
    /// Interaction logic for DisassemblyControl.xaml
    /// </summary>
    public partial class DisassemblyControl : UserControl
    {
        private ObservableCollection<InstructionViewModel> _instructions;
        private uint _currentLine;

        public ObservableCollection<BreakpointViewModel> Breakpoints { get; private set; } = new ObservableCollection<BreakpointViewModel>();

        public DisassemblyControl()
        {
            InitializeComponent();
        }

        public void SetCodeBytes(NativeModule module)//Should be an Interface
        {
            NativeModuleSection codeSection = module.GetCodeSection();
            var disasm = new Disassembler(codeSection.Data, ArchitectureMode.x86_32, module.AddressOfCode, true);
            var bindTo = disasm.Disassemble().Select(i =>
            {
                InstructionViewModel model = new InstructionViewModel(i);
                if ((i.Mnemonic == ud_mnemonic_code.UD_Ipush) && (i.Operands[0].LvalUDWord > module.NtHeader.OptionalHeader.ImageBase))
                {
                    try
                    {
                        model.ReferenceString = NativeHelpers.GetRemoteString(module.ProcessHandle, (IntPtr)i.Operands[0].LvalUDWord);
                    }
                    catch (Exception)
                    {

                    }
                }

                return model;
            });
            _instructions = new ObservableCollection<InstructionViewModel>(bindTo);
            DisassemblyGrid.ItemsSource = _instructions;
        }

        public void SetCurrentLine(uint address)
        {
            var current = _instructions.SingleOrDefault(i => i.Address == _currentLine);
            if (current != null)
                current.RemoveHighlight();

            _currentLine = address;
            var next = _instructions.SingleOrDefault(i => i.Address == _currentLine);
            if (next != null)
                next.Highlight();
        }

        private void ToggleBreakpointMenuItem_OnClick(object sender, RoutedEventArgs e)
        {
            if (DisassemblyGrid.SelectedItems.Count == 0)
                return;

            InstructionViewModel selected = DisassemblyGrid.SelectedItems[0] as InstructionViewModel;

            var found = Breakpoints.SingleOrDefault(i => i.Address == selected.Address);
            if (found != null)
            {
                Breakpoints.Remove(found);
            }
            else
            {
                Breakpoints.Add(new BreakpointViewModel((uint)selected.Address));
            }
        }

        public void UpdateReferenceStrings(NativeProcess process)
        {
            foreach (InstructionViewModel model in _instructions)
            {
                var i = model.Instruction;
                if (i.Mnemonic == ud_mnemonic_code.UD_Icall)
                {
                    try
                    {
                        uint address = NativeHelpers.GetRemoteDWord(process.ProcessHandle, (IntPtr)i.Operands[0].LvalUDWord);
                        string name = process.GetImportByAddress(address);
                        if (name != null)
                            model.ReferenceString = name;
                    }
                    catch (Exception)
                    {
                        
                    }
                }
            }
        }

        //Not only does this code error out in SharpDisasm, but it takes FOREVER to run, maybe rendering all the code sections for each module is a bad idea...especially considering you cant set a break point in a shared kernel dll...
        //public void LoadCodeRegions(IEnumerable<CodeRegion> regions, NativeDebugger debugger)
        //{
        //    IEnumerable<InstructionViewModel> bindTo = null;
        //    foreach (CodeRegion region in regions)
        //    {
        //        var disasm = new Disassembler(region.Code, ArchitectureMode.x86_32, region.Address, true);
        //        var delta = disasm.Disassemble().Select(i =>
        //        {
        //            InstructionViewModel model = new InstructionViewModel(i);
        //            if ((i.Mnemonic == ud_mnemonic_code.UD_Ipush) && (i.Operands[0].LvalUDWord > debugger.NtHeader.OptionalHeader.ImageBase))
        //            {
        //                try
        //                {
        //                    model.ReferenceString = debugger.GetRemoteString(i.Operands[0].LvalUDWord - debugger.NtHeader.OptionalHeader.ImageBase);
        //                }
        //                catch (Exception)
        //                {

        //                }
        //            }

        //            return model;
        //        });

        //        if (bindTo != null)
        //            bindTo = bindTo.Concat(delta);
        //        else
        //            bindTo = delta;

        //    }
        //    _instructions = new ObservableCollection<InstructionViewModel>(bindTo);

        //    DisassemblyGrid.ItemsSource = _instructions;
        //}
    }
}
