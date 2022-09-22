using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
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
using Microsoft.Win32;
using SharpDbg.Interop;
using SharpDbg.Models;
using SharpDbg.ViewModels;
using SharpDisasm;
using SharpDisasm.Udis86;

namespace SharpDbg
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private NativeDebugger _debugger;
        private readonly ObservableCollection<BreakpointViewModel> _breakpoints;
        public MainWindow()
        {
            InitializeComponent();

            _breakpoints = DisassemblyControl.Breakpoints;
            BreakpointGrid.ItemsSource = _breakpoints;
        }

        private void OpenMenuItem_OnClick(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog();
            dialog.Filter = "Executables (.exe)|*.exe";
            var result = dialog.ShowDialog();
            if ((!result.HasValue) || (!result.Value))
                return;

            //Wiring all the events here sounds stupid, maybe ill fix this
            _debugger = new NativeDebugger(dialog.FileName);
            _debugger.OnThreadCreated += OnThreadCreated;
            _debugger.OnContextChanged += (o, context) =>
            {
                ContextControl.Dispatcher.Invoke(() => {ContextControl.SetContext(context); });
                FlagsControl.Dispatcher.Invoke(() => { FlagsControl.SetFlags(context.EFlags); });
                DisassemblyControl.Dispatcher.Invoke(() => { DisassemblyControl.SetCurrentLine(context.Eip); });
                StackViewControl.Dispatcher.Invoke(() => StackViewControl.SetESP(context.Esp, ((NativeDebugger)o).Process));
            };
            _debugger.OnEntryPoint += (o, s) =>
            {
                var debugger = (NativeDebugger) o;
                MemoryViewControl.Dispatcher.Invoke(() => MemoryViewControl.SetModule(debugger.Process));
            };
            _debugger.OnDebugEvent += (o, s) =>
            {
                DebugEventTextBlock.Dispatcher.Invoke(() => DebugEventTextBlock.Text += s + Environment.NewLine);
            };
            _debugger.OnDebugPrint += (o, s) =>
            {
                DebugPrintTextBlock.Dispatcher.Invoke(() => DebugPrintTextBlock.Text += s + Environment.NewLine);
            };
            _debugger.OnProcessCreated += (o, p) =>
            {
                ImportTreeView.Dispatcher.Invoke(() => SetImports(p.Imports));

                DisassemblyControl.Dispatcher.Invoke(() => DisassemblyControl.SetCodeBytes(p.MainModule));
                //GraphDisassemblyControl.Dispatcher.Invoke(() => GraphDisassemblyControl.SetModule(p.MainModule));
                Dispatcher.Invoke(() => AddBreakpoint(p.MainModule.AddressOfCode, "Entry Point"));
            };
            _debugger.OnProcessUpdated += (o, process) =>
            {
                ProcessViewControl.Dispatcher.Invoke(() => ProcessViewControl.SetProcess(process));
            };
            _debugger.OnBreakpointHit += (o, a) =>
            {
                var breakpoint = _breakpoints.SingleOrDefault(i => i.Address == a);
                if (breakpoint != null)
                    breakpoint.HitCount++;
            };
            _debugger.OnImportsUpdated += (o, a) =>
            {
                DisassemblyControl.Dispatcher.Invoke(() => DisassemblyControl.UpdateReferenceStrings(a));
            };
            _debugger.OpenProcess();
        }

        private void AddBreakpoint(uint address, string label = null)
        {
            //Add to local model
            _breakpoints.Add(new BreakpointViewModel(address) { Label = label });


        }

        private void SetImports(Dictionary<string, List<ImportedFunction>> imports)
        {
            ImportTreeView.Items.Clear();
            foreach (var import in imports)
            {
                TreeViewItem item = new TreeViewItem { Header = import.Value, ItemsSource = import.Value.Select(i => i.Name) };
                ImportTreeView.Items.Add(item);
            }
        }

        private void OnThreadCreated(object sender, CREATE_THREAD_DEBUG_INFO createThreadDebugInfo)
        {
            
        }

        private void ActionButton_OnClick(object sender, RoutedEventArgs e)
        {
            if (_debugger.State == DebuggerState.ProcessOpened)
            {
                _debugger.StartDebug();
                ((Button) sender).Content = "Continue";
            }
            else if (_debugger.State != DebuggerState.NotRunning)
            {
                _debugger.Resume();
            }
        }

        private void PauseButton_OnClick(object sender, RoutedEventArgs e)
        {
            _debugger.Pause();
        }

        private void StepIntoButton_OnClick(object sender, RoutedEventArgs e)
        {
            _debugger.StepInto();
        }

        private void MainWindow_OnClosed(object sender, EventArgs e)
        {
            _debugger?.CloseProcess();
        }

        private void ToggleButton_OnUnchecked(object sender, RoutedEventArgs e)
        {
            var item = ((CheckBox)sender).Tag as BreakpointViewModel;

            //Remove from debugger
            _debugger.ClearBreakpoint(item.Address);
        }

        private void ToggleButton_OnChecked(object sender, RoutedEventArgs e)
        {
            var item = ((CheckBox)sender).Tag as BreakpointViewModel;

            //Add to debugger
            _debugger.SetBreakpoint(item.Address);
        }
    }
}
