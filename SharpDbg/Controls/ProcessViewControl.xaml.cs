using System;
using System.Collections.Generic;
using System.Diagnostics;
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

namespace SharpDbg.Controls
{
    /// <summary>
    /// Interaction logic for ProcessViewControl.xaml
    /// </summary>
    public partial class ProcessViewControl : UserControl
    {
        private static readonly List<string> HideModuleColumnList = new List<string> { "FileVersionInfo", "Site", "Container"};
        private static readonly List<string> HideThreadColumnList = new List<string> { "StartTime", "PrivilegedProcessorTime", "TotalProcessorTime", "UserProcessorTime", "Site", "Container" };

        public ProcessViewControl()
        {
            InitializeComponent();
        }

        public void SetProcess(Process process)
        {
            ModulesDataGrid.ItemsSource = process.Modules;
            ThreadsDataGrid.ItemsSource = process.Threads;
        }

        private void ModulesDataGrid_OnAutoGeneratingColumn(object sender, DataGridAutoGeneratingColumnEventArgs e)
        {
            e.Cancel = HideModuleColumnList.Contains(e.PropertyName);
        }

        private void ThreadsDataGrid_OnAutoGeneratingColumn(object sender, DataGridAutoGeneratingColumnEventArgs e)
        {
            e.Cancel = HideThreadColumnList.Contains(e.PropertyName);
        }
    }
}
