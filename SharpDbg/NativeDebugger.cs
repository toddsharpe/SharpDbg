using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.RightsManagement;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SharpDbg.Interop;
using SharpDbg.Models;

namespace SharpDbg
{
    public class NativeDebugger
    {
        public string FullFileName { get; private set; }
        public string FileName { get; private set; }

        public DebuggerState State { get; private set; } = DebuggerState.NotRunning;

        //Events
        public EventHandler<NativeProcess> OnProcessCreated;
        public EventHandler<EXIT_PROCESS_DEBUG_INFO> OnProcessExited;
        public EventHandler<CREATE_THREAD_DEBUG_INFO> OnThreadCreated;
        public EventHandler<EXIT_THREAD_DEBUG_INFO> OnThreadExited;
        public EventHandler<LOAD_DLL_DEBUG_INFO> OnDllLoaded;
        public EventHandler<Process> OnProcessUpdated;
        public EventHandler<uint> OnBreakpointHit;
        public EventHandler<NativeProcess> OnImportsUpdated;
        public EventHandler OnEntryPoint;

        public EventHandler<CONTEXT> OnContextChanged;
        public EventHandler<string> OnDebugEvent;
        public EventHandler<string> OnDebugPrint; 

        private readonly Thread _thread;
        private readonly Dictionary<IntPtr, string> _modules;

        private readonly ManualResetEvent _inputEvent;

        private readonly Dictionary<uint, Breakpoint> _breakpoints;
        private bool _firstBreakpoint;
        private uint _lastBreakpointAddress;//So we can patch it again on single step

        private CONTEXT _context;
        public NativeProcess Process { get; private set; }

        public NativeDebugger(string path)
        {
            FullFileName = path;
            FileName = Path.GetFileName(path);

            _inputEvent = new ManualResetEvent(false);

            _thread = new Thread(() =>
            {
                DoLoadProcess();
                State = DebuggerState.ProcessOpened;
                _inputEvent.WaitOne();
                State = DebuggerState.Running;
                DebugProcess();
            }) { Name = "Debug Thread" };

            _firstBreakpoint = true;
            _modules = new Dictionary<IntPtr, string>();

            _breakpoints = new Dictionary<uint, Breakpoint>();
            _context = new CONTEXT { ContextFlags = CONTEXT_FLAGS.CONTEXT_ALL };
        }

        public void Resume()
        {
            _inputEvent.Set();
        }

        public void StepInto()
        {
            _context.EFlags |= 0x100;
            _inputEvent.Set();
        }

        public void StepOver()
        {
            
        }

        public void StepOut()
        {
            
        }

        public void Pause()
        {
            _inputEvent.Reset();
        }

        public void OpenProcess()
        {
            _thread.Start();
        }

        public void CloseProcess()
        {
            _thread.Abort();
            Kernel32.TerminateProcess(Process.ProcessHandle, 0);
            Kernel32.CloseHandle(Process.ProcessHandle);
        }

        public void StartDebug()
        {
            _inputEvent.Set();
        }

        //TODO: Atuomatically determine to flush cache based on EIP
        public void SetBreakpoint(uint address)
        {
            if (_breakpoints.ContainsKey(address))
                throw new Exception("BP Already assigned");

            Breakpoint breakpoint = new Breakpoint(Process.ProcessHandle, address);
            breakpoint.Enable();
            _breakpoints.Add(address, breakpoint);

            //Read and save instruction
            FlushBreakpoint(breakpoint);
        }


        //TODO: Automatically determine to flush cache based on EIP
        public void ClearBreakpoint(uint address, bool flush = false)
        {
            if (!_breakpoints.ContainsKey(address))
                throw new Exception("BP Already cleared");

            Breakpoint breakpoint = _breakpoints[address];
            breakpoint.Disable();

            _breakpoints.Remove(address);
        }

        private void FlushBreakpoint(Breakpoint breakpoint)
        {
            bool result = Kernel32.FlushInstructionCache(Process.ProcessHandle, (IntPtr)breakpoint.Address, breakpoint.Length);
            if (!result)
                throw new Exception();
        }

        private void DoLoadProcess()
        {
            //Start the process
            STARTUPINFO si = new STARTUPINFO { cb = (uint)Marshal.SizeOf<STARTUPINFO>() };
            PROCESS_INFORMATION pi;
            Kernel32.CreateProcess(FullFileName, null, IntPtr.Zero, IntPtr.Zero, false, ProcessCreationFlags.DEBUG_ONLY_THIS_PROCESS, IntPtr.Zero, null, ref si, out pi);

            //Eat the first event here, the ProcessCreated event
            DEBUG_EVENT DebugEv = new DEBUG_EVENT();
            bool wait = Kernel32.WaitForDebugEvent(ref DebugEv, Kernel32.INFINITE);
            if (!wait)
                throw new Exception();

            if (DebugEv.dwDebugEventCode != DebugEventType.CREATE_PROCESS_DEBUG_EVENT)
                throw new Exception();

            Process = new NativeProcess(pi.hProcess, DebugEv.CreateProcessInfo.lpBaseOfImage);
            Process.LoadImports();

            uint dwContinueStatus = OnCreateProcessDebugEvent(ref DebugEv);
            Kernel32.ContinueDebugEvent(DebugEv.dwProcessId, DebugEv.dwThreadId, dwContinueStatus);
        }



        private void DebugProcess()
        {

            uint dwContinueStatus = Kernel32.DBG_CONTINUE;
            DEBUG_EVENT DebugEv = new DEBUG_EVENT();
            
            //Start the debug loop
            while (true)
            {

                bool wait = Kernel32.WaitForDebugEvent(ref DebugEv, Kernel32.INFINITE);
                switch (DebugEv.dwDebugEventCode)
                {
                    case DebugEventType.EXCEPTION_DEBUG_EVENT:
                        var info = DebugEv.Exception;
                        IntPtr threadHandle = Kernel32.OpenThread(Kernel32.ThreadAccess.GET_CONTEXT | Kernel32.ThreadAccess.SET_CONTEXT, false, DebugEv.dwThreadId);
                        if (!Kernel32.GetThreadContext(threadHandle, ref _context))
                            throw new Exception();

                        OnProcessUpdated?.Invoke(this, Process.Process);

                        switch (info.ExceptionRecord.ExceptionCode)
                        {
                            case Kernel32.EXCEPTION_ACCESS_VIOLATION:
                                // First chance: Pass this on to the system. 
                                // Last chance: Display an appropriate error.
                                string output = String.Format("EXCEPTION_ACCESS_VIOLATION: {0} 0x{1:X8}. First: {2}",
                                    info.ExceptionRecord.ExceptionInformation[0] == 1 ? "write" : "read", info.ExceptionRecord.ExceptionInformation[1], info.dwFirstChance);
                                OnDebugEvent?.Invoke(this, output);
                                return;//One access violation is enough for now
                                break;

                            case Kernel32.EXCEPTION_BREAKPOINT:
                                // First chance: Display the current 
                                // instruction and register values. 

                                if ((info.dwFirstChance == 0))
                                    dwContinueStatus = Kernel32.DBG_EXCEPTION_NOT_HANDLED;
                                else
                                {
                                    if (_firstBreakpoint)
                                    {
                                        //This is the break in NTDLL
                                        Process.UpdateImports();
                                        Process.LoadModules();
                                        OnImportsUpdated?.Invoke(this, Process);
                                        OnEntryPoint?.Invoke(this, EventArgs.Empty);

                                        //Patch message box
                                        //var function = Process.Imports["USER32.dll"].Single(i => i.Name == "MessageBoxA");
                                        //var debug = Process.Imports["KERNEL32.dll"].Single(i => i.Name == "OutputDebugStringA");
                                        //ImportPatcher.PatchImport(Process.ProcessHandle, (uint)Process.Address, function, debug);

                                        _firstBreakpoint = false;
                                    }
                                    else
                                    {
                                        //Fix EIP
                                        _context.Eip--;
                                        _lastBreakpointAddress = _context.Eip;
                                        OnBreakpointHit?.Invoke(this, _context.Eip);

                                        //Revert instruction
                                        if (_breakpoints.ContainsKey(_context.Eip))
                                        {
                                            Breakpoint breakpoint = _breakpoints[_context.Eip];
                                            breakpoint.Disable();
                                            FlushBreakpoint(breakpoint);

                                            //Set trap flag
                                            _context.EFlags |= 0x100;
                                        }
                                    }
                                    //Reports
                                    OnContextChanged?.Invoke(this, _context);

                                    //Wait for user input
                                    _inputEvent.Reset();

                                    _inputEvent.WaitOne();
                                    dwContinueStatus = Kernel32.DBG_CONTINUE;
                                }

                                break;

                            case Kernel32.EXCEPTION_DATATYPE_MISALIGNMENT:
                                // First chance: Pass this on to the system. 
                                // Last chance: Display an appropriate error. 
                                break;

                            case Kernel32.EXCEPTION_SINGLE_STEP:
                                // First chance: Update the display of the 
                                // current instruction and register values. 
                                if (_breakpoints.ContainsKey(_lastBreakpointAddress))
                                {
                                    Breakpoint b = _breakpoints[_lastBreakpointAddress];
                                    b.Enable();
                                    _lastBreakpointAddress = 0;
                                }

                                OnContextChanged?.Invoke(this, _context);
                                _inputEvent.Reset();

                                _inputEvent.WaitOne();
                                dwContinueStatus = Kernel32.DBG_CONTINUE;

                                break;

                            case Kernel32.DBG_CONTROL_C:
                                // First chance: Pass this on to the system. 
                                // Last chance: Display an appropriate error. 
                                break;

                            default:
                                // Handle other exceptions. 
                                break;
                        }

                        _context.Dr6 = 0;
                        if (!Kernel32.SetThreadContext(threadHandle, ref _context))
                        {
                            var error = Marshal.GetLastWin32Error();
                            throw new Exception();
                        }

                        if (!Kernel32.CloseHandle(threadHandle))
                            throw new Exception();

                        break;

                    case DebugEventType.CREATE_THREAD_DEBUG_EVENT:
                        // As needed, examine or change the thread's registers 
                        // with the GetThreadContext and SetThreadContext functions; 
                        // and suspend and resume thread execution with the 
                        // SuspendThread and ResumeThread functions. 

                        dwContinueStatus = OnCreateThreadDebugEvent(ref DebugEv);
                        break;

                    case DebugEventType.CREATE_PROCESS_DEBUG_EVENT:
                        // As needed, examine or change the registers of the
                        // process's initial thread with the GetThreadContext and
                        // SetThreadContext functions; read from and write to the
                        // process's virtual memory with the ReadProcessMemory and
                        // WriteProcessMemory functions; and suspend and resume
                        // thread execution with the SuspendThread and ResumeThread
                        // functions. Be sure to close the handle to the process image
                        // file with CloseHandle.

                        dwContinueStatus = OnCreateProcessDebugEvent(ref DebugEv);
                        break;

                    case DebugEventType.EXIT_THREAD_DEBUG_EVENT:
                        // Display the thread's exit code. 

                        dwContinueStatus = OnExitThreadDebugEvent(ref DebugEv);
                        break;

                    case DebugEventType.EXIT_PROCESS_DEBUG_EVENT:
                        // Display the process's exit code. 

                        dwContinueStatus = OnExitProcessDebugEvent(ref DebugEv);
                        break;

                    case DebugEventType.LOAD_DLL_DEBUG_EVENT:
                        // Read the debugging information included in the newly 
                        // loaded DLL. Be sure to close the handle to the loaded DLL 
                        // with CloseHandle.

                        dwContinueStatus = OnLoadDllDebugEvent(ref DebugEv);
                        break;

                    case DebugEventType.UNLOAD_DLL_DEBUG_EVENT:
                        // Display a message that the DLL has been unloaded. 

                        dwContinueStatus = OnUnloadDllDebugEvent(ref DebugEv);
                        break;

                    case DebugEventType.OUTPUT_DEBUG_STRING_EVENT:
                        // Display the output debugging string. 

                        dwContinueStatus = OnOutputDebugStringEvent(ref DebugEv);
                        break;

                    case DebugEventType.RIP_EVENT:
                        dwContinueStatus = OnRipEvent(ref DebugEv);
                        break;
                }

                if (!Kernel32.ContinueDebugEvent(DebugEv.dwProcessId, DebugEv.dwThreadId, dwContinueStatus))
                    throw new Exception();
            }
        }

        #region Events

        private uint OnCreateThreadDebugEvent(ref DEBUG_EVENT DebugEv)
        {
            CREATE_THREAD_DEBUG_INFO info = DebugEv.CreateThread;
            OnThreadCreated?.Invoke(this, info);

            string output = String.Format("Thread 0x{0:X8} (Id: {1}) created at: 0x{2:X8}", (uint)info.hThread, DebugEv.dwThreadId, (uint)info.lpStartAddress.Method.MethodHandle.GetFunctionPointer());
            OnDebugEvent?.Invoke(this, output);
            return Kernel32.DBG_CONTINUE;
        }

        private uint OnCreateProcessDebugEvent(ref DEBUG_EVENT DebugEv)
        {
            CREATE_PROCESS_DEBUG_INFO info = DebugEv.CreateProcessInfo;

            OnProcessCreated?.Invoke(this, Process);

            var name = Kernel32.GetFileNameFromHandle(info.hFile);
            _modules.Add(info.lpBaseOfImage, Path.GetFileName(name));

            string output = String.Format("Process (Id: {0}) created at 0x{1:X8}. Start:0x{2:X8}", DebugEv.dwProcessId, (uint)info.lpBaseOfImage, (uint)info.lpStartAddress);
            OnDebugEvent?.Invoke(this, output);

            return Kernel32.DBG_CONTINUE;
        }

        private uint OnExitThreadDebugEvent(ref DEBUG_EVENT DebugEv)
        {
            var info = DebugEv.ExitThread;
            OnThreadExited?.Invoke(this, info);

            string output = String.Format("The thread {0} exited with code: {1}", DebugEv.dwThreadId, info.dwExitCode);
            OnDebugEvent?.Invoke(this, output);
            return Kernel32.DBG_CONTINUE;
        }

        private uint OnExitProcessDebugEvent(ref DEBUG_EVENT DebugEv)
        {
            var info = DebugEv.ExitProcess;
            OnProcessExited?.Invoke(this, info);

            string output = String.Format("The process {0} exited with code: {1}", DebugEv.dwProcessId, info.dwExitCode);
            OnDebugEvent?.Invoke(this, output);
            return Kernel32.DBG_CONTINUE;
        }

        private uint OnLoadDllDebugEvent(ref DEBUG_EVENT DebugEv)
        {
            var info = DebugEv.LoadDll;
            var name = Kernel32.GetFileNameFromHandle(info.hFile);
            _modules.Add(info.lpBaseOfDll, Path.GetFileName(name));
            OnDllLoaded?.Invoke(this, info);

            string output = String.Format("{0} - Loaded at 0x{1:X8}", name, (uint)info.lpBaseOfDll);
            OnDebugEvent?.Invoke(this, output);
            return Kernel32.DBG_CONTINUE;
        }

        private uint OnUnloadDllDebugEvent(ref DEBUG_EVENT DebugEv)
        {
            var info = DebugEv.UnloadDll;
            if (_modules.ContainsKey(info.lpBaseOfDll))
            {
                string name = _modules[info.lpBaseOfDll];
                _modules.Remove(info.lpBaseOfDll);

                string output = String.Format("DLL '{0}' unloaded.", _modules[info.lpBaseOfDll]);
                OnDebugEvent?.Invoke(this, output);
            }
            else
            {
                
            }
            return Kernel32.DBG_CONTINUE;
        }

        private uint OnOutputDebugStringEvent(ref DEBUG_EVENT DebugEv)
        {
            var info = DebugEv.DebugString;
            uint bytesRead = 0;
            string debugString;

            if (info.fUnicode != 0)
            {
                byte[] buffer = new byte[info.nDebugStringLength * 2 - 1];
                Kernel32.ReadProcessMemory(Process.ProcessHandle, info.lpDebugStringData, buffer, buffer.Length, ref bytesRead);
                debugString = Encoding.Unicode.GetString(buffer);
            }
            else
            {
                byte[] buffer = new byte[info.nDebugStringLength - 1];
                Kernel32.ReadProcessMemory(Process.ProcessHandle, info.lpDebugStringData, buffer, buffer.Length, ref bytesRead);
                debugString = Encoding.ASCII.GetString(buffer);
            }
            
            OnDebugPrint?.Invoke(this, debugString);
            return Kernel32.DBG_CONTINUE;
        }

        private uint OnRipEvent(ref DEBUG_EVENT DebugEv)
        {
            var info = DebugEv.RipInfo;
            return Kernel32.DBG_CONTINUE;
        }

        #endregion
    }
}
