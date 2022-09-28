using System;
using System.Runtime.InteropServices;

namespace APCInjection.Imports
{
    class Imports
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool CreateProcess(
            string lpApplicationName, 
            string lpCommandLine, 
            IntPtr lpProcessAttributes, 
            IntPtr lpThreadAttributes, 
            bool bInheritHandles,
            uint dwCreationFlags, 
            IntPtr lpEnvironment, 
            string lpCurrentDirectory, 
            ref STARTUPINFO lpStartupInfo, 
            ref PROCESS_INFORMATION lpProcessInformation
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint ResumeThread(IntPtr hThhread);

        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        public static class CreationFlags
        {
            public const uint SUSPENDED = 0x4;
        }
    }
}
