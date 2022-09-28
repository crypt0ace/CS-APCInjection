using System;
using System.Runtime.InteropServices;

namespace APCInjection.Imports
{
    class Imports
    {
        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, ref IntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll")]
        public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation);
        [DllImport("kernel32.dll")]
        public static extern void Sleep(uint dwMilliseconds);
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, int dwThreadId);
        [DllImport("kernel32.dll")]
        public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);
        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);
        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(IntPtr handle, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32.dll")]
        public static extern uint ResumeThread(IntPtr hThread);


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
        public enum ThreadAccess : int
        {
            SET_CONTEXT = 0x0010
        }
        public static readonly UInt32 MEM_COMMIT = 0x1000;
        public static readonly UInt32 MEM_RESERVE = 0x2000;
        public static readonly UInt32 PAGE_EXECUTE_READ = 0x20;
        public static readonly UInt32 PAGE_READWRITE = 0x04;
    }
}
