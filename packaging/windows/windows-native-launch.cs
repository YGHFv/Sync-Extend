using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SyncExtend.Windows
{
    // The object is created only from this invocation's CreateProcess result.
    // PID lookups never substitute for the original kernel process HANDLE.
    public sealed class LoggedProcess : IDisposable
    {
        private readonly SafeProcessHandle process;
        private readonly int id;
        private bool disposed;
        private string observedImage;

        private LoggedProcess(IntPtr originalHandle, uint originalPid)
        {
            process = new SafeProcessHandle(originalHandle, true);
            id = unchecked((int)originalPid);
        }

        public int Id { get { EnsureOpen(); return id; } }
        public IntPtr Handle { get { EnsureOpen(); return process.DangerousGetHandle(); } }
        public bool OriginalHandleReturnedByCreateProcess { get { return true; } }
        public bool OriginalWaitVerified { get; private set; }
        public bool ImageObservedFromOriginalHandle { get { return observedImage != null; } }

        public DateTime StartTime
        {
            get
            {
                EnsureOpen();
                FileTime created, exited, kernel, user;
                if (!GetProcessTimes(process, out created, out exited, out kernel, out user))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                long birth = checked((long)(((ulong)created.High << 32) | created.Low));
                return DateTime.FromFileTimeUtc(birth);
            }
        }

        public ImageIdentity MainModule
        {
            get
            {
                EnsureOpen();
                if (observedImage == null)
                {
                    var value = new StringBuilder(32768);
                    uint length = (uint)value.Capacity;
                    if (!QueryFullProcessImageName(process, 0, value, ref length))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    observedImage = value.ToString();
                }
                return new ImageIdentity(observedImage);
            }
        }

        public bool HasExited { get { return WaitOriginal(0); } }

        public int ExitCode
        {
            get
            {
                EnsureOpen();
                if (!HasExited) throw new InvalidOperationException("The original process is still active.");
                uint code;
                if (!GetExitCodeProcess(process, out code))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return unchecked((int)code);
            }
        }

        public bool WaitForExit(int milliseconds)
        {
            if (milliseconds < -1) throw new ArgumentOutOfRangeException("milliseconds");
            bool exited = WaitOriginal(milliseconds == -1 ? UInt32.MaxValue : (uint)milliseconds);
            if (exited) OriginalWaitVerified = true;
            return exited;
        }

        public void WaitForExit()
        {
            WaitForExit(-1);
        }

        public void Kill()
        {
            EnsureOpen();
            if (!TerminateProcess(process, UInt32.MaxValue))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        public void Dispose()
        {
            if (disposed) return;
            disposed = true;
            process.Dispose();
        }

        private bool WaitOriginal(uint milliseconds)
        {
            EnsureOpen();
            uint result = WaitForSingleObject(process, milliseconds);
            if (result == 0) return true;
            if (result == 0x102) return false;
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        private void EnsureOpen()
        {
            if (disposed) throw new ObjectDisposedException("LoggedProcess");
        }

        public sealed class ImageIdentity
        {
            internal ImageIdentity(string fileName) { FileName = fileName; }
            public string FileName { get; private set; }
        }

        public static LoggedProcess Start(
            string image, string[] arguments, string workingDirectory,
            string standardOutputPath, string standardErrorPath)
        {
            string executable = Path.GetFullPath(image);
            string directory = Path.GetFullPath(workingDirectory);
            string output = Path.GetFullPath(standardOutputPath);
            string error = Path.GetFullPath(standardErrorPath);
            if (String.Equals(output, error, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("The two original log paths must be distinct.");

            var command = new StringBuilder(QuoteArgument(executable));
            foreach (string argument in arguments)
            {
                command.Append(' ');
                command.Append(QuoteArgument(argument));
            }
            if (command.Length >= 32767)
                throw new ArgumentException("The native command line exceeds the Windows limit.");

            var security = new SecurityAttributes();
            security.Length = Marshal.SizeOf(typeof(SecurityAttributes));
            security.InheritHandle = true;
            IntPtr attributes = IntPtr.Zero;
            IntPtr inheritedValues = IntPtr.Zero;
            bool initialized = false;
            using (SafeFileHandle input = OpenInheritedFile(
                "NUL", 0x80000000, 3, ref security, 3, 0x80, IntPtr.Zero))
            using (SafeFileHandle stdout = OpenInheritedFile(
                output, 0x40000000, 1, ref security, 1, 0x00200080, IntPtr.Zero))
            using (SafeFileHandle stderr = OpenInheritedFile(
                error, 0x40000000, 1, ref security, 1, 0x00200080, IntPtr.Zero))
            {
                try
                {
                    IntPtr bytes = IntPtr.Zero;
                    bool measured = InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref bytes);
                    int measureError = Marshal.GetLastWin32Error();
                    if (measured || measureError != 122 || bytes.ToInt64() <= 0 ||
                        bytes.ToInt64() > Int32.MaxValue)
                        throw new Win32Exception(measureError);
                    attributes = Marshal.AllocHGlobal(bytes);
                    if (!InitializeProcThreadAttributeList(attributes, 1, 0, ref bytes))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    initialized = true;
                    inheritedValues = Marshal.AllocHGlobal(IntPtr.Size * 3);
                    Marshal.WriteIntPtr(inheritedValues, 0, input.DangerousGetHandle());
                    Marshal.WriteIntPtr(inheritedValues, IntPtr.Size, stdout.DangerousGetHandle());
                    Marshal.WriteIntPtr(inheritedValues, IntPtr.Size * 2, stderr.DangerousGetHandle());
                    if (!UpdateProcThreadAttribute(
                        attributes, 0, new IntPtr(0x00020002), inheritedValues,
                        new IntPtr(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero))
                        throw new Win32Exception(Marshal.GetLastWin32Error());

                    var startup = new StartupInfoEx();
                    startup.Startup.Size = (uint)Marshal.SizeOf(typeof(StartupInfoEx));
                    startup.Startup.Flags = 0x00000101; // USESTDHANDLES | USESHOWWINDOW
                    startup.Startup.ShowWindow = 0; // SW_HIDE
                    startup.Startup.StandardInput = input.DangerousGetHandle();
                    startup.Startup.StandardOutput = stdout.DangerousGetHandle();
                    startup.Startup.StandardError = stderr.DangerousGetHandle();
                    startup.Attributes = attributes;
                    ProcessInformation created;
                    // Inherit only the three fresh handles in HANDLE_LIST.
                    // No process-global standard-handle flag is changed.
                    if (!CreateProcess(
                        executable, command, IntPtr.Zero, IntPtr.Zero, true,
                        0x08080000, IntPtr.Zero, directory, ref startup, out created))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    using (var thread = new SafeWaitHandle(created.Thread, true))
                    {
                        return new LoggedProcess(created.Process, created.ProcessId);
                    }
                }
                finally
                {
                    if (initialized) DeleteProcThreadAttributeList(attributes);
                    if (inheritedValues != IntPtr.Zero) Marshal.FreeHGlobal(inheritedValues);
                    if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
                }
            }
        }

        private static string QuoteArgument(string value)
        {
            if (value == null || value.IndexOf('\0') >= 0)
                throw new ArgumentException("A native argument is null or contains NUL.");
            var quoted = new StringBuilder("\"");
            int backslashes = 0;
            foreach (char character in value)
            {
                if (character == '\\') { backslashes++; continue; }
                if (character == '"')
                {
                    quoted.Append('\\', backslashes * 2 + 1);
                    quoted.Append('"');
                }
                else
                {
                    quoted.Append('\\', backslashes);
                    quoted.Append(character);
                }
                backslashes = 0;
            }
            quoted.Append('\\', backslashes * 2);
            quoted.Append('"');
            return quoted.ToString();
        }

        private static SafeFileHandle OpenInheritedFile(
            string path, uint access, uint sharing, ref SecurityAttributes security,
            uint disposition, uint attributes, IntPtr template)
        {
            SafeFileHandle handle = CreateFile(
                path, access, sharing, ref security, disposition, attributes, template);
            if (handle.IsInvalid)
            {
                int failure = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(failure);
            }
            return handle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            public int Length;
            public IntPtr Descriptor;
            [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StartupInfo
        {
            public uint Size;
            public IntPtr Reserved, Desktop, Title;
            public uint X, Y, Width, Height, XCountChars, YCountChars, FillAttribute, Flags;
            public ushort ShowWindow, ReservedBytes;
            public IntPtr ReservedData, StandardInput, StandardOutput, StandardError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StartupInfoEx
        {
            public StartupInfo Startup;
            public IntPtr Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInformation
        {
            public IntPtr Process, Thread;
            public uint ProcessId, ThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileTime { public uint Low, High; }

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(
            string path, uint access, uint sharing, ref SecurityAttributes security,
            uint disposition, uint attributes, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(
            IntPtr list, int count, uint flags, ref IntPtr bytes);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(
            IntPtr list, uint flags, IntPtr attribute, IntPtr value,
            IntPtr bytes, IntPtr previous, IntPtr returnedBytes);

        [DllImport("kernel32.dll")]
        private static extern void DeleteProcThreadAttributeList(IntPtr list);

        [DllImport("kernel32.dll", EntryPoint = "CreateProcessW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcess(
            string application, StringBuilder command, IntPtr processSecurity,
            IntPtr threadSecurity, [MarshalAs(UnmanagedType.Bool)] bool inherit,
            uint flags, IntPtr environment, string directory,
            ref StartupInfoEx startup, out ProcessInformation process);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(SafeProcessHandle process, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetProcessTimes(
            SafeProcessHandle process, out FileTime created, out FileTime exited,
            out FileTime kernel, out FileTime user);

        [DllImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW",
            CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryFullProcessImageName(
            SafeProcessHandle process, uint flags, StringBuilder image, ref uint characters);
    }
}
