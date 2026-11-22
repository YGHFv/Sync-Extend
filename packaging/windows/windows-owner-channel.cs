using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SyncExtend.Windows
{
    // A deserialized receipt cannot construct this owner or its original
    // stdin channel. Only this invocation's Process.Start reaches the factory.
    public sealed class OwnerProcess
    {
        private OwnerProcess(Process original, OwnerChannel stdout, Task<OwnerCapture> stderr)
        {
            Original = original;
            Stdout = stdout;
            Stderr = stderr;
        }
        public Process Original { get; private set; }
        public OwnerChannel Stdout { get; private set; }
        public Task<OwnerCapture> Stderr { get; private set; }
        public Task<OwnerCapture> FailedStartStdout { get; private set; }

        public static OwnerProcess Start(string image, string[] arguments)
        {
            var info = new ProcessStartInfo();
            info.FileName = Path.GetFullPath(image);
            info.WorkingDirectory = Path.GetDirectoryName(info.FileName);
            info.UseShellExecute = false;
            info.CreateNoWindow = true;
            info.RedirectStandardInput = true;
            info.RedirectStandardOutput = true;
            info.RedirectStandardError = true;
            foreach (string argument in arguments) info.ArgumentList.Add(argument);
            Process original = Process.Start(info);
            var owner = new OwnerProcess(original, null, null);
            try
            {
                owner.Stdout = new OwnerChannel(original.StandardOutput.BaseStream, 1048576);
                owner.Stderr = OwnerChannel.DrainHashAsync(original.StandardError.BaseStream);
                return owner;
            }
            catch (Exception failure)
            {
                // A failed wrapper construction still owns this exact child.
                // EOF closes its native resources; preserve the created prefix.
                // Keep the actual object reachable if any closure observation
                // fails, rather than disposing an unverified original.
                bool originalWait = false;
                bool stdoutConsumed = false;
                bool stderrConsumed = false;
                try { original.StandardInput.Close(); } catch { }
                try
                {
                    if (owner.Stdout == null)
                        owner.Stdout = new OwnerChannel(original.StandardOutput.BaseStream, 1048576);
                    owner.FailedStartStdout = owner.Stdout.DrainAsync();
                }
                catch { }
                try
                {
                    if (owner.Stderr == null)
                        owner.Stderr = OwnerChannel.DrainHashAsync(original.StandardError.BaseStream);
                }
                catch { }
                try
                {
                    original.WaitForExit();
                    originalWait = original.HasExited;
                }
                catch { }
                try
                {
                    if (owner.FailedStartStdout != null)
                    {
                        owner.FailedStartStdout.GetAwaiter().GetResult();
                        stdoutConsumed = owner.Stdout.Capture != null;
                    }
                }
                catch { }
                try
                {
                    if (owner.Stderr != null)
                    {
                    owner.Stderr.GetAwaiter().GetResult();
                        stderrConsumed = true;
                    }
                }
                catch { }
                if (originalWait && stdoutConsumed && stderrConsumed)
                {
                    owner.Stdout.Dispose();
                    original.Dispose();
                }
                else
                    failure.Data["SyncExtendOriginalProtectedProcess"] = owner;
                throw;
            }
        }

        public async Task WriteJsonLineAsync(string json)
        {
            if (json == null || json.IndexOf('\r') >= 0 || json.IndexOf('\n') >= 0)
                throw new InvalidDataException("Use one JSON control request.");
            byte[] bytes = new UTF8Encoding(false, true).GetBytes(json + "\n");
            if (bytes.Length > 4096)
                throw new InvalidDataException("The original owner request exceeds its byte limit.");
            // Write the original stdin bytes directly; no shell or console
            // encoding participates in the protected owner protocol.
            await Original.StandardInput.BaseStream.WriteAsync(bytes, 0, bytes.Length).ConfigureAwait(false);
            await Original.StandardInput.BaseStream.FlushAsync().ConfigureAwait(false);
        }

        public void CloseInput()
        {
            Original.StandardInput.Close();
        }
    }

    public sealed class OwnerFrame
    {
        internal OwnerFrame(string json, int wireBytes, string wireSha256)
        {
            Json = json;
            WireBytes = wireBytes;
            WireSha256 = wireSha256;
        }
        public string Json { get; private set; }
        public int WireBytes { get; private set; }
        public string WireSha256 { get; private set; }
    }

    public sealed class OwnerCapture
    {
        internal OwnerCapture(long bytes, string sha256) { Bytes = bytes; Sha256 = sha256; }
        public long Bytes { get; private set; }
        public string Sha256 { get; private set; }
    }

    // This channel owns the original stdout stream. Each read is bounded, and
    // raw bytes are hashed before decoding; no protected content is logged.
    public sealed class OwnerChannel : IDisposable
    {
        private readonly Stream stream;
        private readonly int maxFrameBytes;
        private readonly byte[] buffer = new byte[4096];
        private readonly SemaphoreSlim reader = new SemaphoreSlim(1, 1);
        private readonly IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private readonly UTF8Encoding utf8 = new UTF8Encoding(false, true);
        private int available, offset;
        private long total;
        private bool eof, disposed;
        public OwnerCapture Capture { get; private set; }

        public OwnerChannel(Stream originalStdout, int maximumFrameBytes)
        {
            if (maximumFrameBytes < 1 || maximumFrameBytes > 1048576)
                throw new ArgumentOutOfRangeException("maximumFrameBytes");
            stream = originalStdout;
            maxFrameBytes = maximumFrameBytes;
        }

        public async Task<OwnerFrame> ReadNextAsync()
        {
            await reader.WaitAsync().ConfigureAwait(false);
            try
            {
                EnsureOpen();
                using (var line = new MemoryStream())
                {
                    while (true)
                    {
                        if (offset == available && !await FillAsync().ConfigureAwait(false))
                        {
                            if (line.Length != 0)
                                throw new InvalidDataException("The original owner closed an incomplete JSONL frame.");
                            return null;
                        }
                        byte value = buffer[offset++];
                        line.WriteByte(value);
                        if (line.Length > maxFrameBytes + 2L)
                            throw new InvalidDataException("The original owner JSONL frame exceeds its byte limit.");
                        if (value != 10) continue;
                        byte[] bytes = line.ToArray();
                        int length = bytes.Length - 1;
                        if (length > 0 && bytes[length - 1] == 13) length--;
                        if (length > maxFrameBytes)
                            throw new InvalidDataException("The original owner JSONL payload exceeds its byte limit.");
                        string json = utf8.GetString(bytes, 0, length);
                        string digest;
                        using (var frameHash = SHA256.Create())
                            digest = Hex(frameHash.ComputeHash(bytes));
                        return new OwnerFrame(json, bytes.Length, digest);
                    }
                }
            }
            finally { reader.Release(); }
        }

        public async Task<OwnerCapture> DrainAsync()
        {
            await reader.WaitAsync().ConfigureAwait(false);
            try
            {
                EnsureOpen();
                // FillAsync already hashed every byte in this original read.
                offset = available;
                while (await FillAsync().ConfigureAwait(false)) offset = available;
                return Capture;
            }
            finally { reader.Release(); }
        }

        private async Task<bool> FillAsync()
        {
            if (eof) return false;
            available = await stream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
            offset = 0;
            if (available == 0)
            {
                eof = true;
                Capture = new OwnerCapture(total, Hex(hash.GetHashAndReset()));
                return false;
            }
            total = checked(total + available);
            hash.AppendData(buffer, 0, available);
            return true;
        }

        public static async Task<OwnerCapture> DrainHashAsync(Stream originalStderr)
        {
            using (var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
            {
                var bytes = new byte[4096];
                long total = 0;
                int count;
                while ((count = await originalStderr.ReadAsync(bytes, 0, bytes.Length).ConfigureAwait(false)) != 0)
                {
                    total = checked(total + count);
                    digest.AppendData(bytes, 0, count);
                }
                return new OwnerCapture(total, Hex(digest.GetHashAndReset()));
            }
        }

        private static string Hex(byte[] bytes)
        {
            var result = new StringBuilder(bytes.Length * 2);
            foreach (byte value in bytes) result.Append(value.ToString("x2"));
            return result.ToString();
        }

        private void EnsureOpen()
        {
            if (disposed) throw new ObjectDisposedException("OwnerChannel");
        }

        public void Dispose()
        {
            if (disposed) return;
            if (!eof) throw new InvalidOperationException("The original owner stdout EOF remains unverified.");
            disposed = true;
            hash.Dispose();
            reader.Dispose();
            // The original Process disposes its streams after both captures
            // and the original process wait have actually completed.
        }
    }
}
