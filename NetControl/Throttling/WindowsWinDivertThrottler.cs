using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;

namespace NetControl.Throttling
{
    public sealed class WindowsWinDivertThrottler : IBandwidthThrottler
    {
        private const int InvalidHandleValue = -1;
        private const uint PacketBufferSize = 65535;

        private readonly ConcurrentDictionary<string, TokenBucket> _downloadBuckets = new();
        private readonly ConcurrentDictionary<string, TokenBucket> _uploadBuckets = new();
        private readonly object _handleLock = new();
        private IntPtr _handle;
        private Thread _packetThread;
        private volatile bool _isRunning;
        private bool _isDisposed;

        public string InterfaceName { get; }

        public WindowsWinDivertThrottler(string interfaceName)
        {
            InterfaceName = interfaceName ?? string.Empty;
        }

        public void SetLimits(IPAddress ip, int downloadLimitKbps, int uploadLimitKbps)
        {
            if (_isDisposed || ip == null) return;

            string key = ip.ToString();
            UpdateBucket(_downloadBuckets, key, downloadLimitKbps);
            UpdateBucket(_uploadBuckets, key, uploadLimitKbps);

            if (downloadLimitKbps > 0 || uploadLimitKbps > 0)
            {
                StartPacketFilter();
            }
        }

        private static void UpdateBucket(
            ConcurrentDictionary<string, TokenBucket> buckets,
            string key,
            int limitKbps)
        {
            if (limitKbps <= 0)
            {
                buckets.TryRemove(key, out _);
                return;
            }

            long rateBytesPerSec = (long)limitKbps * 1024;
            long maxCapacity = Math.Max(rateBytesPerSec * 3 / 2, 4096);
            buckets.AddOrUpdate(
                key,
                _ => new TokenBucket(rateBytesPerSec, maxCapacity),
                (_, existing) =>
                {
                    existing.UpdateRate(rateBytesPerSec, maxCapacity);
                    return existing;
                });
        }

        public void RemoveLimit(IPAddress ip)
        {
            if (_isDisposed || ip == null) return;
            string key = ip.ToString();
            _downloadBuckets.TryRemove(key, out _);
            _uploadBuckets.TryRemove(key, out _);

            if (_downloadBuckets.IsEmpty && _uploadBuckets.IsEmpty)
            {
                StopPacketFilter();
            }
        }

        public void ResetAll()
        {
            _downloadBuckets.Clear();
            _uploadBuckets.Clear();
            StopPacketFilter();
        }

        private void StartPacketFilter()
        {
            lock (_handleLock)
            {
                if (_isRunning) return;

                IntPtr handle = WinDivertOpen("ip", 0, 1000, 0);
                if (handle == IntPtr.Zero || handle.ToInt64() == InvalidHandleValue)
                {
                    int error = Marshal.GetLastWin32Error();
                    Console.WriteLine($"[WINDIVERT] Failed to open packet filter. Win32 error {error}. Run as administrator.");
                    return;
                }

                _handle = handle;
                _isRunning = true;
                _packetThread = new Thread(PacketFilterLoop)
                {
                    IsBackground = true,
                    Name = "NetControl WinDivert Throttler"
                };
                _packetThread.Start();
                Console.WriteLine("[WINDIVERT] Windows packet throttling started.");
            }
        }

        private void StopPacketFilter()
        {
            lock (_handleLock)
            {
                _isRunning = false;
                IntPtr handle = _handle;
                _handle = IntPtr.Zero;

                if (handle != IntPtr.Zero)
                {
                    WinDivertClose(handle);
                }
            }

            _packetThread?.Join(TimeSpan.FromSeconds(2));
            _packetThread = null;
        }

        private void PacketFilterLoop()
        {
            IntPtr buffer = Marshal.AllocHGlobal((int)PacketBufferSize);
            IntPtr address = Marshal.AllocHGlobal(256);

            try
            {
                while (_isRunning)
                {
                    IntPtr handle;
                    lock (_handleLock)
                    {
                        handle = _handle;
                    }
                    if (handle == IntPtr.Zero) break;

                    bool received = WinDivertRecv(
                        handle,
                        buffer,
                        PacketBufferSize,
                        out uint receivedLength,
                        address);

                    if (!received)
                    {
                        if (!_isRunning) break;
                        Thread.Sleep(1);
                        continue;
                    }

                    bool allow = true;
                    byte[] packet = new byte[receivedLength];
                    Marshal.Copy(buffer, packet, 0, (int)receivedLength);

                    if (TryGetIpv4Addresses(packet, out byte[] sourceIp, out byte[] destinationIp))
                    {
                        string source = new IPAddress(sourceIp).ToString();
                        string destination = new IPAddress(destinationIp).ToString();

                        if (_uploadBuckets.TryGetValue(source, out TokenBucket uploadBucket))
                        {
                            allow = uploadBucket.TryConsume(packet.Length);
                        }
                        else if (_downloadBuckets.TryGetValue(destination, out TokenBucket downloadBucket))
                        {
                            allow = downloadBucket.TryConsume(packet.Length);
                        }
                    }

                    if (allow)
                    {
                        Marshal.Copy(packet, 0, buffer, packet.Length);
                        WinDivertSend(
                            handle,
                            buffer,
                            (uint)packet.Length,
                            out _,
                            address);
                    }
                }
            }
            catch (Exception ex)
            {
                if (_isRunning)
                {
                    Console.WriteLine($"[WINDIVERT] Packet filter error: {ex.Message}");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(address);
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static bool TryGetIpv4Addresses(
            byte[] packet,
            out byte[] sourceIp,
            out byte[] destinationIp)
        {
            sourceIp = null;
            destinationIp = null;

            if (packet.Length < 20) return false;
            if ((packet[0] >> 4) != 4) return false;

            int headerLength = (packet[0] & 0x0F) * 4;
            if (headerLength < 20 || packet.Length < headerLength) return false;

            sourceIp = new byte[4];
            destinationIp = new byte[4];
            Array.Copy(packet, 12, sourceIp, 0, 4);
            Array.Copy(packet, 16, destinationIp, 0, 4);
            return true;
        }

        public void Dispose()
        {
            if (_isDisposed) return;
            _isDisposed = true;
            ResetAll();
            GC.SuppressFinalize(this);
        }

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr WinDivertOpen(
            string filter,
            int layer,
            short priority,
            ulong flags);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl,
            SetLastError = true)]
        private static extern bool WinDivertRecv(
            IntPtr handle,
            IntPtr packet,
            uint packetLength,
            out uint receiveLength,
            IntPtr address);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl,
            SetLastError = true)]
        private static extern bool WinDivertSend(
            IntPtr handle,
            IntPtr packet,
            uint packetLength,
            out uint sendLength,
            IntPtr address);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern bool WinDivertClose(IntPtr handle);

        private sealed class TokenBucket
        {
            private long _rateBytesPerSec;
            private long _capacity;
            private double _tokens;
            private long _lastRefillTicks;
            private readonly object _bucketLock = new();

            public TokenBucket(long rateBytesPerSec, long capacity)
            {
                _rateBytesPerSec = rateBytesPerSec;
                _capacity = capacity;
                _tokens = capacity;
                _lastRefillTicks = Stopwatch.GetTimestamp();
            }

            public void UpdateRate(long newRateBytesPerSec, long newCapacity)
            {
                lock (_bucketLock)
                {
                    _rateBytesPerSec = newRateBytesPerSec;
                    _capacity = newCapacity;
                    if (_tokens > _capacity)
                    {
                        _tokens = _capacity;
                    }
                }
            }

            public bool TryConsume(int bytes)
            {
                lock (_bucketLock)
                {
                    long now = Stopwatch.GetTimestamp();
                    double elapsedSeconds =
                        (double)(now - _lastRefillTicks) / Stopwatch.Frequency;
                    _lastRefillTicks = now;

                    _tokens = Math.Min(
                        _capacity,
                        _tokens + elapsedSeconds * _rateBytesPerSec);

                    if (_tokens >= bytes)
                    {
                        _tokens -= bytes;
                        return true;
                    }
                    return false;
                }
            }
        }
    }
}
