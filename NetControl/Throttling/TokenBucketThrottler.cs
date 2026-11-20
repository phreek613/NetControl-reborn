using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;

namespace NetControl.Throttling
{
    /// <summary>
    /// Pure C# managed Token Bucket traffic shaper.
    /// Operates without external binary or OS-specific dependencies,
    /// providing universal cross-platform support for Windows, Linux, and macOS.
    /// </summary>
    public class TokenBucketThrottler : IBandwidthThrottler
    {
        public string InterfaceName { get; }

        private readonly ConcurrentDictionary<string, TokenBucket> _downloadBuckets = new();
        private readonly ConcurrentDictionary<string, TokenBucket> _uploadBuckets = new();
        private bool _isDisposed = false;

        public TokenBucketThrottler(string interfaceName)
        {
            InterfaceName = interfaceName ?? string.Empty;
        }

        public void SetLimits(IPAddress ip, int downloadLimitKbps, int uploadLimitKbps)
        {
            if (_isDisposed || ip == null) return;

            string key = ip.ToString();
            if (downloadLimitKbps <= 0)
            {
                _downloadBuckets.TryRemove(key, out _);
            }
            else
            {
                UpdateBucket(_downloadBuckets, key, downloadLimitKbps);
            }

            if (uploadLimitKbps <= 0)
            {
                _uploadBuckets.TryRemove(key, out _);
            }
            else
            {
                UpdateBucket(_uploadBuckets, key, uploadLimitKbps);
            }
        }

        private static void UpdateBucket(ConcurrentDictionary<string, TokenBucket> buckets, string key, int limitKbps)
        {
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
        }

        /// <summary>
        /// Evaluates whether a packet of the given size should be allowed through.
        /// Returns true if bandwidth allowance is available or if the IP is not throttled;
        /// returns false if the packet exceeds the rate limit budget.
        /// </summary>
        public bool AllowPacket(IPAddress ip, int packetSizeBytes)
        {
            if (_isDisposed || ip == null) return true;

            if (_downloadBuckets.TryGetValue(ip.ToString(), out var bucket))
            {
                return bucket.TryConsume(packetSizeBytes);
            }

            return true;
        }

        public void ResetAll()
        {
            _downloadBuckets.Clear();
            _uploadBuckets.Clear();
        }

        public void Dispose()
        {
            if (!_isDisposed)
            {
                _isDisposed = true;
                ResetAll();
            }
            GC.SuppressFinalize(this);
        }

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
                    double elapsedSeconds = (double)(now - _lastRefillTicks) / Stopwatch.Frequency;
                    _lastRefillTicks = now;

                    // Refill tokens
                    _tokens = Math.Min(_capacity, _tokens + elapsedSeconds * _rateBytesPerSec);

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

