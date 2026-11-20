using System;
using System.Net;

namespace NetControl.Throttling
{
    /// <summary>
    /// Cross-platform abstraction for per-device network bandwidth throttling.
    /// </summary>
    public interface IBandwidthThrottler : IDisposable
    {
        string InterfaceName { get; }

        /// <summary>
        /// Sets independent download and upload limits for a target IP in KB/s.
        /// Zero disables that direction.
        /// </summary>
        void SetLimits(IPAddress ip, int downloadLimitKbps, int uploadLimitKbps);

        /// <summary>
        /// Removes any active bandwidth limit for the given target IP.
        /// </summary>
        void RemoveLimit(IPAddress ip);

        /// <summary>
        /// Resets and clears all active throttling rules on the interface.
        /// </summary>
        void ResetAll();
    }
}

