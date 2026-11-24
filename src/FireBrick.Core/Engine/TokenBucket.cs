using System.Diagnostics;

namespace FireBrick.Core.Engine;

/// <summary>
/// Thread-safe token bucket rate limiter operating in bytes per second.
/// </summary>
public sealed class TokenBucket
{
    private readonly object _lock = new();
    private long _bytesPerSecond;
    private double _capacityBytes;
    private double _tokens;
    private long _lastTimestamp;

    public TokenBucket(long bytesPerSecond, double burstSeconds = 0.25)
    {
        _lastTimestamp = Stopwatch.GetTimestamp();
        SetRate(bytesPerSecond, burstSeconds);
    }

    public long BytesPerSecond
    {
        get { lock (_lock) return _bytesPerSecond; }
    }

    public void SetRate(long bytesPerSecond, double burstSeconds = 0.25)
    {
        lock (_lock)
        {
            _bytesPerSecond = Math.Max(0, bytesPerSecond);
            if (_bytesPerSecond == 0)
            {
                _capacityBytes = 0;
                _tokens = 0;
                return;
            }

            // Allow at least 16 KB burst so standard MTU packets and TCP ACKs are never starved.
            _capacityBytes = Math.Max(_bytesPerSecond * Math.Clamp(burstSeconds, 0.05, 2.0), 16 * 1024);
            _tokens = Math.Min(_tokens == 0 ? _capacityBytes : _tokens, _capacityBytes);
        }
    }

    /// <summary>
    /// Attempts to consume <paramref name="bytes"/> from the bucket.
    /// Returns true if allowed (or if rate is 0 / unlimited), false if throttled.
    /// </summary>
    public bool TryConsume(int bytes)
    {
        if (bytes <= 0) return true;

        lock (_lock)
        {
            if (_bytesPerSecond <= 0)
                return true;

            long now = Stopwatch.GetTimestamp();
            double elapsedSeconds = (double)(now - _lastTimestamp) / Stopwatch.Frequency;
            _lastTimestamp = now;

            if (elapsedSeconds > 0)
            {
                _tokens = Math.Min(_capacityBytes, _tokens + elapsedSeconds * _bytesPerSecond);
            }

            if (_tokens >= bytes)
            {
                _tokens -= bytes;
                return true;
            }

            return false;
        }
    }
}
