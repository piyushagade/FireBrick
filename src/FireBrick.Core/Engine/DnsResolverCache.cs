using System.Collections.Concurrent;
using System.Net;

namespace FireBrick.Core.Engine;

/// <summary>
/// Thread-safe asynchronous reverse DNS (PTR) cache with concurrency throttling and timeout protection.
/// </summary>
public sealed class DnsResolverCache
{
    private readonly ConcurrentDictionary<string, string> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _concurrency = new(6, 6);

    public string? TryGetCached(string ipAddress)
    {
        return _cache.TryGetValue(ipAddress, out var host) ? host : null;
    }

    public async Task<string> ResolveAsync(string ipAddress, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(ipAddress) ||
            ipAddress is "0.0.0.0" or "::" or "127.0.0.1" or "::1" or "*")
        {
            return string.Empty;
        }

        if (_cache.TryGetValue(ipAddress, out var cached))
            return cached;

        if (!IPAddress.TryParse(ipAddress, out var parsed))
            return string.Empty;

        await _concurrency.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_cache.TryGetValue(ipAddress, out cached))
                return cached;

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromMilliseconds(1200));

            var lookupTask = Dns.GetHostEntryAsync(parsed);
            var completed = await Task.WhenAny(lookupTask, Task.Delay(Timeout.Infinite, timeoutCts.Token)).ConfigureAwait(false);
            if (completed == lookupTask && lookupTask.IsCompletedSuccessfully)
            {
                var host = lookupTask.Result.HostName ?? string.Empty;
                if (string.Equals(host, ipAddress, StringComparison.OrdinalIgnoreCase))
                    host = string.Empty;

                _cache[ipAddress] = host;
                return host;
            }
        }
        catch
        {
            // Swallow DNS failures gracefully
        }
        finally
        {
            _concurrency.Release();
        }

        _cache[ipAddress] = string.Empty;
        return string.Empty;
    }

    public void Clear() => _cache.Clear();
}
