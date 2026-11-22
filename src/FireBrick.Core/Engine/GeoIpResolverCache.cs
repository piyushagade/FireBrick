using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using FireBrick.Core.Models;

namespace FireBrick.Core.Engine;

/// <summary>
/// Throttled asynchronous GeoIP & Organization/ASN lookup cache for public remote IP addresses.
/// Automatically skips RFC1918 private, loopback, and link-local addresses.
/// </summary>
public sealed class GeoIpResolverCache
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromMilliseconds(1800) };
    private readonly ConcurrentDictionary<string, GeoIpInfoDto> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _concurrency = new(4, 4);

    public GeoIpInfoDto? TryGetCached(string ipAddress)
    {
        return _cache.TryGetValue(ipAddress, out var info) ? info : null;
    }

    public static bool IsPrivateOrLocalIp(string ipAddress)
    {
        if (string.IsNullOrWhiteSpace(ipAddress) || ipAddress == "*")
            return true;

        if (!IPAddress.TryParse(ipAddress, out var ip))
            return true;

        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any))
            return true;

        var bytes = ip.GetAddressBytes();
        if (bytes.Length == 4)
        {
            if (bytes[0] == 10) return true;
            if (bytes[0] == 127) return true;
            if (bytes[0] == 169 && bytes[1] == 254) return true;
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            if (bytes[0] >= 224) return true; // Multicast / reserved
        }
        else if (bytes.Length == 16)
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast)
                return true;
            if ((bytes[0] & 0xFE) == 0xFC) // Unique local fc00::/7
                return true;
        }

        return false;
    }

    public async Task<GeoIpInfoDto> ResolveAsync(string ipAddress, CancellationToken ct = default)
    {
        if (IsPrivateOrLocalIp(ipAddress))
        {
            return new GeoIpInfoDto { IpAddress = ipAddress, CountryCode = "LAN", Org = "Local Network" };
        }

        if (_cache.TryGetValue(ipAddress, out var cached))
            return cached;

        await _concurrency.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_cache.TryGetValue(ipAddress, out cached))
                return cached;

            var url = $"http://ip-api.com/json/{Uri.EscapeDataString(ipAddress)}?fields=status,countryCode,country,city,org,as";
            using var resp = await Http.GetAsync(url, ct).ConfigureAwait(false);
            if (resp.IsSuccessStatusCode)
            {
                var json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                if (root.TryGetProperty("status", out var status) && status.GetString() == "success")
                {
                    var info = new GeoIpInfoDto
                    {
                        IpAddress = ipAddress,
                        CountryCode = root.TryGetProperty("countryCode", out var cc) ? cc.GetString() ?? string.Empty : string.Empty,
                        CountryName = root.TryGetProperty("country", out var cn) ? cn.GetString() ?? string.Empty : string.Empty,
                        City = root.TryGetProperty("city", out var ctEl) ? ctEl.GetString() ?? string.Empty : string.Empty,
                        Org = root.TryGetProperty("org", out var orgEl) ? orgEl.GetString() ?? string.Empty : string.Empty,
                        Asn = root.TryGetProperty("as", out var asEl) ? asEl.GetString() ?? string.Empty : string.Empty
                    };
                    _cache[ipAddress] = info;
                    return info;
                }
            }
        }
        catch
        {
            // Swallow transient network/timeout errors
        }
        finally
        {
            _concurrency.Release();
        }

        var empty = new GeoIpInfoDto { IpAddress = ipAddress };
        _cache[ipAddress] = empty;
        return empty;
    }
}
