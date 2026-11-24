using System.Runtime.InteropServices;
using FireBrick.Core.Engine;
using FireBrick.Core.Interop;
using FireBrick.Core.Models;
using Xunit;

namespace FireBrick.Tests;

public sealed class BandwidthLimiterTests
{
    [Fact]
    public void WinDivertAddress_HasExact80ByteAbiSize()
    {
        Assert.Equal(80, Marshal.SizeOf<WinDivertAddress>());
    }

    [Fact]
    public void TokenBucket_UnlimitedRate_AlwaysAllows()
    {
        var bucket = new TokenBucket(0);
        Assert.True(bucket.TryConsume(1_000_000));
        Assert.True(bucket.TryConsume(1_000_000));
    }

    [Fact]
    public async Task TokenBucket_EnforcesBurstAndRefills()
    {
        // 64 KB/s with 0.25s burst => 16 KB capacity
        var bucket = new TokenBucket(64 * 1024, burstSeconds: 0.25);

        Assert.True(bucket.TryConsume(16 * 1024));
        Assert.False(bucket.TryConsume(4096));

        await Task.Delay(120);
        Assert.True(bucket.TryConsume(2048));
    }

    [Fact]
    public async Task BandwidthLimiterManager_PersistsAndExpiresRules()
    {
        var tempConfig = Path.Combine(Path.GetTempPath(), $"fb_bw_test_{Guid.NewGuid():N}.json");
        try
        {
            using var mgr = new BandwidthLimiterManager(configPath: tempConfig);
            var status = mgr.GetStatus();
            Assert.Equal(BandwidthLimiterMode.Disabled, status.Mode);

            var rule = await mgr.SaveRuleAsync(new BandwidthRuleDto
            {
                ApplicationPath = @"C:\Tools\curl.exe",
                DownloadLimitKBps = 512,
                UploadLimitKBps = 128,
                Enabled = true
            });

            Assert.Single(mgr.GetRules());
            Assert.Equal("curl.exe", rule.DisplayAppName);

            // Add an already-expired temporary rule and verify cleanup
            await mgr.SaveRuleAsync(new BandwidthRuleDto
            {
                ApplicationPath = @"C:\Tools\wget.exe",
                DownloadLimitKBps = 256,
                Enabled = true,
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1)
            });
            Assert.Equal(2, mgr.GetRules().Count);

            int removed = await mgr.CleanupExpiredRulesAsync();
            Assert.Equal(1, removed);
            Assert.Single(mgr.GetRules());

            // Reload from disk in a fresh instance
            using var mgr2 = new BandwidthLimiterManager(configPath: tempConfig);
            Assert.Single(mgr2.GetRules());
            Assert.Equal(512, mgr2.GetRules()[0].DownloadLimitKBps);

            await mgr2.DeleteRuleAsync(rule.Id);
            Assert.Empty(mgr2.GetRules());
        }
        finally
        {
            try { if (File.Exists(tempConfig)) File.Delete(tempConfig); } catch { }
        }
    }

    [Fact]
    public void BandwidthFormatting_FormatsRatesCorrectly()
    {
        Assert.Equal("Unlimited", BandwidthRuleDto.FormatRateKBps(0));
        Assert.Equal("512 KB/s", BandwidthRuleDto.FormatRateKBps(512));
        Assert.Equal("2.5 MB/s", BandwidthRuleDto.FormatRateKBps(2560));

        Assert.Equal("0 B/s", BandwidthAppUsageDto.FormatBps(0));
        Assert.Equal("500 B/s", BandwidthAppUsageDto.FormatBps(500));
        Assert.Equal("10 KB/s", BandwidthAppUsageDto.FormatBps(10 * 1024));
    }
}
