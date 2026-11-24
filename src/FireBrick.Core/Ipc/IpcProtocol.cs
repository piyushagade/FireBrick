using System.Text;
using System.Text.Json;

namespace FireBrick.Core.Ipc;

public static class IpcConstants
{
    public const string PipeName = "FireBrick_IPC_v1";
}

public static class IpcCommands
{
    public const string Ping = "Ping";
    public const string GetStatus = "GetStatus";
    public const string SetProfileMode = "SetProfileMode";
    public const string SetNotificationMode = "SetNotificationMode";
    public const string GetRules = "GetRules";
    public const string CreateRule = "CreateRule";
    public const string UpdateRule = "UpdateRule";
    public const string DeleteRule = "DeleteRule";
    public const string SetRuleEnabled = "SetRuleEnabled";
    public const string CleanupInvalidRules = "CleanupInvalidRules";
    public const string GetRecentEvents = "GetRecentEvents";
    public const string GetActiveConnections = "GetActiveConnections";
    public const string GetTemporaryRules = "GetTemporaryRules";
    public const string CreateQuickRule = "CreateQuickRule";
    public const string RemoveTemporaryRule = "RemoveTemporaryRule";
    public const string EnableAuditPolicy = "EnableAuditPolicy";
    public const string KillConnectionsForApp = "KillConnectionsForApp";
    public const string SetRuleLock = "SetRuleLock";
    public const string GetRuleLockAlerts = "GetRuleLockAlerts";
    public const string SyncBlocklist = "SyncBlocklist";
    public const string RemoveBlocklist = "RemoveBlocklist";
    public const string GetCurrentNetworkName = "GetCurrentNetworkName";
    public const string GetAutoRules = "GetAutoRules";
    public const string SaveAutoRules = "SaveAutoRules";
    public const string RecordAutoRuleHit = "RecordAutoRuleHit";
    public const string GetHostsFile = "GetHostsFile";
    public const string SaveHostsEntries = "SaveHostsEntries";
    public const string SaveHostsRaw = "SaveHostsRaw";
    public const string RestoreHostsBackup = "RestoreHostsBackup";
    public const string FlushDnsCache = "FlushDnsCache";
    public const string GetBandwidthStatus = "GetBandwidthStatus";
    public const string SetBandwidthMode = "SetBandwidthMode";
    public const string GetBandwidthRules = "GetBandwidthRules";
    public const string SaveBandwidthRule = "SaveBandwidthRule";
    public const string DeleteBandwidthRule = "DeleteBandwidthRule";
    public const string GetBandwidthUsage = "GetBandwidthUsage";
    public const string InstallWinDivertAddon = "InstallWinDivertAddon";
}

public sealed class IpcRequest
{
    public string Command { get; set; } = string.Empty;
    public string? PayloadJson { get; set; }
}

public sealed class IpcResponse
{
    public bool Success { get; set; }
    public string? Error { get; set; }
    public string? PayloadJson { get; set; }

    public static IpcResponse Ok(object? payload = null) => new()
    {
        Success = true,
        PayloadJson = payload == null ? null : JsonSerializer.Serialize(payload)
    };

    public static IpcResponse Fail(string error) => new()
    {
        Success = false,
        Error = error
    };
}

public sealed class UpdateRulePayload
{
    public string OriginalName { get; set; } = string.Empty;
    public Models.FirewallRuleDto Rule { get; set; } = new();
}

public sealed class ToggleRulePayload
{
    public string RuleName { get; set; } = string.Empty;
    public bool Enabled { get; set; }
}

public sealed class QuickRulePayload
{
    public string ApplicationPath { get; set; } = string.Empty;
    public Models.RuleAction Action { get; set; } = Models.RuleAction.Allow;
    public Models.RuleDirection Direction { get; set; } = Models.RuleDirection.Outbound;
    public int? TemporaryMinutes { get; set; }
}

public sealed class SetBandwidthModePayload
{
    public Models.BandwidthLimiterMode Mode { get; set; } = Models.BandwidthLimiterMode.Disabled;
    public bool AutoUnloadWinDivertWhenIdle { get; set; } = true;
}

public static class PipeFraming
{
    public static async Task WriteMessageAsync<T>(Stream stream, T message, CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(message);
        var payload = Encoding.UTF8.GetBytes(json);
        var lengthBytes = BitConverter.GetBytes(payload.Length);
        await stream.WriteAsync(lengthBytes, ct).ConfigureAwait(false);
        await stream.WriteAsync(payload, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    public static async Task<T?> ReadMessageAsync<T>(Stream stream, CancellationToken ct)
    {
        var lengthBuf = new byte[4];
        int read = await ReadExactAsync(stream, lengthBuf, ct).ConfigureAwait(false);
        if (read < 4) return default;

        int length = BitConverter.ToInt32(lengthBuf, 0);
        if (length <= 0 || length > 32 * 1024 * 1024)
            throw new InvalidDataException($"Invalid IPC message length: {length}");

        var payload = new byte[length];
        read = await ReadExactAsync(stream, payload, ct).ConfigureAwait(false);
        if (read < length) return default;

        var json = Encoding.UTF8.GetString(payload);
        return JsonSerializer.Deserialize<T>(json);
    }

    private static async Task<int> ReadExactAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total), ct).ConfigureAwait(false);
            if (n == 0) break;
            total += n;
        }
        return total;
    }
}
