using System.IO.Pipes;
using System.Text.Json;

namespace FireBrick.Core.Ipc;

/// <summary>
/// Named Pipe client for communicating with the privileged FireBrick.Service background daemon.
/// </summary>
public sealed class FireBrickIpcClient
{
    public async Task<bool> IsServiceAvailableAsync(CancellationToken ct = default)
    {
        try
        {
            var resp = await SendAsync(IpcCommands.Ping, null, 1500, ct).ConfigureAwait(false);
            return resp.Success;
        }
        catch
        {
            return false;
        }
    }

    public async Task<IpcResponse> SendAsync(string command, object? payload = null, int timeoutMs = 8000, CancellationToken ct = default)
    {
        using var pipe = new NamedPipeClientStream(".", IpcConstants.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(timeoutMs, ct).ConfigureAwait(false);

        var request = new IpcRequest
        {
            Command = command,
            PayloadJson = payload == null ? null : JsonSerializer.Serialize(payload)
        };

        await PipeFraming.WriteMessageAsync(pipe, request, ct).ConfigureAwait(false);
        var response = await PipeFraming.ReadMessageAsync<IpcResponse>(pipe, ct).ConfigureAwait(false);
        return response ?? IpcResponse.Fail("Empty response from FireBrick Service.");
    }

    public async Task<T?> SendAndDeserializeAsync<T>(string command, object? payload = null, int timeoutMs = 4000, CancellationToken ct = default)
    {
        var resp = await SendAsync(command, payload, timeoutMs, ct).ConfigureAwait(false);
        if (!resp.Success)
            throw new InvalidOperationException(resp.Error ?? $"IPC command {command} failed.");
        if (string.IsNullOrEmpty(resp.PayloadJson))
            return default;
        return JsonSerializer.Deserialize<T>(resp.PayloadJson);
    }
}
