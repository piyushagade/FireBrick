using System.Text.Json;
using FireBrick.Core.Models;

namespace FireBrick.Core.Engine;

/// <summary>
/// Persists FireBrick user and service settings as JSON.
/// </summary>
public sealed class SettingsStore
{
    private readonly string _path;
    private readonly object _lock = new();
    private AppSettingsDto _current;

    public SettingsStore(string? path = null)
    {
        _path = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "FireBrick",
            "settings.json");
        _current = LoadInternal();
    }

    public AppSettingsDto Get()
    {
        lock (_lock)
        {
            return _current;
        }
    }

    public void Save(AppSettingsDto settings)
    {
        lock (_lock)
        {
            _current = settings;
            try
            {
                var dir = Path.GetDirectoryName(_path);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                var json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_path, json);
            }
            catch
            {
                // Ignore IO write failure
            }
        }
    }

    private AppSettingsDto LoadInternal()
    {
        try
        {
            if (File.Exists(_path))
            {
                var json = File.ReadAllText(_path);
                return JsonSerializer.Deserialize<AppSettingsDto>(json) ?? new AppSettingsDto();
            }
        }
        catch { }

        return new AppSettingsDto();
    }
}
