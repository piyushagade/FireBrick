using FireBrick.App.Services;
using FireBrick.Core.Engine;
using FireBrick.Core.Models;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireBrick.App.Pages;

public sealed partial class HostsPage : Page
{
    private HostsFileDocumentDto _document = new();
    private bool _isBinding;
    private CancellationTokenSource? _toastDismissCts;

    public HostsPage()
    {
        InitializeComponent();
        Loaded += async (_, _) => await LoadHostsAsync();
        Unloaded += (_, _) =>
        {
            _toastDismissCts?.Cancel();
            _toastDismissCts?.Dispose();
            _toastDismissCts = null;
        };
    }

    private async Task LoadHostsAsync()
    {
        try
        {
            _document = await FirewallBackendService.Instance.GetHostsFileAsync();
            FilePathText.Text = string.IsNullOrWhiteSpace(_document.FilePath)
                ? @"C:\Windows\System32\drivers\etc\hosts"
                : _document.FilePath;
            RestoreBackupBtn.Visibility = _document.HasBackup ? Visibility.Visible : Visibility.Collapsed;
            RawEditorTextBox.Text = _document.RawContent;
            ApplyFilter();
        }
        catch (Exception ex)
        {
            ShowToast(InfoBarSeverity.Error, "Failed to load hosts file", ex.Message);
        }
    }

    private void ApplyFilter()
    {
        _isBinding = true;
        try
        {
            var query = SearchBox.Text?.Trim() ?? string.Empty;
            var filterTag = (FilterCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "All";

            IEnumerable<HostsEntryDto> items = _document.Entries;

            items = filterTag switch
            {
                "Enabled" => items.Where(e => e.Enabled),
                "Disabled" => items.Where(e => !e.Enabled),
                "Sinkhole" => items.Where(e => e.IsSinkhole),
                _ => items
            };

            if (!string.IsNullOrWhiteSpace(query))
            {
                items = items.Where(e =>
                    e.Address.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                    e.Hosts.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                    e.Comment.Contains(query, StringComparison.OrdinalIgnoreCase));
            }

            var filtered = items.ToList();
            HostsEntriesList.ItemsSource = filtered;
            EmptyStateText.Visibility = filtered.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

            int activeCount = _document.Entries.Count(e => e.Enabled);
            EntryCountText.Text = $"{activeCount} active / {_document.Entries.Count} total";
        }
        finally
        {
            _isBinding = false;
        }
    }

    private void SearchBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
        => ApplyFilter();

    private void FilterCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (HostsEntriesList != null)
            ApplyFilter();
    }

    private async void RefreshButton_Click(object sender, RoutedEventArgs e)
    {
        await LoadHostsAsync();
        ShowToast(InfoBarSeverity.Informational, "Hosts File Reloaded", $"Loaded {_document.Entries.Count} entry/entries from disk.");
    }

    private void RawModeToggle_Click(object sender, RoutedEventArgs e)
    {
        bool rawMode = RawModeToggle.IsChecked == true;
        TableViewContainer.Visibility = rawMode ? Visibility.Collapsed : Visibility.Visible;
        FilterBar.Visibility = rawMode ? Visibility.Collapsed : Visibility.Visible;
        RawViewContainer.Visibility = rawMode ? Visibility.Visible : Visibility.Collapsed;
        if (rawMode)
        {
            RawEditorTextBox.Text = _document.RawContent;
        }
    }

    private void DiscardRawButton_Click(object sender, RoutedEventArgs e)
    {
        RawEditorTextBox.Text = _document.RawContent;
        ShowToast(InfoBarSeverity.Informational, "Changes Discarded", "Restored editor contents to the saved hosts file.");
    }

    private async void SaveRawButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            _document = await FirewallBackendService.Instance.SaveHostsRawAsync(RawEditorTextBox.Text ?? string.Empty);
            RestoreBackupBtn.Visibility = _document.HasBackup ? Visibility.Visible : Visibility.Collapsed;
            ApplyFilter();
            ShowToast(InfoBarSeverity.Success, "Hosts File Saved", $"Saved raw hosts file ({_document.Entries.Count} parsed entries).");
        }
        catch (UnauthorizedAccessException)
        {
            ShowToast(InfoBarSeverity.Warning, "Administrator Permission Required",
                "Update FireBrickService or relaunch as Administrator to modify the Windows hosts file.");
        }
        catch (Exception ex)
        {
            ShowToast(InfoBarSeverity.Error, "Failed to Save Hosts File", ex.Message);
        }
    }

    private async void FlushDnsButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            bool ok = await FirewallBackendService.Instance.FlushDnsCacheAsync();
            ShowToast(
                ok ? InfoBarSeverity.Success : InfoBarSeverity.Warning,
                ok ? "DNS Cache Flushed" : "DNS Flush Failed",
                ok ? "Windows DNS resolver cache cleared. Hosts changes are active immediately." : "Could not run ipconfig /flushdns.");
        }
        catch (Exception ex)
        {
            ShowToast(InfoBarSeverity.Error, "DNS Flush Error", ex.Message);
        }
    }

    private async void RestoreBackupButton_Click(object sender, RoutedEventArgs e)
    {
        var confirm = new ContentDialog
        {
            Title = "Restore Hosts File Backup?",
            Content = "This will overwrite your current hosts file with the backup saved before FireBrick's first edit.",
            PrimaryButtonText = "Restore",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = XamlRoot
        };

        if (await confirm.ShowAsync() != ContentDialogResult.Primary)
            return;

        try
        {
            _document = await FirewallBackendService.Instance.RestoreHostsBackupAsync();
            RawEditorTextBox.Text = _document.RawContent;
            ApplyFilter();
            ShowToast(InfoBarSeverity.Success, "Backup Restored", "Restored hosts file from backup.");
        }
        catch (Exception ex)
        {
            ShowToast(InfoBarSeverity.Error, "Restore Failed", ex.Message);
        }
    }

    private async void EntryToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_isBinding) return;
        if (sender is not ToggleSwitch ts || ts.Tag is not HostsEntryDto entry) return;
        if (entry.Enabled == ts.IsOn) return;

        entry.Enabled = ts.IsOn;
        await PersistEntriesAsync(
            entry.Enabled ? "Entry Enabled" : "Entry Disabled",
            $"{entry.Address} → {entry.Hosts}");
    }

    private async void AddEntryButton_Click(object sender, RoutedEventArgs e)
    {
        var created = await ShowEntryDialogAsync(null);
        if (created == null) return;

        _document.Entries.Add(created);
        await PersistEntriesAsync("Host Entry Added", $"{created.Address} → {created.Hosts}");
    }

    private async void EditEntryButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not HostsEntryDto entry) return;
        var updated = await ShowEntryDialogAsync(entry);
        if (updated == null) return;

        entry.Address = updated.Address;
        entry.Hosts = updated.Hosts;
        entry.Comment = updated.Comment;
        entry.Enabled = updated.Enabled;
        await PersistEntriesAsync("Host Entry Updated", $"{entry.Address} → {entry.Hosts}");
    }

    private async void DeleteEntryButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not HostsEntryDto entry) return;

        _document.Entries.Remove(entry);
        await PersistEntriesAsync("Host Entry Deleted", $"Removed {entry.Hosts}");
    }

    private async Task PersistEntriesAsync(string successTitle, string successMessage)
    {
        try
        {
            _document = await FirewallBackendService.Instance.SaveHostsEntriesAsync(_document.Entries);
            RestoreBackupBtn.Visibility = _document.HasBackup ? Visibility.Visible : Visibility.Collapsed;
            RawEditorTextBox.Text = _document.RawContent;
            ApplyFilter();
            ShowToast(InfoBarSeverity.Success, successTitle, successMessage);
        }
        catch (UnauthorizedAccessException)
        {
            await LoadHostsAsync();
            ShowToast(InfoBarSeverity.Warning, "Administrator Permission Required",
                "Update FireBrickService (in Dashboard/Settings) or relaunch as Administrator to edit the hosts file.");
        }
        catch (Exception ex)
        {
            await LoadHostsAsync();
            ShowToast(InfoBarSeverity.Error, "Failed to Save Hosts File", ex.Message);
        }
    }

    private async Task<HostsEntryDto?> ShowEntryDialogAsync(HostsEntryDto? existing)
    {
        var ipBox = new TextBox
        {
            Header = "IP Address",
            PlaceholderText = "e.g. 0.0.0.0 or 127.0.0.1",
            Text = existing?.Address ?? "0.0.0.0"
        };

        var presetBar = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6 };
        Button MakePreset(string label, string ip)
        {
            var b = new Button { Content = label, Padding = new Thickness(8, 3, 8, 3), FontSize = 11 };
            b.Click += (_, _) => ipBox.Text = ip;
            return b;
        }
        presetBar.Children.Add(MakePreset("0.0.0.0 (Block)", "0.0.0.0"));
        presetBar.Children.Add(MakePreset("127.0.0.1 (Local)", "127.0.0.1"));
        presetBar.Children.Add(MakePreset("::1 (IPv6)", "::1"));

        var hostsBox = new TextBox
        {
            Header = "Hostname(s)",
            PlaceholderText = "e.g. telemetry.example.com ads.example.com",
            Text = existing?.Hosts ?? string.Empty
        };

        var commentBox = new TextBox
        {
            Header = "Comment (optional)",
            PlaceholderText = "e.g. Block telemetry",
            Text = existing?.Comment ?? string.Empty
        };

        var enabledCheck = new CheckBox
        {
            Content = "Enabled (active in hosts file)",
            IsChecked = existing?.Enabled ?? true
        };

        var errorText = new TextBlock
        {
            Foreground = new Microsoft.UI.Xaml.Media.SolidColorBrush(global::Windows.UI.Color.FromArgb(255, 239, 68, 68)),
            FontSize = 12,
            TextWrapping = TextWrapping.Wrap,
            Visibility = Visibility.Collapsed
        };

        var panel = new StackPanel { Spacing = 10, MinWidth = 380 };
        panel.Children.Add(ipBox);
        panel.Children.Add(presetBar);
        panel.Children.Add(hostsBox);
        panel.Children.Add(commentBox);
        panel.Children.Add(enabledCheck);
        panel.Children.Add(errorText);

        var dialog = new ContentDialog
        {
            Title = existing == null ? "Add Hosts Entry" : "Edit Hosts Entry",
            Content = panel,
            PrimaryButtonText = existing == null ? "Add" : "Save",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = XamlRoot
        };

        HostsEntryDto? result = null;
        dialog.PrimaryButtonClick += (_, args) =>
        {
            var candidate = new HostsEntryDto
            {
                Id = existing?.Id ?? Guid.NewGuid().ToString("N"),
                LineIndex = existing?.LineIndex ?? -1,
                Address = ipBox.Text?.Trim() ?? string.Empty,
                Hosts = hostsBox.Text?.Trim() ?? string.Empty,
                Comment = commentBox.Text?.Trim() ?? string.Empty,
                Enabled = enabledCheck.IsChecked == true
            };

            if (!HostsFileManager.ValidateEntry(candidate, out var err))
            {
                errorText.Text = err;
                errorText.Visibility = Visibility.Visible;
                args.Cancel = true;
                return;
            }

            result = candidate;
        };

        var dialogResult = await dialog.ShowAsync();
        return dialogResult == ContentDialogResult.Primary ? result : null;
    }

    private async void ShowToast(InfoBarSeverity severity, string title, string message, int lingerSeconds = 5)
    {
        _toastDismissCts?.Cancel();
        _toastDismissCts?.Dispose();
        var cts = new CancellationTokenSource();
        _toastDismissCts = cts;

        HostsToast.Severity = severity;
        HostsToast.Title = title;
        HostsToast.Message = message;
        HostsToast.IsOpen = true;

        try
        {
            await Task.Delay(TimeSpan.FromSeconds(lingerSeconds), cts.Token);
            if (!cts.IsCancellationRequested)
            {
                HostsToast.IsOpen = false;
            }
        }
        catch (TaskCanceledException)
        {
            // Replaced or manually dismissed
        }
    }

    private void HostsToast_Closed(InfoBar sender, InfoBarClosedEventArgs args)
    {
        _toastDismissCts?.Cancel();
    }
}
