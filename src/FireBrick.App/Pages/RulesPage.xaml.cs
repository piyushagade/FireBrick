using System.Collections.ObjectModel;
using FireBrick.App.Services;
using FireBrick.Core.Engine;
using FireBrick.Core.Interop;
using FireBrick.Core.Models;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireBrick.App.Pages;

public sealed partial class RulesPage : Page
{
    private List<FirewallRuleDto> _allRules = new();
    private readonly ObservableCollection<FirewallRuleDto> _filteredRules = new();
    private bool _suppressToggle;

    public RulesPage()
    {
        InitializeComponent();
        RulesListView.ItemsSource = _filteredRules;
        Loaded += async (_, _) =>
        {
            var pending = FirewallBackendService.Instance.PendingRulesSearchFilter;
            if (!string.IsNullOrWhiteSpace(pending))
            {
                FirewallBackendService.Instance.PendingRulesSearchFilter = null;
                SearchBox.Text = pending;
            }
            await LoadRulesAsync();
        };
    }

    private async Task LoadRulesAsync()
    {
        try
        {
            RuleCountSubtitle.Text = "Loading Windows Firewall rules...";
            _allRules = await FirewallBackendService.Instance.GetRulesAsync();
            ApplyFilters();
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Failed to load rules", ex.Message);
        }
    }

    private void ApplyFilters()
    {
        if (SearchBox == null || DirectionFilter == null || ActionFilter == null || StateFilter == null)
            return;

        _suppressToggle = true;
        try
        {
            var query = SearchBox.Text?.Trim() ?? string.Empty;
            var dirTag = (DirectionFilter.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "All";
            var actTag = (ActionFilter.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "All";
            var stateTag = (StateFilter.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "All";

            IEnumerable<FirewallRuleDto> q = _allRules;

            if (!string.IsNullOrWhiteSpace(query))
            {
                q = q.Where(r =>
                    r.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                    r.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                    r.ApplicationName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                    r.ExpandedApplicationPath.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                    r.Grouping.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                    r.DisplayGrouping.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                    r.RemotePorts.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                    r.LocalPorts.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                    r.RemoteAddresses.Contains(query, StringComparison.OrdinalIgnoreCase));
            }

            if (dirTag == "Outbound") q = q.Where(r => r.Direction == RuleDirection.Outbound);
            else if (dirTag == "Inbound") q = q.Where(r => r.Direction == RuleDirection.Inbound);

            if (actTag == "Allow") q = q.Where(r => r.Action == RuleAction.Allow);
            else if (actTag == "Block") q = q.Where(r => r.Action == RuleAction.Block);

            q = stateTag switch
            {
                "Enabled" => q.Where(r => r.Enabled),
                "Disabled" => q.Where(r => !r.Enabled),
                "Invalid" => q.Where(r => r.IsInvalidPath),
                "Temporary" => q.Where(r => r.IsTemporary),
                "FireBrick" => q.Where(r => r.Name.Contains("FireBrick", StringComparison.OrdinalIgnoreCase) ||
                                            r.Grouping.Contains("FireBrick", StringComparison.OrdinalIgnoreCase)),
                _ => q
            };

            var list = q.OrderBy(r => r.DisplayName, StringComparer.OrdinalIgnoreCase).Take(600).ToList();
            _filteredRules.Clear();
            foreach (var item in list)
                _filteredRules.Add(item);

            int invalidCount = _allRules.Count(r => r.IsInvalidPath);
            RuleCountSubtitle.Text = $"Showing {_filteredRules.Count:N0} of {_allRules.Count:N0} rules ({invalidCount} invalid paths)";
        }
        finally
        {
            _suppressToggle = false;
        }
    }

    private void FilterChanged(object sender, object e) => ApplyFilters();

    private async void RefreshButton_Click(object sender, RoutedEventArgs e) => await LoadRulesAsync();

    private async void RuleToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_suppressToggle) return;
        if (sender is not ToggleSwitch ts || ts.Tag is not FirewallRuleDto rule) return;
        if (rule.Enabled == ts.IsOn) return;

        try
        {
            await FirewallBackendService.Instance.SetRuleEnabledAsync(rule.Name, ts.IsOn);
            rule.Enabled = ts.IsOn;
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Cannot toggle rule", ex.Message);
            _suppressToggle = true;
            ts.IsOn = rule.Enabled;
            _suppressToggle = false;
        }
    }

    private async void NewRuleButton_Click(object sender, RoutedEventArgs e)
    {
        var dto = await ShowRuleEditorDialogAsync(null);
        if (dto == null) return;

        try
        {
            await FirewallBackendService.Instance.CreateRuleAsync(dto);
            ShowInfo(InfoBarSeverity.Success, "Rule Created", $"Created rule '{dto.Name}'.");
            await LoadRulesAsync();
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Failed to create rule", ex.Message);
        }
    }

    private async void EditRuleButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not FirewallRuleDto existing) return;
        var updated = await ShowRuleEditorDialogAsync(existing);
        if (updated == null) return;

        try
        {
            await FirewallBackendService.Instance.UpdateRuleAsync(existing.Name, updated);
            ShowInfo(InfoBarSeverity.Success, "Rule Updated", $"Updated rule '{updated.Name}'.");
            await LoadRulesAsync();
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Failed to update rule", ex.Message);
        }
    }

    private async void DeleteRuleButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not FirewallRuleDto rule) return;

        var confirm = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = "Delete Firewall Rule",
            Content = $"Permanently delete '{rule.Name}'?",
            PrimaryButtonText = "Delete",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close
        };

        if (await confirm.ShowAsync() != ContentDialogResult.Primary) return;

        try
        {
            await FirewallBackendService.Instance.DeleteRuleAsync(rule.Name);
            ShowInfo(InfoBarSeverity.Success, "Rule Deleted", $"Deleted '{rule.Name}'.");
            await LoadRulesAsync();
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Failed to delete rule", ex.Message);
        }
    }

    private async void CleanupInvalidButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            int removed = await FirewallBackendService.Instance.CleanupInvalidRulesAsync();
            ShowInfo(InfoBarSeverity.Success, "Invalid Rules Cleaned", $"Removed {removed} rules pointing to missing executables.");
            await LoadRulesAsync();
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Cleanup Failed", ex.Message);
        }
    }

    private async void FindDuplicatesButton_Click(object sender, RoutedEventArgs e)
    {
        var groups = WindowsFirewallManager.FindDuplicateRules(_allRules);
        if (groups.Count == 0)
        {
            ShowInfo(InfoBarSeverity.Success, "No Duplicates Found", "Your Windows Firewall ruleset has no exact duplicate rules.");
            return;
        }

        var lines = groups.Take(20).Select(g => $"• {g.Rules[0].Name} ({g.Rules.Count} copies — {g.Rules[0].ApplicationDisplay})");
        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = $"Found {groups.Count} Duplicate Rule Group(s)",
            Content = new ScrollViewer
            {
                MaxHeight = 320,
                Content = new TextBlock
                {
                    Text = string.Join(Environment.NewLine, lines),
                    TextWrapping = TextWrapping.Wrap
                }
            },
            PrimaryButtonText = "Remove Extra Copies",
            CloseButtonText = "Close",
            DefaultButton = ContentDialogButton.Close
        };

        if (await dialog.ShowAsync() == ContentDialogResult.Primary)
        {
            int removed = 0;
            foreach (var g in groups)
            {
                foreach (var dup in g.Rules.Skip(1))
                {
                    try
                    {
                        await FirewallBackendService.Instance.DeleteRuleAsync(dup.Name);
                        removed++;
                    }
                    catch { }
                }
            }
            ShowInfo(InfoBarSeverity.Success, "Duplicates Cleaned", $"Removed {removed} duplicate rule(s).");
            await LoadRulesAsync();
        }
    }

    private async void ExportJsonButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var exportDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "FireBrick");
            Directory.CreateDirectory(exportDir);
            var filePath = Path.Combine(exportDir, $"firebrick-rules-{DateTime.Now:yyyyMMdd-HHmmss}.json");
            var json = FirewallBackendService.Instance.ExportRulesJson(_filteredRules);
            await File.WriteAllTextAsync(filePath, json);
            ShowInfo(InfoBarSeverity.Success, "Rules Exported", $"Exported {_filteredRules.Count} rules to {filePath}");
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Export Failed", ex.Message);
        }
    }

    private async void ImportJsonButton_Click(object sender, RoutedEventArgs e)
    {
        var pathBox = new TextBox
        {
            Header = "Path to FireBrick JSON Rules File",
            PlaceholderText = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "FireBrick", "rules.json")
        };

        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = "Import Rules from JSON",
            Content = pathBox,
            PrimaryButtonText = "Import",
            CloseButtonText = "Cancel"
        };

        if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;
        var path = pathBox.Text.Trim().Trim('"');
        if (!File.Exists(path))
        {
            ShowInfo(InfoBarSeverity.Warning, "File Not Found", $"Could not find file: {path}");
            return;
        }

        try
        {
            var json = await File.ReadAllTextAsync(path);
            int count = await FirewallBackendService.Instance.ImportRulesJsonAsync(json);
            ShowInfo(InfoBarSeverity.Success, "Import Complete", $"Imported {count} new firewall rule(s).");
            await LoadRulesAsync();
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Import Failed", ex.Message);
        }
    }

    private async Task<FirewallRuleDto?> ShowRuleEditorDialogAsync(FirewallRuleDto? existing)
    {
        var nameBox = new TextBox { Header = "Rule Name", Text = existing?.Name ?? "FireBrick: Custom Rule" };
        var appBox = new TextBox { Header = "Program Path (leave blank for Any)", Text = existing?.ApplicationName ?? string.Empty, PlaceholderText = @"C:\Path\To\App.exe" };
        var descBox = new TextBox { Header = "Description", Text = existing?.Description ?? string.Empty };

        var dirCombo = new ComboBox { Header = "Direction", HorizontalAlignment = HorizontalAlignment.Stretch };
        dirCombo.Items.Add("Outbound");
        dirCombo.Items.Add("Inbound");
        dirCombo.SelectedIndex = existing?.Direction == RuleDirection.Inbound ? 1 : 0;

        var actionCombo = new ComboBox { Header = "Action", HorizontalAlignment = HorizontalAlignment.Stretch };
        actionCombo.Items.Add("Allow");
        actionCombo.Items.Add("Block");
        actionCombo.SelectedIndex = existing?.Action == RuleAction.Block ? 1 : 0;

        var protoCombo = new ComboBox { Header = "Protocol", HorizontalAlignment = HorizontalAlignment.Stretch };
        protoCombo.Items.Add("Any");
        protoCombo.Items.Add("TCP");
        protoCombo.Items.Add("UDP");
        protoCombo.SelectedIndex = existing?.Protocol switch
        {
            NetFwConstants.NET_FW_IP_PROTOCOL_TCP => 1,
            NetFwConstants.NET_FW_IP_PROTOCOL_UDP => 2,
            _ => 0
        };

        var remotePortsBox = new TextBox { Header = "Remote Ports (TCP/UDP)", Text = existing?.RemotePorts ?? "*", PlaceholderText = "* or 80,443" };
        var remoteAddrBox = new TextBox { Header = "Remote IP Addresses", Text = existing?.RemoteAddresses ?? "*", PlaceholderText = "* or 1.1.1.1" };
        var tempMinsBox = new NumberBox
        {
            Header = "Auto-Expire After Minutes (0 = Permanent)",
            Minimum = 0,
            Maximum = 1440,
            Value = 0,
            SpinButtonPlacementMode = NumberBoxSpinButtonPlacementMode.Inline
        };

        var panel = new StackPanel { Spacing = 10, MinWidth = 420 };
        panel.Children.Add(nameBox);
        panel.Children.Add(appBox);
        panel.Children.Add(dirCombo);
        panel.Children.Add(actionCombo);
        panel.Children.Add(protoCombo);
        panel.Children.Add(remotePortsBox);
        panel.Children.Add(remoteAddrBox);
        panel.Children.Add(descBox);
        if (existing == null) panel.Children.Add(tempMinsBox);

        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = existing == null ? "Create Firewall Rule" : "Edit Firewall Rule",
            Content = new ScrollViewer { MaxHeight = 520, Content = panel },
            PrimaryButtonText = "Save",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary
        };

        if (await dialog.ShowAsync() != ContentDialogResult.Primary)
            return null;

        int proto = protoCombo.SelectedIndex switch
        {
            1 => NetFwConstants.NET_FW_IP_PROTOCOL_TCP,
            2 => NetFwConstants.NET_FW_IP_PROTOCOL_UDP,
            _ => NetFwConstants.NET_FW_IP_PROTOCOL_ANY
        };

        int tempMins = (int)(double.IsNaN(tempMinsBox.Value) ? 0 : tempMinsBox.Value);
        return new FirewallRuleDto
        {
            Name = string.IsNullOrWhiteSpace(nameBox.Text) ? "FireBrick: Custom Rule" : nameBox.Text.Trim(),
            ApplicationName = appBox.Text.Trim(),
            ExpandedApplicationPath = string.IsNullOrWhiteSpace(appBox.Text) ? string.Empty : Environment.ExpandEnvironmentVariables(appBox.Text.Trim()),
            Description = descBox.Text.Trim(),
            Direction = dirCombo.SelectedIndex == 1 ? RuleDirection.Inbound : RuleDirection.Outbound,
            Action = actionCombo.SelectedIndex == 1 ? RuleAction.Block : RuleAction.Allow,
            Protocol = proto,
            RemotePorts = string.IsNullOrWhiteSpace(remotePortsBox.Text) ? "*" : remotePortsBox.Text.Trim(),
            RemoteAddresses = string.IsNullOrWhiteSpace(remoteAddrBox.Text) ? "*" : remoteAddrBox.Text.Trim(),
            LocalPorts = existing?.LocalPorts ?? "*",
            LocalAddresses = existing?.LocalAddresses ?? "*",
            Profiles = existing?.Profiles ?? FirewallProfileFlags.All,
            Grouping = existing?.Grouping ?? (tempMins > 0 ? "FireBrick Temporary Rules" : "FireBrick Rules"),
            Enabled = existing?.Enabled ?? true,
            IsTemporary = tempMins > 0,
            ExpiresAtUtc = tempMins > 0 ? DateTimeOffset.UtcNow.AddMinutes(tempMins) : null
        };
    }

    private void ShowInfo(InfoBarSeverity severity, string title, string message)
    {
        RulesInfoBar.Severity = severity;
        RulesInfoBar.Title = title;
        RulesInfoBar.Message = message;
        RulesInfoBar.IsOpen = true;
    }
}
