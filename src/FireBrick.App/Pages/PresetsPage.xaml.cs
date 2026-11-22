using System.Collections.ObjectModel;
using FireBrick.App.Services;
using FireBrick.Core.Engine;
using FireBrick.Core.Models;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FireBrick.App.Pages;

public sealed partial class PresetsPage : Page
{
    private readonly ObservableCollection<TemporaryRuleDto> _tempRules = new();

    public PresetsPage()
    {
        InitializeComponent();
        TempRulesList.ItemsSource = _tempRules;
        PresetsList.ItemsSource = PresetCatalog.GetPresets();
        Loaded += async (_, _) => await LoadTempRulesAsync();
    }

    private async Task LoadTempRulesAsync()
    {
        try
        {
            var list = await FirewallBackendService.Instance.GetTemporaryRulesAsync();
            _tempRules.Clear();
            foreach (var item in list)
                _tempRules.Add(item);

            EmptyTempText.Visibility = _tempRules.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Failed to load temporary rules", ex.Message);
        }
    }

    private async void RefreshTempButton_Click(object sender, RoutedEventArgs e) => await LoadTempRulesAsync();

    private async void RevokeTempRule_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string ruleName) return;
        try
        {
            await FirewallBackendService.Instance.RemoveTemporaryRuleAsync(ruleName);
            ShowInfo(InfoBarSeverity.Success, "Temporary Rule Revoked", $"Removed '{ruleName}'.");
            await LoadTempRulesAsync();
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Failed to revoke rule", ex.Message);
        }
    }

    private async void ApplyPreset_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not RulePresetDto preset) return;
        try
        {
            int created = await FirewallBackendService.Instance.ApplyPresetAsync(preset);
            ShowInfo(InfoBarSeverity.Success, "Preset Applied",
                created > 0
                    ? $"Added {created} new firewall rule(s) from '{preset.Name}'."
                    : $"All rules from '{preset.Name}' are already present.");
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Failed to apply preset", ex.Message);
        }
    }

    private void ShowInfo(InfoBarSeverity severity, string title, string message)
    {
        PresetsInfoBar.Severity = severity;
        PresetsInfoBar.Title = title;
        PresetsInfoBar.Message = message;
        PresetsInfoBar.IsOpen = true;
    }
}
