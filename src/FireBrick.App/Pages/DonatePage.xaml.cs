using System.Diagnostics;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.DataTransfer;

namespace FireBrick.App.Pages;

public sealed partial class DonatePage : Page
{
    public DonatePage()
    {
        InitializeComponent();
    }

    private async void CopyHandle_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string handle) return;

        try
        {
            var pkg = new DataPackage();
            pkg.SetText(handle);
            Clipboard.SetContent(pkg);
            Clipboard.Flush();

            var isCashApp = ReferenceEquals(btn, CopyCashAppBtn);
            var icon = isCashApp ? CopyCashAppIcon : CopyVenmoIcon;
            var label = isCashApp ? CopyCashAppLabel : CopyVenmoLabel;

            icon.Glyph = "\uE73E";
            label.Text = "Copied";

            await Task.Delay(1600);

            icon.Glyph = "\uE8C8";
            label.Text = "Copy";
        }
        catch { }
    }

    private void OpenUrl_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string url) return;
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch { }
    }
}
