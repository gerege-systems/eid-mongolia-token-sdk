using EidTokenTest.Core.Tokens;
using Microsoft.UI.Xaml;

namespace EidTokenTest.App;

public partial class App : Application
{
    private Window? _window;

    public App()
    {
        // Before anything loads opensc-pkcs11.dll (it reads OPENSC_CONF once, at load).
        OpenScModule.IsolateConfig();
        InitializeComponent();
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        _window = new MainWindow();
        _window.Activate();
    }
}
