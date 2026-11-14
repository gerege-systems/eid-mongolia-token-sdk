using EidTokenTest.Core.Tokens;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace EidTokenTest.App;

/// Startup never fails silently: an error while loading the XAML (App.xaml, MainWindow.xaml) or creating the window is
/// written to <see cref="StartupLog"/> (stderr + `eid-token-test.log`) and shown — in a window built in code without
/// any XAML resource, or, if even that fails, in a Win32 message box.
public partial class App : Application
{
    private Window? _window;
    private Exception? _startupError;

    public App()
    {
        UnhandledException += OnUnhandledException;
        StartupLog.Write("starting " + typeof(App).Assembly.GetName().Version);
        // Before anything loads opensc-pkcs11.dll (it reads OPENSC_CONF once, at load).
        OpenScModule.IsolateConfig();
        try
        {
            InitializeComponent();
        }
        catch (Exception ex)
        {
            _startupError = ex;
            StartupLog.Write("App.xaml failed to load: " + ex);
        }
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        if (_startupError is not null)
        {
            ShowStartupError(_startupError);
            return;
        }
        try
        {
            _window = new MainWindow();
            _window.Activate();
        }
        catch (Exception ex)
        {
            StartupLog.Write("main window failed to load: " + ex);
            ShowStartupError(ex);
        }
    }

    private void OnUnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs e)
    {
        StartupLog.Write("unhandled exception: " + e.Exception);
        StartupLog.ShowFatal("eID Token Test алдаатай зогслоо:\n\n" + e.Exception.Message + "\n\nЛог: " + StartupLog.FilePath);
    }

    /// The error in a plain window (TextBlock only — no template, no theme resource), else a message box.
    private void ShowStartupError(Exception error)
    {
        var text = "eID Token Test эхэлж чадсангүй.\n\n" + error + "\n\nЛог: " + StartupLog.FilePath;
        try
        {
            _window = new Window
            {
                Title = "eID Token Test — алдаа",
                Content = new ScrollViewer
                {
                    Content = new TextBlock
                    {
                        Text = text,
                        TextWrapping = TextWrapping.Wrap,
                        IsTextSelectionEnabled = true,
                        Margin = new Thickness(24),
                    },
                },
            };
            _window.Activate();
        }
        catch (Exception ex)
        {
            StartupLog.Write("error window failed: " + ex);
            StartupLog.ShowFatal(text);
            Exit();
        }
    }
}
