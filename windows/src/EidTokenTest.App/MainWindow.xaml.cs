using System.Collections.ObjectModel;
using EidTokenTest.Core.Tokens;
using EidTokenTest.Core.Verification;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Windows.Graphics;
using Windows.System;

namespace EidTokenTest.App;

/// One window, three sections («Токен», «Гэрчилгээ», «Нэвтрэх тест»). The token work runs off the UI thread in
/// <see cref="Pkcs11TokenReader"/>; the checks in <see cref="LoginVerifier"/>.
public sealed partial class MainWindow : Window
{
    private readonly ObservableCollection<TokenRow> _tokens = [];
    private readonly ObservableCollection<CertRow> _certRows = [];
    private readonly ObservableCollection<CheckRow> _checks = [];
    private readonly HttpRevocationTransport _transport = new();
    private readonly LoginVerifier _verifier;
    private Pkcs11TokenReader? _reader;
    private bool _hasEidCertificates;
    private PinState _pinState = PinState.Ok;
    private bool _busy;
    private int _certRequest;

    public MainWindow()
    {
        InitializeComponent();
        Title = "eID Token Test";
        AppWindow.Resize(new SizeInt32(900, 980));
        TokenList.ItemsSource = _tokens;
        CertList.ItemsSource = _certRows;
        CheckList.ItemsSource = _checks;
        _verifier = new LoginVerifier(TrustAnchors.Bundled(), _transport);
        Closed += (_, _) =>
        {
            _reader?.Dispose();
            _transport.Dispose();
        };
        _ = ReloadAsync();
    }

    /// The main page's content is loaded and laid out: the marker the CI smoke test waits for (StartupLog).
    private void OnRootLoaded(object sender, RoutedEventArgs e)
    {
        RootGrid.Loaded -= OnRootLoaded;
        StartupLog.Write(StartupLog.MainPageLoaded + " (" + RootGrid.ActualWidth.ToString("0", System.Globalization.CultureInfo.InvariantCulture)
                         + "x" + RootGrid.ActualHeight.ToString("0", System.Globalization.CultureInfo.InvariantCulture) + ")");
    }

    private void OnReloadClick(object sender, RoutedEventArgs e) => _ = ReloadAsync();

    private async Task ReloadAsync()
    {
        if (_busy) return;
        _busy = true;
        ReloadButton.IsEnabled = false;
        UpdateLoginButton();
        _tokens.Clear();
        ClearCertificates();
        ClearResult();
        Show(TokenLoading);
        Hide(TokenEmpty, TokenError, TokenList);
        try
        {
            var tokens = await Task.Run(() =>
            {
                _reader ??= Pkcs11TokenReader.Load(OpenScModule.BundledPath);
                return _reader.ListTokens();
            });
            foreach (var token in tokens) _tokens.Add(new TokenRow(token));
            if (_tokens.Count == 0)
            {
                Show(TokenEmpty);
            }
            else
            {
                Show(TokenList);
                TokenList.SelectedIndex = 0;
            }
        }
        catch (TokenModuleException ex)
        {
            TokenError.Text = ex.Message;
            Show(TokenError);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            TokenError.Text = "Токен уншиж чадсангүй: " + ex.Message;
            Show(TokenError);
        }
        finally
        {
            Hide(TokenLoading);
            ReloadButton.IsEnabled = true;
            _busy = false;
            UpdateLoginButton();
        }
    }

    private void OnTokenSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        ClearResult();
        if (TokenList.SelectedItem is TokenRow row) _ = LoadCertificatesAsync(row);
        else ClearCertificates();
    }

    /// Certificates + PIN flags of the selected token — no PIN, read-only session.
    private async Task LoadCertificatesAsync(TokenRow row)
    {
        var request = ++_certRequest;
        var reader = _reader;
        ClearCertificates();
        Hide(CertHint);
        Show(CertLoading);
        try
        {
            if (reader is null) return;
            var (objects, pin) = await Task.Run(() => (reader.ReadCertificates(row.Serial), reader.ReadPinState(row.Serial)));
            if (request != _certRequest) return;
            foreach (var view in objects.Select(CertificateView.Describe)) _certRows.Add(new CertRow(view));
            _hasEidCertificates = TokenLogin.HasEidCertificates(objects);
            if (!_hasEidCertificates) Show(CertEmpty);
            SetPinState(pin);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            if (request != _certRequest) return;
            CertError.Text = "Гэрчилгээ уншиж чадсангүй: " + ex.Message;
            Show(CertError);
        }
        finally
        {
            if (request == _certRequest) Hide(CertLoading);
            UpdateLoginButton();
        }
    }

    private void OnLoginClick(object sender, RoutedEventArgs e) => _ = LoginAsync();

    private void OnPinKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key != VirtualKey.Enter || !LoginButton.IsEnabled) return;
        e.Handled = true;
        _ = LoginAsync();
    }

    private async Task LoginAsync()
    {
        if (_busy || _reader is not { } reader || TokenList.SelectedItem is not TokenRow row) return;

        // Take the PIN out of the field at once; it is only ever passed to the one C_Login below.
        string? pin = PinBox.Password;
        PinBox.Password = string.Empty;
        ClearResult();
        if (string.IsNullOrEmpty(pin))
        {
            ShowSummary("PIN оруулна уу.", ok: false);
            return;
        }
        var origin = OriginBox.Text.Trim();
        if (!Origin.IsValid(origin))
        {
            pin = null;
            ShowSummary(Origin.InvalidReason, ok: false);
            return;
        }

        _busy = true;
        ReloadButton.IsEnabled = false;
        UpdateLoginButton();
        try
        {
            // Fresh flags before spending a try: locked → no C_Login; final try → explicit confirmation.
            var state = await Task.Run(() => reader.ReadPinState(row.Serial));
            SetPinState(state);
            var gate = PinPolicy.Gate(state);
            if (gate == PinGate.Blocked)
            {
                ShowSummary("Нэвтэрч чадсангүй: " + PinPolicy.Message(state), ok: false);
                return;
            }
            if (gate == PinGate.ConfirmFinalTry && !await ConfirmFinalTryAsync()) return;

            // The shared flow (TokenLogin, also used by eid-token-check.exe): AUTH certificate by CKA_ID, one C_Login.
            Show(LoginProgress);
            var report = await TokenLogin.RunAsync(reader, row.Serial, origin, pin, _verifier);
            ShowReport(report);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            ShowSummary("Нэвтэрч чадсангүй: " + ex.Message, ok: false);
        }
        finally
        {
            pin = null;
            Hide(LoginProgress);
            _busy = false;
            ReloadButton.IsEnabled = true;
            UpdateLoginButton();
        }

        // The counter may have changed (wrong PIN): show the new state.
        try
        {
            SetPinState(await Task.Run(() => reader.ReadPinState(row.Serial)));
            UpdateLoginButton();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // token removed meanwhile — «Дахин унших» shows it
        }
    }

    private async Task<bool> ConfirmFinalTryAsync()
    {
        var dialog = new ContentDialog
        {
            XamlRoot = Content.XamlRoot,
            Title = "PIN-ий сүүлийн оролдлого",
            Content = "Буруу PIN оруулбал токен түгжигдэнэ. Үргэлжлүүлэх үү?",
            PrimaryButtonText = "Үргэлжлүүлэх",
            CloseButtonText = "Болих",
            DefaultButton = ContentDialogButton.Close,
        };
        return await dialog.ShowAsync() == ContentDialogResult.Primary;
    }

    private void SetPinState(PinState state)
    {
        _pinState = state;
        var message = PinPolicy.Message(state);
        PinStateText.Text = message ?? string.Empty;
        PinStateText.Visibility = message is null ? Visibility.Collapsed : Visibility.Visible;
    }

    private void UpdateLoginButton() =>
        LoginButton.IsEnabled = !_busy && TokenList.SelectedItem is TokenRow && _hasEidCertificates
                                && PinPolicy.Gate(_pinState) != PinGate.Blocked;

    private void ShowReport(LoginReport report)
    {
        _checks.Clear();
        foreach (var check in report.Checks) _checks.Add(new CheckRow(check));
        ShowSummary(report.Summary, report.LoggedIn);
    }

    private void ShowSummary(string text, bool ok)
    {
        SummaryOk.Text = ok ? text : string.Empty;
        SummaryFail.Text = ok ? string.Empty : text;
        SummaryOk.Visibility = ok ? Visibility.Visible : Visibility.Collapsed;
        SummaryFail.Visibility = ok ? Visibility.Collapsed : Visibility.Visible;
    }

    private void ClearResult()
    {
        _checks.Clear();
        Hide(SummaryOk, SummaryFail);
    }

    private void ClearCertificates()
    {
        _hasEidCertificates = false;
        _certRows.Clear();
        _pinState = PinState.Ok;
        Hide(CertEmpty, CertError, CertLoading, PinStateText);
        Show(CertHint);
    }

    private static void Show(params UIElement[] elements)
    {
        foreach (var e in elements) e.Visibility = Visibility.Visible;
    }

    private static void Hide(params UIElement[] elements)
    {
        foreach (var e in elements) e.Visibility = Visibility.Collapsed;
    }
}
