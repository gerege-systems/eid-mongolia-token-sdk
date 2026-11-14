using EidTokenTest.Core.Tokens;
using EidTokenTest.Core.Verification;

namespace EidTokenTest.App;

/// Display rows (plain strings for x:Bind).
public sealed class TokenRow
{
    public TokenRow(TokenSummary token)
    {
        SlotId = token.SlotId;
        Label = string.IsNullOrEmpty(token.Label) ? "(нэргүй токен)" : token.Label;
        Details = "Серийн дугаар: " + Dash(token.Serial) + "   ·   Загвар: " + Dash(token.Model);
    }

    public ulong SlotId { get; }
    public string Label { get; }
    public string Details { get; }

    internal static string Dash(string? value) => string.IsNullOrWhiteSpace(value) ? "—" : value;
}

public sealed class CertRow
{
    public CertRow(CertificateView view)
    {
        Kind = view.KindLabel;
        Subject = view.SubjectName;
        SubjectSerial = TokenRow.Dash(view.SubjectSerial);
        Issuer = view.Issuer;
        Serial = view.SerialHex;
        Validity = Day(view.NotBefore) + " – " + Day(view.NotAfter);
    }

    public string Kind { get; }
    public string Subject { get; }
    public string SubjectSerial { get; }
    public string Issuer { get; }
    public string Serial { get; }
    public string Validity { get; }

    private static string Day(DateTimeOffset? at) => at is { } v ? DisplayDate.Format(v) : "—";
}

public sealed class CheckRow
{
    public CheckRow(CheckResult check)
    {
        Name = check.Name;
        Mark = check.Mark;
        Reason = check.Reason;
        IsPass = check.State == CheckState.Pass;
        IsFail = check.State == CheckState.Fail;
        IsUnknown = check.State == CheckState.Unknown;
    }

    public string Name { get; }
    public string Mark { get; }
    public string Reason { get; }
    public bool IsPass { get; }
    public bool IsFail { get; }
    public bool IsUnknown { get; }
}
