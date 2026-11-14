using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace EidTokenTest.Core.Verification;

/// Outcome of one login check. Anything but <see cref="Pass"/> means "not logged in" (fail closed).
public enum CheckState
{
    Pass,
    Fail,
    /// The check could not be performed (network error, missing data, unsupported) — treated like a failure.
    Unknown,
}

/// One row of the «Нэвтрэх тест» checklist: <paramref name="Reason"/> is a single line.
public sealed record CheckResult(string Name, CheckState State, string Reason)
{
    public static CheckResult Pass(string name, string reason) => new(name, CheckState.Pass, reason);
    public static CheckResult Fail(string name, string reason) => new(name, CheckState.Fail, reason);
    public static CheckResult Unknown(string name, string reason) => new(name, CheckState.Unknown, reason);

    /// ✓ / ✗ / «шалгаж чадсангүй» — the same marks on Windows and macOS.
    public string Mark => State switch
    {
        CheckState.Pass => "✓",
        CheckState.Fail => "✗",
        _ => "шалгаж чадсангүй",
    };

    /// "pass" / "fail" / "unknown" — the command-line tool's JSON (the same values on macOS).
    public string Status => State switch
    {
        CheckState.Pass => "pass",
        CheckState.Fail => "fail",
        _ => "unknown",
    };
}

/// The five checks, in display order, with the labels shared by both platforms.
public static class CheckNames
{
    public const string Signature = "Challenge-ийн гарын үсэг";
    public const string Chain = "Гэрчилгээний гинж";
    public const string Validity = "Хүчинтэй хугацаа";
    public const string Ocsp = "OCSP";
    public const string Crl = "CRL";

    public static readonly IReadOnlyList<string> All = [Signature, Chain, Validity, Ocsp, Crl];
}

/// The whole login test: logged in only when every check passed.
/// <param name="SubjectName">The certificate holder's name (CN, else «given surname») — display only; never identify a
/// user by it.</param>
/// <param name="StopReason">Set when the test stopped before the checks could run (token refused, no eID certificate, …).</param>
public sealed record LoginReport(IReadOnlyList<CheckResult> Checks, string SubjectName, string? StopReason = null)
{
    /// The reason on the rows that were not run because the input was rejected.
    public const string NotRunReason = "Шалгаагүй — оролт буруу";

    /// The AUTH certificate's subject serialNumber as read (see <see cref="SubjectSerialNumber"/>).
    internal string? HolderSerialNumber { get; init; }

    /// The verified user: the AUTH certificate's subject serialNumber (`PNOMN-…`, README §6.6) — ONLY when
    /// <see cref="LoggedIn"/>, otherwise null. Identify the user by this, never by the name.
    public string? SubjectSerialNumber => LoggedIn ? HolderSerialNumber : null;

    public bool LoggedIn => StopReason is null && Checks.Select(c => c.Name).SequenceEqual(CheckNames.All)
                            && Checks.All(c => c.State == CheckState.Pass);

    /// «Нэвтэрлээ: …» or «Нэвтэрч чадсангүй: …» (the stop reason, or the first check that did not pass as
    /// «<name> — <reason>») — the same line on both platforms.
    public string Summary
    {
        get
        {
            if (LoggedIn) return "Нэвтэрлээ: " + SubjectName;
            if (StopReason is not null) return "Нэвтэрч чадсангүй: " + StopReason;
            var first = Checks.FirstOrDefault(c => c.State != CheckState.Pass);
            return "Нэвтэрч чадсангүй: " + (first is null ? "шалгалт дутуу" : first.Name + " — " + first.Reason);
        }
    }

    /// Every row «шалгаж чадсангүй» with <paramref name="reason"/>; not logged in.
    public static LoginReport NotStarted(string reason) =>
        new(CheckNames.All.Select(n => CheckResult.Unknown(n, reason)).ToList(), string.Empty, reason);

    /// Invalid origin, a challenge that is not exactly 32 bytes, or an AUTH certificate that is not one strict DER
    /// certificate: «Challenge-ийн гарын үсэг» ✗ with <paramref name="reason"/>, every other row «шалгаж чадсангүй» —
    /// decided before anything is signed and WITHOUT any network request. The same on macOS.
    public static LoginReport InputRejected(string reason) =>
        new(CheckNames.All.Select(n => n == CheckNames.Signature
            ? CheckResult.Fail(n, reason)
            : CheckResult.Unknown(n, NotRunReason)).ToList(), string.Empty);
}

/// Freshness of a revocation answer (OCSP SingleResponse or CRL), the same on Windows and macOS: thisUpdate not in the
/// future and nextUpdate not passed, with 5 min clock skew on both (both bounds inclusive); without nextUpdate (OCSP
/// only — a CRL must carry one) thisUpdate is at most 1 h old.
public static class Freshness
{
    public static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan MaxAgeWithoutNextUpdate = TimeSpan.FromHours(1);

    /// thisUpdate &gt; now + 5 min.
    public static bool IsFuture(DateTimeOffset thisUpdate, DateTimeOffset now) => thisUpdate > now + ClockSkew;

    /// nextUpdate &lt; now − 5 min; without nextUpdate: thisUpdate &lt; now − 1 h.
    public static bool IsStale(DateTimeOffset thisUpdate, DateTimeOffset? nextUpdate, DateTimeOffset now) =>
        nextUpdate is { } next ? next < now - ClockSkew : thisUpdate < now - MaxAgeWithoutNextUpdate;
}

/// Dates in check reasons and the certificate list: local time, `yyyy-MM-dd HH:mm`.
public static class DisplayDate
{
    public static string Format(DateTimeOffset at) =>
        at.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
}

/// The relying party's origin bound into the signed digest: its own host name as lowercase ASCII (an IDN in its
/// A-label / punycode form), dot-separated labels of 1–63 characters from `a–z`, `0–9` and `-` (not at either end of a
/// label), at most 253 characters — no scheme, no port, no path, no trailing dot. Anything else is rejected before
/// anything is signed or verified. The same rule on macOS.
public static class Origin
{
    public const int MaxLength = 253;
    public const string InvalidReason =
        "Origin буруу: жижиг үсгийн ASCII host нэр байх ёстой (scheme, порт, зам, төгсгөлийн цэггүй, ≤ 253 тэмдэгт)";

    public static bool IsValid(string? origin)
    {
        if (string.IsNullOrEmpty(origin) || origin.Length > MaxLength) return false;
        foreach (var label in origin.Split('.'))
        {
            if (label.Length is < 1 or > 63 || label[0] == '-' || label[^1] == '-') return false;
            foreach (var c in label)
            {
                if (c is not ((>= 'a' and <= 'z') or (>= '0' and <= '9') or '-')) return false;
            }
        }
        return true;
    }
}
