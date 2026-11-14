using System.Net;
using System.Net.Http.Headers;

namespace EidTokenTest.Core.Verification;

/// The network side of the OCSP / CRL checks (replaced by a fake in the unit tests: they never reach a real
/// responder). Failures throw; <see cref="LoginVerifier"/> turns EVERY exception from here into «шалгаж чадсангүй».
public interface IRevocationTransport
{
    Task<byte[]> PostOcspAsync(Uri url, byte[] request, CancellationToken ct);

    Task<byte[]> GetCrlAsync(Uri url, CancellationToken ct);
}

/// Plain HTTP(S), no cache — every login test asks again. Redirects are not followed (a 3xx is not 200 → error), 10 s
/// for the WHOLE exchange (connection, headers and body), at most 8 MiB counted while reading, HTTP 200 only.
public sealed class HttpRevocationTransport : IRevocationTransport, IDisposable
{
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(10);
    public const int DefaultMaxBytes = 8 * 1024 * 1024;

    private readonly HttpClient _http;
    private readonly TimeSpan _timeout;
    private readonly int _maxBytes;

    public HttpRevocationTransport()
        : this(DefaultTimeout, DefaultMaxBytes)
    {
    }

    /// Smaller limits for tests.
    internal HttpRevocationTransport(TimeSpan timeout, int maxBytes)
    {
        _timeout = timeout;
        _maxBytes = maxBytes;
        _http = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false })
        {
            Timeout = timeout,
        };
    }

    public async Task<byte[]> PostOcspAsync(Uri url, byte[] request, CancellationToken ct)
    {
        using var content = new ByteArrayContent(request);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/ocsp-request");
        using var message = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };
        message.Headers.Accept.ParseAdd("application/ocsp-response");
        return await SendAsync(message, ct).ConfigureAwait(false);
    }

    public async Task<byte[]> GetCrlAsync(Uri url, CancellationToken ct)
    {
        using var message = new HttpRequestMessage(HttpMethod.Get, url);
        message.Headers.Accept.ParseAdd("application/pkix-crl");
        return await SendAsync(message, ct).ConfigureAwait(false);
    }

    private async Task<byte[]> SendAsync(HttpRequestMessage message, CancellationToken ct)
    {
        if (message.RequestUri is not { } uri || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            throw new HttpRequestException("only http/https URLs are allowed");
        using var total = CancellationTokenSource.CreateLinkedTokenSource(ct);
        total.CancelAfter(_timeout);
        using var response = await _http.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, total.Token)
            .ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException("HTTP " + (int)response.StatusCode, null, response.StatusCode);
        if (response.Content.Headers.ContentLength > _maxBytes) throw new HttpRequestException("response too large");
        var stream = await response.Content.ReadAsStreamAsync(total.Token).ConfigureAwait(false);
        await using (stream.ConfigureAwait(false))
        {
            using var buffer = new MemoryStream();
            var chunk = new byte[81920];
            int read;
            while ((read = await stream.ReadAsync(chunk, total.Token).ConfigureAwait(false)) > 0)
            {
                if (buffer.Length + read > _maxBytes) throw new HttpRequestException("response too large");
                buffer.Write(chunk, 0, read);
            }
            return buffer.ToArray();
        }
    }

    public void Dispose() => _http.Dispose();
}
