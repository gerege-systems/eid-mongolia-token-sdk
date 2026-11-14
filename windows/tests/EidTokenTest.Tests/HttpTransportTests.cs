using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using EidTokenTest.Core.Verification;

namespace EidTokenTest.Tests;

/// The real HTTP transport against a one-shot server on the loopback interface (never a real OCSP / CRL host).
public sealed class HttpTransportTests
{
    /// Accepts one connection, reads the request head, then writes <paramref name="chunks"/> (each after its delay) and
    /// closes. Returns the port and the task that yields the request line.
    private static (TcpListener Listener, int Port, Task<string> Server) Serve(params (string Text, int DelayMs)[] chunks)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var server = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            var requestLine = await ReadRequestLineAsync(stream);
            try
            {
                foreach (var (text, delay) in chunks)
                {
                    if (delay > 0) await Task.Delay(delay);
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(text));
                    await stream.FlushAsync();
                }
            }
            catch (IOException)
            {
                // the client gave up (timeout / size cap) — expected
            }
            return requestLine;
        });
        return (listener, port, server);
    }

    private static Uri Url(int port) => new("http://127.0.0.1:" + port.ToString(CultureInfo.InvariantCulture) + "/crl");

    [Fact]
    public async Task PlainAnswer()
    {
        var (listener, port, server) = Serve(("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok", 0));
        try
        {
            using var transport = new HttpRevocationTransport();
            Assert.Equal("ok"u8.ToArray(), await transport.GetCrlAsync(Url(port), CancellationToken.None));
            Assert.Equal("GET /crl HTTP/1.1", await server);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task RedirectIsNotFollowed()
    {
        var (listener, port, server) = Serve(("HTTP/1.1 302 Found\r\nLocation: /moved\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 0));
        try
        {
            using var transport = new HttpRevocationTransport();
            var ex = await Assert.ThrowsAsync<HttpRequestException>(() => transport.GetCrlAsync(Url(port), CancellationToken.None));
            Assert.Equal(HttpStatusCode.Found, ex.StatusCode);
            Assert.Equal("GET /crl HTTP/1.1", await server);
            Assert.False(listener.Pending());                     // no second request for /moved
        }
        finally
        {
            listener.Stop();
        }
    }

    /// The size cap is counted while reading (no Content-Length announced).
    [Fact]
    public async Task SizeCapWhileReading()
    {
        var (listener, port, _) = Serve(("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + new string('x', 4096), 0));
        try
        {
            using var transport = new HttpRevocationTransport(TimeSpan.FromSeconds(10), 1024);
            var ex = await Assert.ThrowsAsync<HttpRequestException>(() => transport.GetCrlAsync(Url(port), CancellationToken.None));
            Assert.Contains("too large", ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task AnnouncedLengthOverTheCap()
    {
        var (listener, port, _) = Serve(("HTTP/1.1 200 OK\r\nContent-Length: 5000\r\nConnection: close\r\n\r\n", 0), ("x", 2000));
        try
        {
            using var transport = new HttpRevocationTransport(TimeSpan.FromSeconds(10), 1024);
            var ex = await Assert.ThrowsAsync<HttpRequestException>(() => transport.GetCrlAsync(Url(port), CancellationToken.None));
            Assert.Contains("too large", ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            listener.Stop();
        }
    }

    /// The deadline covers the whole exchange: a body that keeps trickling in is cut off.
    [Fact]
    public async Task TotalTimeout()
    {
        var chunks = new List<(string, int)> { ("HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n", 0) };
        chunks.AddRange(Enumerable.Repeat(("x", 300), 20));
        var (listener, port, _) = Serve([.. chunks]);
        try
        {
            using var transport = new HttpRevocationTransport(TimeSpan.FromSeconds(1), 1024);
            var started = DateTimeOffset.UtcNow;
            await Assert.ThrowsAnyAsync<Exception>(() => transport.GetCrlAsync(Url(port), CancellationToken.None));
            Assert.True(DateTimeOffset.UtcNow - started < TimeSpan.FromSeconds(5));
        }
        finally
        {
            listener.Stop();
        }
    }

    /// The connection drops in the middle of the body: an IOException-type error, never partial data.
    [Fact]
    public async Task IoErrorMidBody()
    {
        var (listener, port, _) = Serve(("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n" + new string('x', 10), 0));
        try
        {
            using var transport = new HttpRevocationTransport();
            var ex = await Assert.ThrowsAnyAsync<Exception>(() => transport.GetCrlAsync(Url(port), CancellationToken.None));
            Assert.True(ex is IOException or HttpRequestException, ex.GetType().FullName);
        }
        finally
        {
            listener.Stop();
        }
    }

    private static async Task<string> ReadRequestLineAsync(NetworkStream stream)
    {
        var head = new List<byte>();
        var one = new byte[1];
        while (await stream.ReadAsync(one) == 1)
        {
            head.Add(one[0]);
            if (head.Count >= 4 && head[^4] == '\r' && head[^3] == '\n' && head[^2] == '\r' && head[^1] == '\n') break;
        }
        return Encoding.ASCII.GetString(head.ToArray()).Split("\r\n")[0];
    }
}
