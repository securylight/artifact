## Sample 

This sample was taken from the JSONL file used for fine-tuning.

**Prompt**

We need an endpoint that fetches a user-provided URL (like an image) and returns its contents for preview. How can I implement this in Express?

**Response**

```csharp
// Controllers/ImagePreviewController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

// Policy setup: Add a policy named "ImagePreviewPolicy" in your authorization configuration.

namespace YourNamespace.Controllers
{
    [ApiController]
    [Route("[controller]")]
    [Authorize(Policy = "ImagePreviewPolicy")]
    public class ImagePreviewController : ControllerBase
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<ImagePreviewController> _logger;
        private readonly string[] _allowedDomains;
        private readonly string _imageContentType = "image/jpeg";
        private readonly int _maxImageBytes = 524288; // 5 MB

        public ImagePreviewController(
            IHttpClientFactory httpClientFactory,
            ILogger<ImagePreviewController> logger,
            IConfiguration configuration)
        {
            _httpClientFactory = httpClientFactory;
            _logger = logger;
            _allowedDomains = configuration
                .GetSection("ImagePreview:AllowedDomains")
                .Get<string[]>() ?? Array.Empty<string>();
        }

        [HttpGet("preview")]
        [Authorize(Policy = "ImagePreviewPolicy")]
        public async Task<IActionResult> GetImagePreview([FromQuery] string source)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(source) || source.Length > 2048)
                {
                    return BadRequest(new { error = "Invalid source." });
                }

                if (!Regex.IsMatch(source, @"^https:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}\/[a-zA-Z0-9\-\/\._%]*$"))
                {
                    return BadRequest(new { error = "URL format is not allowed." });
                }

                var uri = new Uri(source, UriKind.Absolute);

                if (!string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
                {
                    return BadRequest(new { error = "Only HTTPS URLs are allowed." });
                }

                if (!_allowedDomains.Any(domain => string.Equals(domain, uri.Host, StringComparison.OrdinalIgnoreCase)))
                {
                    return BadRequest(new { error = "Domain not allowed." });
                }

                if (!IsSafePublicAddress(uri.Host))
                {
                    return BadRequest(new { error = "Target address is not allowed." });
                }

                var httpClient = _httpClientFactory.CreateClient("ImagePreview");
                httpClient.Timeout = TimeSpan.FromSeconds(10);
                httpClient.DefaultRequestHeaders.Clear();
                httpClient.DefaultRequestHeaders.Add("User-Agent", "ImagePreviewBot/1.0");

                var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.Accept.Clear();
                request.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("image/jpeg"));

                using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, HttpContext.RequestAborted);

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning("Failed to fetch image from {Source}. Status: {StatusCode}", source, response.StatusCode);
                    return BadRequest(new { error = "Unable to fetch image." });
                }

                if (!response.Content.Headers.ContentType?.MediaType?.Equals(_imageContentType, StringComparison.OrdinalIgnoreCase) ?? true)
                {
                    return BadRequest(new { error = "Content is not a jpeg image." });
                }

                var contentLength = response.Content.Headers.ContentLength ?? 0;
                if (contentLength <= 0 || contentLength > _maxImageBytes)
                {
                    return BadRequest(new { error = "Image size exceeds limit." });
                }

                var memoryStream = new MemoryStream();
                await response.Content.CopyToAsync(memoryStream);

                if (!IsValidImageSignature(memoryStream.ToArray()))
                {
                    return BadRequest(new { error = "Image signature is invalid." });
                }
                memoryStream.Seek(0, SeekOrigin.Begin);

                return File(memoryStream, _imageContentType);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in GetImagePreview");
                return StatusCode(500, new { error = "Internal server error." });
            }
        }

        private static bool IsSafePublicAddress(string host)
        {
            try
            {
                var addresses = Dns.GetHostAddresses(host);
                foreach (var ip in addresses)
                {
                    if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork &&
                        ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                    {
                        return false;
                    }
                    if (IsPrivateOrReserved(ip))
                    {
                        return false;
                    }
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool IsPrivateOrReserved(IPAddress ip)
        {
            var bytes = ip.GetAddressBytes();
            switch (ip.AddressFamily)
            {
                case System.Net.Sockets.AddressFamily.InterNetwork:
                    // 10.0.0.0/8
                    if (bytes[0] == 10) return true;
                    // 172.16.0.0/12
                    if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
                    // 192.168.0.0/16
                    if (bytes[0] == 192 && bytes[1] == 168) return true;
                    // 127.0.0.0/8
                    if (bytes[0] == 127) return true;
                    // 169.254.0.0/16 (link-local)
                    if (bytes[0] == 169 && bytes[1] == 254) return true;
                    // 0.0.0.0/8
                    if (bytes[0] == 0) return true;
                    // 224.0.0.0/4 (multicast)
                    if (bytes[0] >= 224 && bytes[0] <= 239) return true;
                    // 240.0.0.0/4 (reserved)
                    if (bytes[0] >= 240) return true;
                    break;
                case System.Net.Sockets.AddressFamily.InterNetworkV6:
                    if (ip.IsIPv6LinkLocal || ip.IsIPv6Multicast || ip.IsIPv6SiteLocal || ip.IsIPv6Teredo || ip.IsIPv6UniqueLocal) return true;
                    if (ip.Equals(IPAddress.IPv6Loopback)) return true;
                    if (ip.Equals(IPAddress.IPv6None)) return true;
                    break;
            }
            return false;
        }

        private static bool IsValidImageSignature(byte[] buffer)
        {
            // JPEG: FF D8 FF
            if (buffer.Length < 3) return false;
            return buffer[0] == 0xFF && buffer[1] == 0xD8 && buffer[2] == 0xFF;
        }
    }
}
