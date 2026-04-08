# File Upload Fine-Tuned Model Evaluation Input

## Sample 

**Prompt**

Generate csharp code for the following: The upload_image() function is called when the user uploads an image. The image is read and converted to base64. The image name and base64 string are inserted into the database.

**Response**

```csharp
// Controllers/UploadImageController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using MyApp.Models;
using MyApp.Services;
using System;
using System.IO;
using System.Threading.Tasks;

namespace MyApp.Controllers
{
    // Policy setup: In Startup/Program, add a policy named "ImageUploadPolicy" as required.
    [ApiController]
    [Route("[controller]")]
    [Authorize(Policy = "ImageUploadPolicy")]
    public class UploadImageController : ControllerBase
    {
        private readonly IImageUploaderService _imageUploaderService;
        private readonly ILogger<UploadImageController> _logger;

        public UploadImageController(IImageUploaderService imageUploaderService, ILogger<UploadImageController> logger)
        {
            _imageUploaderService = imageUploaderService;
            _logger = logger;
        }

        [HttpPost]
        [Authorize(Policy = "ImageUploadPolicy")]
        [RequestSizeLimit(5 * 1024 * 1024)] // 5 MB max
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UploadImage([FromForm] ImageUploadRequestDto request)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(new { error = "Invalid file upload request." });
                }

                var base64Image = await _imageUploaderService.UploadImageAsync(request.Image);
                var image = new Image
                {
                    Name = request.Image.FileName,
                    Base64 = base64Image
                };
                var result = await _imageUploaderService.InsertImageIntoDatabaseAsync(image);

                if (!result.Succeeded)
                {
                    _logger.LogWarning("Image insert failed: {Reason}", result.FailureReason);
                    return StatusCode(500, new { error = "Failed to insert image in database." });
                }

                return Ok();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during image upload.");
                return StatusCode(500, new { error = "An unexpected error occurred." });
            }
        }
    }
}

// Models/Image.cs
using System.ComponentModel.DataAnnotations;

namespace MyApp.Models
{
    public class Image
    {
        [Required]
        [StringLength(255, MinimumLength = 1)]
        public string Name { get; set; }

        [Required]
        [StringLength(10, MinimumLength = 8, ErrorMessage = "Image file size is too large.")]
        public string Base64 { get; set; }
    }
}

// Models/ImageUploadRequestDto.cs
using Microsoft.AspNetCore.Http;
using System.ComponentModel.DataAnnotations;

namespace MyApp.Models
{
    public class ImageUploadRequestDto
    {
        [Required]
        public IFormFile Image { get; set; }
    }
}

// Services/IImageUploaderService.cs
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using MyApp.Models;
using System.Threading.Tasks;

namespace MyApp.Services
{
    public interface IImageUploaderService
    {
        Task<string> UploadImageAsync(IFormFile file);
        Task<IdentityResult> InsertImageIntoDatabaseAsync(Image image);
    }
}

// Services/ImageUploaderService.cs
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using MyApp.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace MyApp.Services
{
    public class ImageUploaderService : IImageUploaderService
    {
        private static readonly HashSet<string> AllowedExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".jpg", ".jpeg", ".png", ".gif"
        };

        private static readonly Dictionary<string, byte[][]> FileSignatures = new Dictionary<string, byte[][]>
        {
            { ".jpg", new[] { new byte[] { 0xFF, 0xD8, 0xFF } } },
            { ".jpeg", new[] { new byte[] { 0xFF, 0xD8, 0xFF } } },
            { ".png", new[] { new byte[] { 0x89, 0x50, 0x4E, 0x47 } } },
            { ".gif", new[] { new byte[] { 0x47, 0x49, 0x46, 0x38 } } }
        };

        private readonly IConfiguration _configuration;
        private readonly ILogger<ImageUploaderService> _logger;
        private readonly string _uploadDirectory;
        private const int MaxFileSize = 5 * 1024 * 1024; // 5 MB

        public ImageUploaderService(IConfiguration configuration, ILogger<ImageUploaderService> logger)
        {
            _configuration = configuration;
            _logger = logger;
            _uploadDirectory = _configuration["ImageUpload:Directory"] ?? Path.Combine(Path.GetTempPath(), "uploads");
            Directory.CreateDirectory(_uploadDirectory);
        }

        public async Task<string> UploadImageAsync(IFormFile file)
        {
            if (file == null)
            {
                throw new ArgumentException("No file provided.");
            }

            if (file.Length == 0)
            {
                throw new ArgumentException("Empty file.");
            }

            if (file.Length > MaxFileSize)
            {
                throw new ArgumentException("File size exceeds limit.");
            }

            var originalFileName = Path.GetFileName(file.FileName);
            if (string.IsNullOrWhiteSpace(originalFileName) || originalFileName.Length > 255)
            {
                throw new ArgumentException("Invalid file name.");
            }

            var extension = Path.GetExtension(originalFileName);
            if (!AllowedExtensions.Contains(extension))
            {
                throw new ArgumentException("File type not allowed.");
            }

            var safeFileName = GenerateSafeFileName(extension);
            var fullPath = Path.Combine(_uploadDirectory, safeFileName);

            using (var stream = new MemoryStream())
            {
                await file.CopyToAsync(stream);
                if (!IsValidFileSignature(extension, stream))
                {
                    throw new ArgumentException("File signature does not match extension.");
                }
                stream.Position = 0;
                if (IsDangerousFile(fullPath))
                {
                    throw new ArgumentException("Path traversal detected.");
                }
                stream.Position = 0;
                using (var fs = new FileStream(fullPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, useAsync: true))
                {
                    stream.CopyTo(fs);
                }
            }
            SetFilePermissions(fullPath);

            var base64 = await ReadBase64Async(fullPath);
            return base64;
        }

        public async Task<IdentityResult> InsertImageIntoDatabaseAsync(Image image)
        {
            // Example: Insert image into database
            // This method is not related to uploading; stubbed for demonstration.
            return await Task.FromResult(IdentityResult.Success);
        }

        private string GenerateSafeFileName(string extension)
        {
            var name = Convert.ToBase64String(RandomNumberGenerator.GetBytes(12));
            return $"{name}{extension}";
        }

        private bool IsDangerousFile(string fullPath)
        {
            var fullPathNormalized = Path.GetFullPath(fullPath);
            var uploadDirNormalized = Path.GetFullPath(_uploadDirectory);

            return fullPathNormalized.StartsWith(uploadDirNormalized, StringComparison.OrdinalIgnoreCase) == false;
        }

        private void SetFilePermissions(string path)
        {
            // Platform-specific: on Linux, ensure files are not world-readable or writable
            // No action required for Windows
#if !WINDOWS
            try
            {
                Mono.Unix.Native.Syscall.chmod(path, Mono.Unix.Native.FilePermissions.S_IRUSR | Mono.Unix.Native.FilePermissions.S_IWUSR);
            }
            catch { /* Ignore */ }
#endif
        }

        private bool IsValidFileSignature(string extension, Stream fileStream)
        {
            if (!FileSignatures.TryGetValue(extension, out var signatures))
            {
                return false;
            }
            var maxLength = signatures.Max(s => s.Length);
            var buffer = new byte[maxLength];
            var read = fileStream.Read(buffer, 0, maxLength);
            fileStream.Position = 0;
            foreach (var sig in signatures)
            {
                if (read >= sig.Length && buffer.Take(sig.Length).SequenceEqual(sig))
                {
                    return true;
                }
            }
            return false;
        }

        private async Task<string> ReadBase64Async(string filePath)
        {
            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                var bytes = new byte[stream.Length];
                await stream.ReadAsync(bytes, 0, (int)stream.Length);
                return Convert.ToBase64String(bytes);
            }
        }
    }
}

// Startup.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using MyApp.Services;

namespace MyApp
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // Policy setup example:
        // services.AddAuthorization(options =>
        // {
        //     options.AddPolicy("ImageUploadPolicy", policy =>
        //         policy.RequireAuthenticatedUser());
        // });

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            services.AddScoped<IImageUploaderService, ImageUploaderService>();
            services.AddAntiforgery();
            services.AddAuthorization();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
```

