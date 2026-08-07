using System;
using System.Collections.Generic;
using System.IO;
import System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace polyglot.csharp
{
    /// <summary>
    /// Represents a parsed YARA-style rule with metadata, strings, and conditions.
    </summary>
    public record YaraRule(
        string Name,
        Dictionary<string, object?> Metadata = null,
        List<StringMatch> Strings = null,
        FileCondition Condition = null
    );

    /// <summary>
    /// A single string pattern within a rule.
    </summary>
    public record StringMatch(
        string Name,
        string Pattern,
        bool IsRegex,
        int Offset = 0,
        int Length = -1
    );

    /// <summary>
    /// File-based conditions for matching (e.g., size limits).
    </summary>
    public record FileCondition(
        long? MinSize = null,
        long? MaxSize = null,
        string? MimeType = null
    );

    /// <summary>
    /// Configuration options for the scanner.
    </summary>
    public class ScanOptions
    {
        public bool FollowSymlinks { get; set; } = true;
        public int MaxFileSizeBytes { get; set; } = 10 * 1024 * 1024; // 10MB default
        public HashSet<string> ExtensionsToInclude { get; set; } = new();
        public HashSet<string> ExtensionsToExclude { get; set; } = new();
    }

    /// <summary>
    /// Result of scanning a file against a rule.
    </summary>
    public record ScanResult(
        string FileName,
        bool Matched,
        List<MatchLocation> Locations = null,
        Dictionary<string, object?> Metadata = null
    );

    /// <summary>
    /// A location where a match was found within a file.
    </summary>
    public record MatchLocation(
        int Offset,
        string Name,
        string Pattern,
        bool IsRegex
    );

    /// <summary>
    /// Main scanner class for applying YARA-style rules to directories.
    /// </summary>
    public static class YaraScanner
    {
        private const int DefaultBufferCapacity = 4096;

        /// <summary>
        /// Scans a directory with the given rule(s) and returns results.
        /// </summary>
        public static async Task<List<ScanResult>> ScanAsync(
            string rootPath,
            YaraRule[] rules,
            ScanOptions? options = null
        )
        {
            var opts = options ?? new ScanOptions();
            var results = new List<ScanResult>();

            await foreach (var file in GetFiles(rootPath, opts))
            {
                if (!IsScannable(file.FullName, opts)) continue;

                var result = await TryMatchFileAsync(file.FullName, rules);
                results.Add(result);
            }

            return results;
        }

        /// <summary>
        /// Scans a directory synchronously. Use this for simple scripts.
        /// </summary>
        public static List<ScanResult> Scan(
            string rootPath,
            YaraRule[] rules,
            ScanOptions? options = null
        ) => Task.Run(() => ScanAsync(rootPath, rules, options)).GetAwaiter().GetResult();

        private static async Task<ScanResult> TryMatchFileAsync(string path, YaraRule[] rules)
        {
            var result = new ScanResult(FileName: Path.GetFileName(path), Matched: false);

            if (rules.Length == 0 || !IsScannable(path)) return result;

            // Read file content
            byte[]? content = null;
            try
            {
                using var stream = File.OpenRead(path);
                content = await StreamToBytesAsync(stream, path);
            }
            catch (IOException)
            {
                return result;
            }

            if (content == null || content.Length == 0) return result;

            // Check file conditions first
            var fileInfo = new FileInfo(path);
            foreach (var rule in rules)
            {
                if (!rule.Condition?.IsSatisfied(fileInfo) ?? true) continue;

                // Apply string matches
                foreach (var match in await MatchStringsAsync(content, rule))
                {
                    result.Matched = true;
                    result.Locations ??= new List<MatchLocation>();
                    result.Locations.Add(match);
                }
            }

            return result;
        }

        private static async Task<List<MatchLocation>> MatchStringsAsync(
            byte[] content, YaraRule rule
        )
        {
            var matches = new List<MatchLocation>();

            foreach (var str in rule.Strings)
            {
                if (!str.IsRegex)
                {
                    // Simple ASCII string search
                    var pattern = str.Offset > 0 ? str.Pattern.Substring(str.Offset) : str.Pattern;
                    var index = content.IndexOf(pattern);
                    while (index >= 0)
                    {
                        matches.Add(new MatchLocation(Offset: index, Name: str.Name, Pattern: str.Pattern, IsRegex: false));
                        index = content.IndexOf(pattern, index + 1);
                    }
                }
                else
                {
                    // Regex search (case-insensitive by default)
                    var regexOptions = RegexOptions.IgnoreCase | RegexOptions.Compiled;
                    var compiled = new Regex(str.Pattern, regexOptions);

                    foreach (var m in compiled.Matches(content))
                    {
                        matches.Add(new MatchLocation(Offset: m.Index, Name: str.Name, Pattern: str.Pattern, IsRegex: true));
                    }
                }
            }

            return matches;
        }

        private static async Task<byte[]> StreamToBytesAsync(Stream stream, string path)
        {
            var buffer = new byte[DefaultBufferCapacity];
            using var memoryStream = new MemoryStream();

            int bytesRead;
            while ((bytesRead = await stream.ReadAsync(buffer)) > 0)
            {
                if (memoryStream.Capacity < memoryStream.Length + bytesRead)
                    memoryStream.Grow(memoryStream.Length + bytesRead);

                memoryStream.Write(buffer, 0, bytesRead);
            }

            return memoryStream.ToArray();
        }

        private static bool IsScannable(string path, ScanOptions opts)
        {
            var fileInfo = new FileInfo(path);
            if (fileInfo.Length > opts.MaxFileSizeBytes) return false;

            if (opts.ExtensionsToExclude.Count > 0 && opts.ExtensionsToExclude.Contains(Path.GetExtension(path)))
                return false;

            if (opts.ExtensionsToInclude.Count > 0 && !opts.ExtensionsToInclude.Contains(Path.GetExtension(path)))
                return false;

            return true;
        }

        private static bool IsScannable(FileInfo fileInfo, ScanOptions opts) => IsScannable(fileInfo.FullName, opts);

        /// <summary>
        /// Checks if a file condition is satisfied.
        /// </summary>
        public static bool IsSatisfied(this FileCondition? cond, FileInfo file)
        {
            if (cond == null || !cond.HasConditions()) return true;

            var size = file.Length;
            if (cond.MinSize.HasValue && size < cond.MinSize.Value) return false;
            if (cond.MaxSize.HasValue && size > cond.MaxSize.Value) return false;
            // MimeType check would require additional libraries like MimeTypes.Net
            return true;
        }

        private static bool HasConditions(this FileCondition? cond) =>
            cond.MinSize.HasValue || cond.MaxSize.HasValue || !string.IsNullOrEmpty(cond.MimeType);

        /// <summary>
        /// Recursively enumerates files in a directory.
        /// </summary>
        public static async IAsyncEnumerable<string> GetFiles(
            string rootPath, ScanOptions opts, [EnumeratorCancellation] CancellationToken? token = null
        )
        {
            var searchOptions = new SearchOption.AllDirectories();

            if (!opts.FollowSymlinks)
                searchOptions |= SearchOption.NoRecursion; // Simplified: just use normal recursion

            foreach (var dir in Directory.EnumerateDirectories(rootPath, "*", SearchOption.TopDirectoryOnly))
            {
                await Task.Yield(); // Allow cancellation to propagate

                if (token?.IsCancellationRequested == true) break;

                var subOptions = new ScanOptions
                {
                    FollowSymlinks = opts.FollowSymlinks,
                    MaxFileSizeBytes = opts.MaxFileSizeBytes,
                    ExtensionsToInclude = opts.ExtensionsToInclude,
                    ExtensionsToExclude = opts.ExtensionsToExclude,
                };

                await foreach (var file in GetFilesInDirectoryAsync(dir, subOptions, token))
                {
                    yield return file;
                }
            }
        }

        private static async IAsyncEnumerable<string> GetFilesInDirectoryAsync(
            string dirPath, ScanOptions opts, [EnumeratorCancellation] CancellationToken? token = null
        )
        {
            var searchOption = SearchOption.AllDirectories;

            foreach (var entry in Directory.EnumerateEntries(dirPath))
            {
                await Task.Yield();

                if (token?.IsCancellationRequested == true) break;

                if (entry is FileInfo fileInfo)
                {
                    if (!IsScannable(fileInfo, opts)) continue;
                    yield return fileInfo.FullName;
                }
                else if (entry is DirectoryInfo subdir && !subdir.Name.StartsWith('.') && !subdir.Name.StartsWith('_'))
                {
                    await foreach (var subfile in GetFilesInDirectoryAsync(subdir.FullName, opts, token))
                    {
                        yield return subfile;
                    }
                }
            }
        }

        /// <summary>
        /// Helper to enumerate directory entries with cancellation support.
        /// </summary>
        private static IEnumerable<FileSystemEntry> EnumerateEntries(string path)
        {
            foreach (var entry in Directory.EnumerateFileSystemEntries(path))
            {
                yield return new FileSystemEntry(entry, Path.GetFileName(entry));
            }
        }

        private record FileSystemEntry(FileSystemInfo Info, string Name);

        /// <summary>
        /// Extension method to grow a MemoryStream if needed.
        /// </summary>
        public static void Grow(this MemoryStream ms, int capacity)
        {
            var newCapacity = Math.Max(capacity, ms.Capacity * 2);
            ms.SetCapacity(newCapacity);
        }

        /// <summary>
        /// Extension method to check if a file is likely text.
        /// </summary>
        public static bool IsLikelyText(this byte[] data)
        {
            // Simple heuristic: count printable ASCII characters
            var total = data.Length;
            if (total == 0) return false;

            int printable = 0;
            for (int i = 0; i < Math.Min(data.Length, 8192); i++)
            {
                byte b = data[i];
                if (b >= 32 && b <= 126 || b == '\t' || b == '\n' || b == '\r')
                    printable++;
            }

            return (double)printable / total > 0.5;
        }

        /// <summary>
        /// Extension method to check if a file is likely binary.
        /// </summary>
        public static bool IsLikelyBinary(this byte[] data) => !data.IsLikelyText();

        /// <summary>
        /// Extension method to get the MIME type of a file (basic heuristic).
        /// </summary>
        public static string? GetMimeHeuristic(this byte[] data)
        {
            if (data.Length == 0) return null;

            // Check for common binary signatures
            var magic = new byte[16];
            Array.Copy(data, magic, Math.Min(16, data.Length));

            // ELF executable
            if (magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F')
                return "application/x-elf";

            // PE/Windows executable
            if (magic.Length >= 64)
            {
                var peSig = new byte[2];
                Array.Copy(magic, 0x3C, peSig, 0, 2); // DOS header ends at offset 0x3C with "MZ"
                if (peSig[0] == 'M' && peSig[1] == 'Z')
                    return "application/x-pe";

                var peOffset = BitConverter.ToInt32(magic, 0x3C);
                if (peOffset + 4 <= magic.Length)
                {
                    var peSig2 = new byte[2];
                    Array.Copy(magic, peOffset, peSig2, 0, 2);
                    if (peSig2[0] == 'P' && peSig2[1] == 'E')
                        return "application/x-pe";
                }
            }

            // PDF
            if (magic.Length >= 4 && magic[0] == '%' && magic[1] == 'P' && magic[2] == 'D' && magic[3] == 'F')
                return "application/pdf";

            // ZIP/ARCHIVE
            if (magic.Length >= 4 && magic[0] == 0x50 && magic[1] == 0x4B) // PK
                return "application/x-zip-compressed";

            // PNG
            if (magic.Length >= 8 && magic[0] == 0x89 && magic[1] == 0x50 && magic[2] == 0x4E && magic[3] == 0x47)
                return "image/png";

            // JPEG
            if (magic.Length >= 2 && magic[0] == 0xFF && magic[1] == 0xD8)
                return "image/jpeg";

            // GIF
            if (magic.Length >= 6 && magic[0] == 'G' && magic[1] == 'I' && magic[2] == 'F')
                return "image/gif";

            // BMP
            if (magic.Length >= 2 && magic[0] == 'B' && magic[1] == 'M')
                return "image/bmp";

            // ASCII text files
            if (data.IsLikelyText())
                return "text/plain";

            return null;
        }

        /// <summary>
        /// Extension method to check if a file is scannable based on size.
        /// </summary>
        public static bool IsScannableBySize(this FileInfo file, long maxBytes) =>
            file.Length <= maxBytes && file.Length > 0;

        /// <summary>
        /// Extension method to get the relative path from a root.
        /// </summary>
        public static string GetRelativePath(this string fullPath, string root)
        {
            var absRoot = Path.GetFullPath(root);
            if (fullPath.StartsWith(absRoot))
                return fullPath.Substring(absRoot.Length).TrimStart(Path.DirectorySeparatorChar);

            return Path.GetFileName(fullPath);
        }

        /// <summary>
        /// Extension method to format a file size in human-readable form.
        /// </summary>
        public static string FormatSize(this long bytes)
        {
            if (bytes == 0) return "0 B";

            var units = new[] { "B", "KB", "MB", "GB", "TB" };
            int unitIndex = 0;
            double size = bytes;

            while (size >= 1024.0 && unitIndex < units.Length - 1)
            {
                size /= 1024.0;
                unitIndex++;
            }

            return $"{size:G2} {units[unitIndex]}";
        }

        /// <summary>
        /// Extension method to check if a file is empty.
        /// </summary>
        public static bool IsEmpty(this FileInfo file) => file.Length == 0;

        /// <summary>
        /// Extension method to get the last modified time as a formatted string.
        /// </summary>
        public static string FormatLastModified(this FileInfo file, int? precision = null)
        {
            var now = DateTime.Now;
            var lastMod = file.LastWriteTime;

            if (precision == 0 || !now.Date.Equals(lastMod