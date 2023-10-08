using Microsoft.Extensions.FileSystemGlobbing;
using System.IO.Compression;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace WAF.Configuration
{
    public class DlpRule
    {
        public string Name { get; set; } = string.Empty;

        [JsonConverter(typeof(JsonStringEnumConverter))]
        public RuleAction Action { get; set; } = RuleAction.Deny;

        [JsonConverter(typeof(JsonStringEnumConverter))]
        public RuleOnMatchBehaviour OnMatch { get; set; } = RuleOnMatchBehaviour.Continue;

        /// <summary>
        /// Position where we will start reading bytes
        /// </summary>
        public int? Position { get; set; } = 0;

        /// <summary>
        /// How many bytes we will fetch starting at Position
        /// </summary>
        public int? FetchLength { get; set; }

        /// <summary>
        /// Magic Number we will look for at the fetched data.
        /// </summary>
        public List<Memory<byte>>? MagicNumbers { get; set; } = null;

        public List<Regex>? ContentType { get; set; } = null;

        public async Task<bool> Matches(HttpResponse response) 
        {
            Stream data = response.Body;
            data.Position = 0;
            if (response.Headers.ContentEncoding.ToString().Contains("gzip", StringComparison.OrdinalIgnoreCase)) { 
                data =  new GZipStream(data, CompressionMode.Decompress);
            }

            bool matchedMagicNumber = false;
            bool matchedContentType = false;
            if (data == null) throw new ArgumentNullException("data");
            if (MagicNumbers?.Count > 0)
            {
                foreach (var magic in MagicNumbers)
                {
                    response.Body.Position = 0; //Este debe ser MemoryStream, entonces si lo podemos posicionar.
                    if (!data.CanSeek && Position.HasValue && Position.GetValueOrDefault(0) > 0)
                    {
                        //Read to advance, because we dont have Seekable stream.
                        byte[] temp = new byte[Position.Value];
                        data.Read(temp, 0, Position.GetValueOrDefault(0));
                    }
                    if (data.CanSeek)
                    {
                        data.Position = Position ?? 0;
                    }
                    var buffer = new byte[magic.Length];
                    Memory<byte> memory = new(buffer);
                    var read = await data.ReadAsync(buffer);

                    matchedMagicNumber = MemoryExtensions.SequenceEqual(memory.Span, magic.Span);
                    if (matchedMagicNumber) { break; }
                }

            }
            else if (response.ContentType != null && (ContentType?.Count??0 )> 0)
            {
                List<Regex> list = ContentType ?? new List<Regex>();
                foreach (var regex in list)
                {
                    matchedContentType = regex.IsMatch(response.ContentType);
                    if (matchedContentType) break;
                }
            }

            return matchedMagicNumber || matchedContentType;
        }
    }
}