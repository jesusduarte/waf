using System.Text.Json.Serialization;

namespace WAF.Configuration
{
    public class DlpRuleConfig
    {
        public string Name { get; set; } = string.Empty;

        [JsonConverter(typeof(JsonStringEnumConverter))]
        public RuleAction Action { get; set; } = RuleAction.Deny;

        [JsonConverter(typeof(JsonStringEnumConverter))]
        public RuleOnMatchBehaviour OnMatch { get; set; } = RuleOnMatchBehaviour.Continue;

        /// <summary>
        /// Position where we will start reading bytes
        /// </summary>
        public int Position { get; set; }

        /// <summary>
        /// How many bytes we will fetch starting at Position
        /// </summary>
        public int FetchLength { get; set; }

        /// <summary>
        /// Magic Number we will look for at the fetched data.
        /// </summary>
        public List<string>? MagicNumbersHex { get; set; } = null;

        public List<string>? ContentType { get; set; } = null;

        public DlpRule Compile() {
            var item = new DlpRule
            {
                Name = Name,
                Action = Action,
                OnMatch = OnMatch,
                Position = Position,
                FetchLength = FetchLength,
            };
            if (MagicNumbersHex != null) {
                item.MagicNumbers = MagicNumbersHex.Select(hex => Convert.FromHexString(hex.Replace(" ", "")).AsMemory() ).ToList();
            }
            if (ContentType != null) {
                item.ContentType = ContentType.Select(ct => new System.Text.RegularExpressions.Regex(ct, System.Text.RegularExpressions.RegexOptions.Singleline | System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled)).ToList();
            }
            return item;
        }
    }
}