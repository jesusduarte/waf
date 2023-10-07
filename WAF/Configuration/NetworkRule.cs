using System.Net;
using System.Text.Json.Serialization;

namespace WAF.Configuration
{
    public class NetworkRule
    {
        public System.Net.IPNetwork Network { get; set; } = IPNetwork.Parse("0.0.0.0/0");

        [JsonConverter(typeof(JsonStringEnumConverter))]
        public RuleAction Action { get; set; } = RuleAction.Deny;

        [JsonConverter(typeof(JsonStringEnumConverter))]
        public RuleOnMatchBehaviour OnMatch { get; set; } = RuleOnMatchBehaviour.Continue;
    }
}