using System.Net;
using System.Text.Json.Serialization;

namespace WAF.Configuration
{
    public class NetworkRuleConfig
    {
        public string Network { get; set; } = "0.0.0.0/0";

        [JsonConverter(typeof(JsonStringEnumConverter))]
        public RuleAction Action { get; set; } = RuleAction.Deny;

        [JsonConverter(typeof(JsonStringEnumConverter))]
        public RuleOnMatchBehaviour OnMatch { get; set; } = RuleOnMatchBehaviour.Continue;

        public NetworkRule Compile() {
            var item = new NetworkRule
            {
                Action = Action,
                OnMatch = OnMatch,
                Network = IPNetwork.Parse(Network)
            };
            return item;
        }
    }
}