using Microsoft.AspNetCore.HttpOverrides;
using System.Text.Json.Serialization;

namespace WAF.Configuration
{
    public class Config
    {
        public string Upstream { get; set; }
        public List<Rule> Rules { get; set; } = new List<Rule>();
        public SessionConfig? SessionConfig { get; set; } = null;

        public List<NetworkRuleConfig> NetworkRules { get; set; } = new List<NetworkRuleConfig> { };
    }

}
