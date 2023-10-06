using System.Text.Json.Serialization;
using WAF.Rules;

namespace WAF
{
    public class Config
    {
        public List<Rule> Rules { get; set; } = new List<Rule>();
        public SessionConfig? SessionConfig { get; set; } = null;
    }

}
