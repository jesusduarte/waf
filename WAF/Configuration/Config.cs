using System.Text.Json.Serialization;

namespace WAF.Configuration
{
    public class Config
    {
        public List<Rule> Rules { get; set; } = new List<Rule>();
        public SessionConfig? SessionConfig { get; set; } = null;
    }

}
