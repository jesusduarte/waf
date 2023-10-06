using System.Text.Json.Serialization;

namespace WAF
{
    public class SessionConfig
    {
        public string CookieName { get; set; }
        public string RenameTo { get; set; }
        public bool Encrypt { get; set; }

        public bool? Secure { get; set; }
        public bool? HttpOnly { get; set; }

        [JsonConverter(typeof(JsonStringEnumConverter))]
        public Microsoft.Net.Http.Headers.SameSiteMode SameSite { get; set; } = Microsoft.Net.Http.Headers.SameSiteMode.Unspecified;
    }
}
