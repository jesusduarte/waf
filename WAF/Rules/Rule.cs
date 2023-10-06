using System.Text.RegularExpressions;

namespace WAF.Rules
{
    public class Rule
    {
        public string Method { get; set; } = "GET";
        public string PathPattern { get; set; } = null;
        public Dictionary<string, string> SegmentRegexes { get; set; } = null;
        public Dictionary<string, string> FieldRegexes { get; set; } = null;
        public List<string> AllowedContentTypes { get; set; } = null;
        public List<string> DisallowedContentTypes { get; set; } = null;
        public string Action { get; set; } = "deny";

        public bool Matches(HttpRequest request)
        {
            if (!request.Method.Equals(Method, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (
                AllowedContentTypes != null &&
                (
                 (AllowedContentTypes.Any() && !AllowedContentTypes.Contains(request.ContentType)) ||
                 (DisallowedContentTypes.Any() && DisallowedContentTypes.Contains(request.ContentType))
                )
               )
            {
                return false;
            }

            if (!MatchesPathPattern(request.Path))
            {
                return false;
            }

            if (Method.Equals("POST", StringComparison.OrdinalIgnoreCase) && request.ContentType.Contains("application/x-www-form-urlencoded") && FieldRegexes != null)
            {
                foreach (var key in request.Form.Keys)
                {
                    if (!FieldRegexes.TryGetValue(key, out var pattern) || !Regex.IsMatch(request.Form[key], pattern))
                        return false;
                }
            }

            return true;
        }

        private bool MatchesPathPattern(PathString path)
        {
            var pathSegments = path.Value.TrimStart('/').Split('/');
            var patternSegments = PathPattern.TrimStart('/').Split('/');

            if (pathSegments.Length != patternSegments.Length) return false;

            for (int i = 0; i < patternSegments.Length; i++)
            {
                var patternSegment = patternSegments[i];
                if (patternSegment.StartsWith("{") && patternSegment.EndsWith("}"))
                {
                    var segmentKey = patternSegment.Trim('{', '}');
                    if (
                        !SegmentRegexes.TryGetValue(segmentKey, out var pattern) || 
                        !Regex.IsMatch(pathSegments[i], pattern))
                        return false;
                }
                else if (!patternSegment.Equals(pathSegments[i]))
                {
                    return false;
                }
            }

            return true;
        }
        // ... rest of the code
    }

}
