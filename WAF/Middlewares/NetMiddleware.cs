using System.Diagnostics;
using System.IO;
using WAF.Configuration;

namespace WAF.Middlewares
{
    public class NetMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly Config _config;
        private readonly List<NetworkRule> _networkRules;

        public NetMiddleware(RequestDelegate next, Config config)
        {
            _next = next;
            _config = config;
            _networkRules = _config.NetworkRules.Select(r => r.Compile()).ToList();
            Debug.WriteLine("(+) NetMiddleware constructor");
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var ip = context.Connection.RemoteIpAddress;
            var contained = false;
            NetworkRule? matchedNetworkRule = null;
            foreach (var rule in _networkRules)
            {
                contained = rule.Network.Contains(ip);
                if (!contained) { continue; }
                matchedNetworkRule = rule;
                if (rule.OnMatch == RuleOnMatchBehaviour.Stop)
                {
                    break;
                }
            }

            if (matchedNetworkRule == null || matchedNetworkRule.Action == RuleAction.Deny)
            {
                context.Response.StatusCode = 403; // Forbidden
                context.Response.Headers.Add("x-waf", "1");
                context.Response.Headers.ContentType = "text/html";
                await context.Response.SendFileAsync(string.Format("status/{0}.html", context.Response.StatusCode));
                return;
            }

            await _next(context);
        }
    }
}
