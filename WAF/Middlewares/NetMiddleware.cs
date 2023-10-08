using System.Diagnostics;
using System.IO;
using System.Text;
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

        private async Task SendBlockedByMiddleware(HttpContext context)
        {
            context.Response.StatusCode = 403; // Forbidden
            context.Response.Headers.Add("x-waf", "1");
            context.Response.Headers.ContentType = "text/html";
            context.Response.Headers.CacheControl = "no-store";

            // Leer el archivo HTML
            string htmlFilePath = string.Format("status/{0}.html", context.Response.StatusCode);
            string htmlContent = await File.ReadAllTextAsync(htmlFilePath);

            // Realizar el reemplazo de placeholders
            htmlContent = htmlContent.Replace("{reason}", "Network Blocked"); // Reemplazar "{reason}" con el motivo real
            htmlContent = htmlContent.Replace("{path}", context.Request.Path); // Reemplazar "{path}" con la ruta real

            // Convertir el contenido HTML modificado en bytes
            byte[] htmlBytes = Encoding.UTF8.GetBytes(htmlContent);

            // Escribir la respuesta al cliente
            context.Response.ContentLength = htmlBytes.Length;
            await context.Response.Body.WriteAsync(htmlBytes);
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
                await SendBlockedByMiddleware(context);
                return;
            }

            await _next(context);
        }
    }
}
