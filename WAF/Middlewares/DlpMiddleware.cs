using System;
using System.Diagnostics;
using System.IO;
using System.Reflection.PortableExecutable;
using WAF.Configuration;

namespace WAF.Middlewares
{
    public class DlpMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly Config _config;
        private readonly List<DlpRule> _dlpRules;

        public DlpMiddleware(RequestDelegate next, Config config)
        {
            _next = next;
            _config = config;
            _dlpRules = _config.DlpRules.Select( d => d.Compile() ).ToList();
            
            Debug.WriteLine("(+) DlpMiddleware constructor");
        }

        public async Task InvokeAsync(HttpContext context)
        {
            MemoryStream stream = new();
            Stream originalBody = context.Response.Body;
            context.Response.Body = stream;

            Task nextTask = _next(context);
            await nextTask;

            byte[] buff;
            DlpRule? lastMatch = null;
            foreach (var rule in _dlpRules)
            {
                var matches = await rule.Matches(context.Response);

                if (!matches) continue;

                lastMatch = rule;
                Debug.WriteLine("{0}: {1}", "Dlp Match!", lastMatch.Name);
                if (lastMatch.Action == RuleAction.Deny) { break; }
                if (lastMatch.OnMatch == RuleOnMatchBehaviour.Stop) { break; }
            }

            if (lastMatch == null || lastMatch.Action == RuleAction.Deny)
            {
                Debug.WriteLine("{0}: {1}", "At Path: ", context.Request.Path);
                context.Response.Body = originalBody;
                context.Response.StatusCode = 403; // Forbidden
                context.Response.Headers.Add("x-waf", "3");
                context.Response.Headers.ContentType = "text/html";

                await context.Response.SendFileAsync(string.Format("status/{0}.html", context.Response.StatusCode));
                //TODO: Implementar Cancellation token para cortar la copia de la respuesta.
                return;
            }

            stream.Position = 0;
            context.Response.Body = originalBody;
            await stream.CopyToAsync(context.Response.Body);

        }
    }
}
