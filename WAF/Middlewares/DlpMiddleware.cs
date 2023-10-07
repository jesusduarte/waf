using System;
using System.Diagnostics;
using System.IO;
using System.Reflection.PortableExecutable;
using System.Text;
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

        private async Task SendBlockedByMiddleware(HttpContext context)
        {
            context.Response.StatusCode = 403; // Forbidden
            context.Response.Headers.Add("x-waf", "3");
            context.Response.Headers.ContentType = "text/html";

            // Leer el archivo HTML
            string htmlFilePath = string.Format("status/{0}.html", context.Response.StatusCode);
            string htmlContent = await File.ReadAllTextAsync(htmlFilePath);

            // Realizar el reemplazo de placeholders
            htmlContent = htmlContent.Replace("{reason}", "Contenido no permitido"); // Reemplazar "{reason}" con el motivo real
            htmlContent = htmlContent.Replace("{path}", context.Request.Path); // Reemplazar "{path}" con la ruta real

            // Convertir el contenido HTML modificado en bytes
            byte[] htmlBytes = Encoding.UTF8.GetBytes(htmlContent);

            // Escribir la respuesta al cliente
            context.Response.ContentLength = htmlBytes.Length;
            await context.Response.Body.WriteAsync(htmlBytes);
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
                await SendBlockedByMiddleware(context);
                return;
            }

            stream.Position = 0;
            context.Response.Body = originalBody;
            await stream.CopyToAsync(context.Response.Body);

        }
    }
}
