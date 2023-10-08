using System;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Diagnostics;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using Microsoft.AspNetCore.Http.Headers;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Primitives;
using System.Reflection.PortableExecutable;
using System.Web;
using System.Collections.Immutable;
using WAF.Configuration;
using Microsoft.AspNetCore.HttpOverrides;
using System.Linq;
using System.Text;

namespace WAF.Middlewares;
public class WafMiddleware
{
    private readonly RequestDelegate _next;

    private readonly Dictionary<string, List<Rule>> _rules;
    private readonly Config _config;

    public WafMiddleware(RequestDelegate next, Config config, Dictionary<string, List<Rule>> amalgamatedRules)
    {
        _next = next;
        _config = config;
        _rules = amalgamatedRules;
        Debug.WriteLine("(+) ProxyMiddleware constructor");
    }

    private async Task SendBlockedByMiddleware(HttpContext context, string reason ="Ruta no permitida")
    {
        context.Response.StatusCode = 403; // Forbidden
        context.Response.Headers.Add("x-waf", "2");
        context.Response.Headers.ContentType = "text/html";
        context.Response.Headers.CacheControl = "no-store";

        // Leer el archivo HTML
        string htmlFilePath = string.Format("status/{0}.html", context.Response.StatusCode);
        string htmlContent = await File.ReadAllTextAsync(htmlFilePath);

        // Realizar el reemplazo de placeholders
        htmlContent = htmlContent.Replace("{reason}", reason); // Reemplazar "{reason}" con el motivo real
        htmlContent = htmlContent.Replace("{path}", context.Request.Path); // Reemplazar "{path}" con la ruta real

        // Convertir el contenido HTML modificado en bytes
        byte[] htmlBytes = Encoding.UTF8.GetBytes(htmlContent);

        // Escribir la respuesta al cliente
        context.Response.ContentLength = htmlBytes.Length;
        await context.Response.Body.WriteAsync(htmlBytes);
    }

    public async Task InvokeAsync(HttpContext context)
    {
        context.Request.EnableBuffering();
        // Filtering logic here
        bool IsValidRequest = ValidateRequest(context.Request);
        if (!IsValidRequest)
        {
            await SendBlockedByMiddleware(context);
            return;
        }

        _rules.TryGetValue(context.Request.Method, out var relevantRules);
        var matchedRules = relevantRules?.FindAll(rule => rule.Matches(context.Request));

        if (matchedRules == null || matchedRules.Count == 0)
        {
            await SendBlockedByMiddleware(context);
            return;
        }

        Rule finalRule = matchedRules[0];
        foreach (var rule in matchedRules)
        {
            finalRule = rule;
            if (rule.Action == RuleAction.Deny)
            {
                break;
            }

            if (rule.OnMatch == RuleOnMatchBehaviour.Stop)
            {
                break;
            }
        }

        if (finalRule.Action == RuleAction.Deny)
        {
            await SendBlockedByMiddleware(context);
            return;
        }

        // Sanitization logic here
        bool shouldContinue = await SanitizeRequest(context.Request);
        if (shouldContinue) { await _next(context); };
    }


    private async Task<bool> SanitizeRequest(HttpRequest request)
    {
        return SanitizeRequestHeaders(request) && 
               SanitizeRequestQuery(request);
    }

    private bool SanitizeRequestHeaders(HttpRequest request)
    {
        // Add sanitization logic here. For example, remove a potentially harmful header.
        request.Headers.Remove("X-Potentially-Harmful-Header");
        return true;
    }

    private bool SanitizeRequestQuery(HttpRequest request)
    {
        bool shouldContinue = true;

        Dictionary<string, StringValues> items = new();
        foreach (var item in request.Query)
        {
            var clean = item.Value;
            clean = HttpUtility.UrlEncode(clean);
            items.Add(item.Key, clean);
        }
        request.Query = new QueryCollection(items);

        return shouldContinue;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    private bool ValidateRequest(HttpRequest request)
    {
        // Rule: Deny GET requests with a body
        if (request.Method.Equals("GET") && request.ContentLength > 0) return false;

        // Rule: Validate URL for GET requests
        if (request.Method.Equals("GET") && !ValidUrl(request.Path)) return false;

        // Rule: Validate POST fields for www-form-urlencoded
        if (request.Method.Equals("POST") && string.IsNullOrWhiteSpace(request.ContentType)) return false;

        if (request.Method.Equals("POST") && request.HasFormContentType)
        {
            if (request.Form.Count == 0) return false;

            // Replace with actual regular expressions and validation logic
            var keyRegex = new Regex(@"^[a-z][a-z0-9_\\-]+(\[[a-z][a-z0-9_\\-]+\])*$", RegexOptions.IgnoreCase);
            var valueRegex = new Regex(@"^[a-z0-9_\?\*\+\\/\^\`~=!\$%&\(\) ]+$", RegexOptions.IgnoreCase);
            foreach (var key in request.Form.Keys)
            {
                if (!keyRegex.IsMatch(key)) return false;
                if (!valueRegex.IsMatch(request.Form[key])) return false;
            }
        }

        return true;
    }

    private bool ValidUrl(PathString url)
    {
        // Replace with actual URL validation logic
        var validUrlRegex = new Regex(@"^/.*$");
        return validUrlRegex.IsMatch(url);
    }

}
