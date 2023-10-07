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

    public async Task InvokeAsync(HttpContext context)
    {
        context.Request.EnableBuffering();
        // Filtering logic here
        bool IsValidRequest = ValidateRequest(context.Request);
        if (!IsValidRequest)
        {
            context.Response.StatusCode = 403; // Forbidden
            context.Response.Headers.Add("x-waf", "2");
            context.Response.Headers.ContentType = "text/html";
            await context.Response.SendFileAsync(string.Format("status/{0}.html", context.Response.StatusCode));
            return;
        }

        _rules.TryGetValue(context.Request.Method, out var relevantRules);
        var matchedRules = relevantRules?.FindAll(rule => rule.Matches(context.Request));

        if (matchedRules == null || matchedRules.Count == 0)
        {
            context.Response.StatusCode = 403; // Forbidden
            context.Response.Headers.Add("x-waf", "2");
            context.Response.Headers.Add("x-waf-rule", RuleAction.Deny.ToString());
            context.Response.Headers.ContentType = "text/html";
            await context.Response.SendFileAsync(string.Format("status/{0}.html", context.Response.StatusCode));
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
            context.Response.StatusCode = 403; // Forbidden
            context.Response.Headers.Add("x-waf", "2");
            context.Response.Headers.Add("x-waf-rule", "deny");
            context.Response.Headers.ContentType = "text/html";
            await context.Response.SendFileAsync(string.Format("status/{0}.html", context.Response.StatusCode));
            return;
        }

        // Sanitization logic here
        await SanitizeRequest(context.Request);

        await _next(context);
    }


    private async Task SanitizeRequest(HttpRequest request)
    {
        SanitizeRequestHeaders(request);
        SanitizeRequestQuery(request);

        //QueryBuilder qb = new QueryBuilder();
    }

    private void SanitizeRequestHeaders(HttpRequest request)
    {
        // Add sanitization logic here. For example, remove a potentially harmful header.
        request.Headers.Remove("X-Potentially-Harmful-Header");
    }

    private void SanitizeRequestQuery(HttpRequest request)
    {
        Dictionary<string, StringValues> items = new();
        foreach (var item in request.Query)
        {
            var clean = item.Value;
            clean = HttpUtility.UrlEncode(clean);
            items.Add(item.Key, clean);
        }
        request.Query = new QueryCollection(items);
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
