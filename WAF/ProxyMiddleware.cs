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

public class ProxyMiddleware
{
    private readonly RequestDelegate _next;
    private readonly HttpClient _httpClient;

    //private readonly string upstream= "https://httpbin.org";
    private readonly string upstream = "https://www.cerveceriaduarte.mx";
    private readonly Dictionary<string, List<Rule>> _rules;
    private Config _config;

    public ProxyMiddleware(RequestDelegate next, Config config, Dictionary<string, List<Rule>> amalgamatedRules)
    {
        _next = next;
        _config = config;
 
        //_httpClient = httpClient;
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
            context.Response.Headers.Add("x-waf","1");
            context.Response.Headers.ContentType = "text/html";
            await context.Response.SendFileAsync(string.Format("status/{0}.html", context.Response.StatusCode));
            return;
        }
        
        _rules.TryGetValue(context.Request.Method, out var relevantRules);
        //var matchedRule = relevantRules?.FirstOrDefault(rule => rule.Matches(context.Request));
        //if (matchedRule == null || matchedRule.Action.Equals("deny", StringComparison.OrdinalIgnoreCase))
        var matchedRule = relevantRules?.FindAll(rule => rule.Matches(context.Request));
        if (matchedRule == null || matchedRule.Count==0 || matchedRule.First().Action.Equals("deny",StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = 403; // Forbidden
            context.Response.Headers.Add("x-waf-rule", "deny");
            context.Response.Headers.ContentType = "text/html";
            await context.Response.SendFileAsync(string.Format("status/{0}.html", context.Response.StatusCode));
            return;
        }

        // Sanitization logic here
        await SanitizeRequest(context.Request);

        await ProxyRequest(context);
    }

    private async Task CopyUpstreamResponseToContext(HttpResponseMessage upstreamResponse, HttpResponse contextResponse)
    {
        contextResponse.StatusCode = (int)upstreamResponse.StatusCode;

        // Copy headers if needed
        var setcookies = upstreamResponse.Headers.Where(h => h.Key.StartsWith("set-cookie", StringComparison.OrdinalIgnoreCase)).ToList();
        foreach (var header in setcookies) {
            string value = string.Join("; ", header.Value.ToArray());
            var setcookie = SetCookieHeaderValue.Parse(value);

            if (_config.SessionConfig != null && _config.SessionConfig.CookieName.Equals(setcookie.Name.Value, StringComparison.OrdinalIgnoreCase)) {
                setcookie.Name = _config.SessionConfig.RenameTo;
                if (_config.SessionConfig.Secure.HasValue) 
                {
                    setcookie.Secure = _config.SessionConfig.Secure.Value;
                }
                if (_config.SessionConfig.HttpOnly.HasValue)
                {
                    setcookie.HttpOnly = _config.SessionConfig.HttpOnly.Value;
                }
                if (_config.SessionConfig.SameSite != Microsoft.Net.Http.Headers.SameSiteMode.Unspecified )
                {
                    setcookie.SameSite = _config.SessionConfig.SameSite;
                }
                if (_config.SessionConfig.Encrypt.HasValue && _config.SessionConfig.Encrypt.Value == true)
                {
                    //string baseValue = setcookie.Value.Value;
                    //setcookie.Value = baseValue;
                    //TODO: Encrypt value
                    Debug.WriteLine("(*) Response.SetCookieEnc: {0} - {1}", setcookie.Name.Value, setcookie.Value.Value);
                }
            }
            Debug.WriteLine("(*) Response.SetCookie: {0} - {1}", header.Key, value);
            Debug.WriteLine("(*) Response.SetCookieCHV: {0} - {1}", header.Key, setcookie.ToString());
            contextResponse.Headers[header.Key] = setcookie.ToString();
        }

        var otherHeaders = upstreamResponse.Headers.Where(h => !h.Key.StartsWith("set-cookie", StringComparison.OrdinalIgnoreCase)).ToList(); 
        foreach (var header in otherHeaders )
        {
            string value = string.Join("; ",header.Value.ToArray());
            contextResponse.Headers[header.Key] = value;
            Debug.WriteLine("(*) Response.Header: {0} - {1}", header.Key, value);
        }
        foreach (var header in upstreamResponse.Content.Headers)
        {
            string value = string.Join("; ", header.Value.ToArray());
            contextResponse.Headers[header.Key] = header.Value.ToArray();
            Debug.WriteLine("(*) Response.Content.Header: {0} - {1}", header.Key, value);
        }
        foreach (var header in upstreamResponse.TrailingHeaders)
        {
            string value = string.Join("; ", header.Value.ToArray());
            contextResponse.Headers[header.Key] = header.Value.ToArray();
            Debug.WriteLine("(*) Response.Trailing.Header: {0} - {1}", header.Key, value);
        }

        // Copy response body
        var responseBodyStream = await upstreamResponse.Content.ReadAsStreamAsync();

        //MemoryStream mem = new MemoryStream();
        //await responseBodyStream.CopyToAsync(mem);
        //mem.Position = 0;
        //await mem.CopyToAsync(contextResponse.Body);

        await responseBodyStream.CopyToAsync(contextResponse.Body);
        await contextResponse.Body.FlushAsync();

    }

    private async Task<HttpRequestMessage> CreateUpstreamRequest(HttpContext context)
    {
        HttpRequest request = context.Request;
        // Create a new HttpRequestMessage and copy over the properties from the incoming HttpRequest
        Uri uri = new(upstream + request.Path + request.QueryString);

        var upstreamRequest = new HttpRequestMessage()
        {
            Method = new HttpMethod(request.Method),
            RequestUri = uri
        };
        Debug.WriteLine("Uri: {0}", upstreamRequest.RequestUri);

        if (request.ContentType != null)
        {
            MemoryStream mem = new();
            await request.Body.CopyToAsync(mem);
            mem.Position = 0;

            upstreamRequest.Content = new StreamContent(mem);
            upstreamRequest.Content.Headers.ContentLength = mem.Length;
            upstreamRequest.Content.Headers.TryAddWithoutValidation("Content-Type", request.ContentType.ToString());
            foreach (var header in request.Headers)
            {
                if (header.Key.StartsWith("Cookie", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                if (!header.Key.Contains("Content", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                if (header.Key.Contains("-type", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                if (header.Key.Contains("-length", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                upstreamRequest.Content.Headers.TryAddWithoutValidation(header.Key, string.Join(", ", header.Value));
                Debug.WriteLine("(*) Request.Content.Header: {0} - {1}", header.Key, string.Join(", ", header.Value));
            }
        }

        return upstreamRequest;
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

    private async Task ProxyRequest(HttpContext context)
    {
        // Forwarding logic here
        HttpClientHandler handler = new()
        {
            UseCookies = false,
            //CookieContainer = cookies,
            AllowAutoRedirect = false
        };
        var _httpClient = new HttpClient(handler, true);
        if (context.Connection.RemoteIpAddress != null)
        {
            _httpClient.DefaultRequestHeaders.Add("X-Forwarded-For", context.Connection.RemoteIpAddress.ToString());
        }

        // Copy headers, etc. if needed
        foreach (var header in context.Request.Headers)
        {
            if (header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            if (header.Key.Contains("Content", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            if (header.Key.StartsWith("Cookie", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            //if (header.Key.StartsWith("Sec-", StringComparison.OrdinalIgnoreCase))
            //{
            //    continue;
            //}

            _httpClient.DefaultRequestHeaders.TryAddWithoutValidation(header.Key, string.Join(", ", header.Value));
            Debug.WriteLine("(*) Request.Header: {0} - {1}", header.Key, string.Join(", ", header.Value));
        }

        var cookieHeaders = context.Request.Headers.Where(h => h.Key.StartsWith("cookie", StringComparison.OrdinalIgnoreCase)).ToList();
        foreach (var header in cookieHeaders) {            
            string key = header.Key;
            var cookie = CookieHeaderValue.Parse(header.Value.ToString());

            bool renameCookie = _config.SessionConfig != null && _config.SessionConfig.RenameTo.Equals(cookie.Name.Value, StringComparison.OrdinalIgnoreCase);
            if (renameCookie) {
                cookie.Name = _config.SessionConfig?.CookieName;
            }

            bool decryptCookie = _config.SessionConfig.Encrypt.HasValue && _config.SessionConfig.Encrypt.Value == true;
            if (decryptCookie)
            {
                //string baseValue = cookie.Value.Value;
                //cookie.Value = baseValue;
                //TODO: Decrypt value
                Debug.WriteLine("(*) Response.CookieDec: {0} - {1}", cookie.Name.Value, cookie.Value.Value);
            }

            Debug.WriteLine("(*) UpstreamRequest.Cookie: {0} - {1}", key, cookie.ToString());
            _httpClient.DefaultRequestHeaders.TryAddWithoutValidation(key, cookie.ToString());
        }

        try
        {
            var upstreamRequest = await CreateUpstreamRequest(context);
            var upstreamResponse = await _httpClient.SendAsync(
               upstreamRequest
               , HttpCompletionOption.ResponseHeadersRead
            );

            await CopyUpstreamResponseToContext(upstreamResponse, context.Response);
        }
        catch (Exception e)
        {
            await context.Response.WriteAsync(e.Message);
            Console.WriteLine(e);
        }
    }
}
