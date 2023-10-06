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
using WAF.Rules;
using System.Web;
using System.Collections.Immutable;

public class ProxyMiddleware
{
    private readonly RequestDelegate _next;
    private readonly HttpClient _httpClient;

    //private readonly string upstream= "https://httpbin.org";
    private readonly string upstream = "https://www.cerveceriaduarte.mx";
    private Dictionary<string, List<Rule>> _rules;

    public ProxyMiddleware(RequestDelegate next, HttpClient httpClient, Dictionary<string, List<Rule>> amalgamatedRules)
    {
        _next = next;

 
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
            await context.Response.WriteAsync("Request blocked by WAF");
            return;
        }
        
        _rules.TryGetValue(context.Request.Method, out var relevantRules);
        //var matchedRule = relevantRules?.FirstOrDefault(rule => rule.Matches(context.Request));
        //if (matchedRule == null || matchedRule.Action.Equals("deny", StringComparison.OrdinalIgnoreCase))
        var matchedRule = relevantRules?.FindAll(rule => rule.Matches(context.Request));  
        if (matchedRule == null || matchedRule.Count==0 || matchedRule.First().Action.Equals("deny",StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = 403; // Forbidden
            await context.Response.WriteAsync("Request blocked by WAF");
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
            //TODO: Check cookie and encrypt.
            string value = string.Join("; ", header.Value.ToArray());
            Debug.WriteLine("(*) Response.Cookie: {0} - {1}", header.Key, value);
            contextResponse.Headers[header.Key] = value;
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
            var keyRegex = new Regex(@"^[a-z][a-z0-9]+(\[[a-z][a-z0-9]+\])*$", RegexOptions.IgnoreCase);
            var valueRegex = new Regex(@"^[a-z0-9\-_\?\*\+\\/\^\`~=!""\$%&\(\)]+$", RegexOptions.IgnoreCase);
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
            //if (header.Key.StartsWith("Sec-", StringComparison.OrdinalIgnoreCase))
            //{
            //    continue;
            //}

            _httpClient.DefaultRequestHeaders.TryAddWithoutValidation(header.Key, string.Join(", ", header.Value));
            Debug.WriteLine("(*) Request.Header: {0} - {1}", header.Key, string.Join(", ", header.Value));
        }

        //List<string> cookieValues = new();
        //foreach (var cookie in context.Request.Cookies)
        //{
        //    //SetCookieHeaderValue.Parse();
        //    cookieValues.Add(string.Format("{0}={1}", cookie.Key, cookie.Value));
        //    Debug.WriteLine("(*) UpstreamRequest.Cookie: {0} - {1}", cookie.Key, cookie.Value);
        //    _httpClient.DefaultRequestHeaders.Add("Cookie", string.Format("{0}={1}", cookie.Key, cookie.Value));
        //}

        var cookieHeaders = context.Response.Headers.Where(h => h.Key.StartsWith("cookie", StringComparison.OrdinalIgnoreCase)).ToList();
        foreach (var header in cookieHeaders) {
            //_httpClient.DefaultRequestHeaders.Add(header.Key, header.Value);
            Debug.WriteLine("(*) UpstreamRequest.Cookie: {0} - {1}", header.Key, header.Value);
            var value = header.Value.ToString();
            _httpClient.DefaultRequestHeaders.TryAddWithoutValidation(header.Key, value);
        }
        //if (cookieValues.Count > 0)
        //{
        //    upstreamRequest.Headers.Add("Cookie", string.Join("; ", cookieValues));
        //    //upstreamRequest.Content.Headers.Add("X-Content-Cookie", string.Join("; ", cookieValues));
        //}

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
