using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using Microsoft.AspNetCore.Http.Extensions;
using System.Diagnostics;
using System.IO;
using System.Net;
using WAF.Configuration;

namespace WAF.Middlewares;

public class ProxyMiddleware
{
    private readonly RequestDelegate _next;

    private readonly string upstream = string.Empty;
    private readonly Config _config;

    public ProxyMiddleware(RequestDelegate next, Config config)
    {
        _next = next;
        _config = config;
        upstream = _config.Upstream;
        Debug.WriteLine("(+) ProxyMiddleware constructor");
    }

    public async Task InvokeAsync(HttpContext context)
    {
        await ProxyRequest(context);

        //await _next(context);
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
        var cookiesToAdd = new List<CookieHeaderValue>();
        foreach (var header in cookieHeaders)
        {
            string key = header.Key;
            var cookies = CookieHeaderValue.ParseList(header.Value);

            foreach (var cookie in cookies??new List<CookieHeaderValue>())
            {
                bool renameCookie = _config.SessionConfig != null && 
                    _config.SessionConfig.RenameTo.Equals(cookie.Name.Value, StringComparison.OrdinalIgnoreCase);
                
                if (renameCookie)
                {
                    cookie.Name = _config.SessionConfig?.CookieName;
                }

                bool decryptCookie = _config.SessionConfig != null &&
                    _config.SessionConfig.Encrypt.HasValue &&
                    _config.SessionConfig.Encrypt.Value == true && 
                    _config.SessionConfig.CookieName.Equals(cookie.Name.Value, StringComparison.OrdinalIgnoreCase);
                
                if (decryptCookie)
                {
                    try
                    {
                        var crypto = new AesCryptor(_config.SessionConfig?.EncryptKey ?? string.Empty);
                        cookie.Value = crypto.Decrypt(cookie.Value.Value);
                    }
                    catch (Exception e)
                    {
                        cookie.Value = string.Empty;
                        Debug.WriteLine("{0} Response.CookieDec: {1}", "{!}", "Could Not decrypt cookie value");
                    }
                    Debug.WriteLine("(*) Response.CookieDec: {0} - {1}", cookie.Name.Value, cookie.Value.Value);
                }

                Debug.WriteLine("(*) UpstreamRequest.Cookie: {0} - {1}", key, cookie.ToString());
                cookiesToAdd.Add(cookie);
                //_httpClient.DefaultRequestHeaders.TryAddWithoutValidation(key, cookie.ToString());
            }
            
        }

        cookiesToAdd.ForEach(c =>
            _httpClient.DefaultRequestHeaders.TryAddWithoutValidation("cookie", c.ToString())
        );
        

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

    private async Task CopyUpstreamResponseToContext(HttpResponseMessage upstreamResponse, HttpResponse contextResponse)
    {
        contextResponse.StatusCode = (int)upstreamResponse.StatusCode;

        // Copy headers if needed
        var setcookiesHeaders = upstreamResponse.Headers.Where(h => h.Key.StartsWith("set-cookie", StringComparison.OrdinalIgnoreCase)).ToList();
        setcookiesHeaders.ForEach(x => Console.WriteLine("Set-Cookie:  " +x.Key + " " + string.Join( ", ", x.Value)));

        var toAddSetCookies = new List<SetCookieHeaderValue>();

        var responseContextSetCookieHeaders = SetCookieHeaderValue.ParseList(contextResponse.Headers
            .Where(h => h.Key.StartsWith("set-cookie", StringComparison.OrdinalIgnoreCase))
            .Select(h => h.Value.ToString())
            .ToList()
        );
        toAddSetCookies.AddRange(responseContextSetCookieHeaders);

        var typedHeaders = contextResponse.GetTypedHeaders();
        var cookies = typedHeaders.SetCookie;

        if (toAddSetCookies.Count > 0)
        {
            contextResponse.Headers.Remove("set-cookie");
        }

        foreach (var setCookieHeader in setcookiesHeaders)
        {
            var values = SetCookieHeaderValue.ParseList(setCookieHeader.Value.ToList());

            foreach (var setcookie in values)
            {
                //var setcookie = ;

                if (_config.SessionConfig != null && 
                    _config.SessionConfig.CookieName.Equals(setcookie.Name.Value, StringComparison.OrdinalIgnoreCase))
                {
                    setcookie.Name = _config.SessionConfig.RenameTo;
                    if (_config.SessionConfig.Secure.HasValue)
                    {
                        setcookie.Secure = _config.SessionConfig.Secure.Value;
                    }
                    if (_config.SessionConfig.HttpOnly.HasValue)
                    {
                        setcookie.HttpOnly = _config.SessionConfig.HttpOnly.Value;
                    }
                    if (_config.SessionConfig.SameSite != Microsoft.Net.Http.Headers.SameSiteMode.Unspecified)
                    {
                        setcookie.SameSite = _config.SessionConfig.SameSite;
                    }
                    if (_config.SessionConfig.Encrypt.HasValue && _config.SessionConfig.Encrypt.Value == true)
                    {
                        var crypto = new AesCryptor(_config.SessionConfig.EncryptKey ?? string.Empty);
                        setcookie.Value = crypto.Encrypt(setcookie.Value.Value); //Encrypt(setcookie.Value.Value, _config.SessionConfig.EncryptKey);
                        Debug.WriteLine("(*) Response.SetCookieEnc: {0} - {1}", setcookie.Name.Value, setcookie.Value.Value);
                    }
                }
                Debug.WriteLine("(*) Response.SetCookie: {0} - {1}", setCookieHeader.Key, setcookie.Value);
                Debug.WriteLine("(*) Response.SetCookieCHV: {0} - {1}", setCookieHeader.Key, setcookie.ToString());
                toAddSetCookies.Add(setcookie);
            }
        }

        if (toAddSetCookies.Count > 0)
        {
            

            //contextResponse.Headers.Add(
            //    "set-cookie",
            //    string.Join(", ", toAddSetCookies.Select(c =>
            //    {
            //        Console.WriteLine("Adding Cookie to contextReponse.Header: " + c.ToString());
            //        return c.ToString();
            //    })
            //    )
            //);

            toAddSetCookies.Select(c => {
                    Console.WriteLine("Adding Cookie to contextReponse.Header: " + c.ToString());
                    return c.ToString();
                })
                .ToList()
                .ForEach(x => contextResponse.Headers.Add("set-cookie", x));
            
        }

        //contextResponse.Headers.Add("set-cookie", string.Join(", ", toAddSetCookies.Select(c => c.ToString()).ToArray()));

        var otherHeaders = upstreamResponse.Headers.Where(h => !h.Key.StartsWith("set-cookie", StringComparison.OrdinalIgnoreCase)).ToList();
        foreach (var header in otherHeaders)
        {
            string value = string.Join("; ", header.Value.ToArray());
            contextResponse.Headers[header.Key] = value;
            //Debug.WriteLine("(*) Response.Header: {0} - {1}", header.Key, value);
        }
        foreach (var header in upstreamResponse.Content.Headers)
        {
            string value = string.Join("; ", header.Value.ToArray());
            contextResponse.Headers[header.Key] = header.Value.ToArray();
            //Debug.WriteLine("(*) Response.Content.Header: {0} - {1}", header.Key, value);
        }
        foreach (var header in upstreamResponse.TrailingHeaders)
        {
            string value = string.Join("; ", header.Value.ToArray());
            contextResponse.Headers[header.Key] = header.Value.ToArray();
            //Debug.WriteLine("(*) Response.Trailing.Header: {0} - {1}", header.Key, value);
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
}
