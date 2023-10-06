using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using System;
using System.IO;
using System.IO.Pipelines;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.VisualBasic;
using System.Security.Principal;

namespace WAF
{
    public class Proxy2Middleware
    {
        private readonly RequestDelegate _next;

        public Proxy2Middleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            //var request = await FormatRequest(context.Request);
            var originalRequestBody = context.Request.Body;
            var bufferRequest = new Pipe();
            var readerRequest = bufferRequest.Reader;

            context.Request.Body = bufferRequest.Reader.AsStream();
            List<KeyValuePair<string, StringValues>> originalRequestHeaders = new();
            foreach (var item in context.Request.Headers)
            {
                originalRequestHeaders.Add(item);
            }

            var copyRequestTask = CopyStreamToPipeAsync(originalRequestBody, bufferRequest.Writer);

            // -------------------------- RESPONSE -----------------------------------
            var originalResponseBody = context.Response.Body;

            //var buffer = new MemoryStream();
            //context.Response.Body = buffer;

            var bufferResponse = new Pipe();
            var reader = bufferResponse.Reader;
            var readerStream = bufferResponse.Reader.AsStream();

            List<KeyValuePair<string, StringValues>> originalResponseHeaders = new();
            foreach (var item in context.Response.Headers)
            {
                originalResponseHeaders.Add(item);
            }


            context.Response.Body = bufferResponse.Writer.AsStream();

            // Continue processing the request
            var nextMiddleware = _next(context);

            // Capture and log the response asynchronously
            //var copyTask = ProcessResponseAsync(buffer, originalResponseBody);
            var copyResponseTask = CopyPipeToStreamAsync(reader, originalResponseBody);

            await Task.WhenAll(new Task[]{
                copyRequestTask,
                nextMiddleware
            });
            await bufferResponse.Writer.CompleteAsync();
            await copyResponseTask;

            context.Response.Body = originalResponseBody;

            //----- Obtener MemoryStreams para debuggeo -----
            if (context.Request.Path.ToString().Contains("chat"))
            {
                await LogChatRequestAndResponse(context, copyRequestTask.Result, copyResponseTask.Result);
            }
            else
            {
                //await LogChatRequestAndResponse(context, copyRequestTask.Result, copyResponseTask.Result);
                await LogRequestAndResponse(context, copyRequestTask.Result, copyResponseTask.Result);
            }


        }

        private static async Task<MemoryStream> CopyStreamToPipeAsync(Stream source, PipeWriter output)
        {
            var captured = new MemoryStream();

            int buffsize = 1024;
            //var data = new byte[buffsize];
            var count = 0;
            while (true)
            {
                //Console.WriteLine("CopyStreamToPipeAsync Loop:"+count++);
                var outputSpan = output.GetMemory(buffsize);
                var readInt = await source.ReadAsync(outputSpan);

                if (readInt == 0) break;

                output.Advance(readInt);
                await captured.WriteAsync(outputSpan[..readInt]);
                await output.FlushAsync();
                //await Console.Out.WriteAsync("Audit Request: " + Encoding.UTF8.GetString(outputSpan[..readInt].ToArray()));
                //await Console.Out.FlushAsync();

            }
            await output.FlushAsync();
            await captured.FlushAsync();

            await output.CompleteAsync();


            captured.Seek(0, SeekOrigin.Begin);
            return captured;
        }


        private static async Task<MemoryStream> CopyPipeToStreamAsync(PipeReader source, Stream output)
        {
            var captured = new MemoryStream();
            var totalRead = 0;
            while (true)
            {
                var read = await source.ReadAsync();
                foreach (var item in read.Buffer)
                {
                    await captured.WriteAsync(item);
                    await output.WriteAsync(item);
                    //await Console.Out.WriteLineAsync(string.Format("Audit Response [{0}]: {1}", item.Length, Encoding.UTF8.GetString(item.ToArray())));

                    totalRead += item.Length;

                    await output.FlushAsync();
                    await captured.FlushAsync();
                }

                var position = read.Buffer.End;
                source.AdvanceTo(position, position);

                if (read.IsCompleted)
                {
                    break;
                }
                if (read.IsCanceled)
                {
                    break;
                }

            }

            await source.CompleteAsync();

            await Task.WhenAll(
                output.FlushAsync(),
                captured.FlushAsync()
            );

            return captured;
        }

        private async Task<string> FormatRequest(Stream request)
        {
            var result = await new StreamReader(request).ReadToEndAsync();
            request.Seek(0, SeekOrigin.Begin);

            return result;
        }

        private async Task<string> FormatChatResponseStreamed(MemoryStream responseStream)
        {
            var startPos = responseStream.Position;
            // Implement formatting of response data
            var reader = new StreamReader(responseStream);

            //string read = await reader.ReadToEndAsync();

            StringBuilder resultBuilder = new();
            while (!reader.EndOfStream)
            {
                var line = await reader.ReadLineAsync();
                if (string.IsNullOrWhiteSpace(line)) { continue; }
                if (!line.StartsWith("data: ")) { continue; }
                var jsonText = line[6..];
                if (jsonText == "[DONE]") { break; }

                JsonDocument doc;

                try
                {
                    doc = JsonDocument.Parse(jsonText);
                }
                catch (Exception e)
                {

                    //No se pudo parsear el string como json. Cambió el formato?
                    continue;
                }

                var objectType = doc.RootElement.GetProperty("object");
                if (objectType.GetString() != "chat.completion.chunk") { continue; }

                var choise = doc.RootElement.GetProperty("choices")[0];
                var delta = choise.GetProperty("delta");
                if (!delta.TryGetProperty("content", out var content))
                {
                    doc.Dispose();
                    continue;
                }

                resultBuilder.Append(content.GetString());
                doc.Dispose();
            }

            return resultBuilder.ToString();
        }

        private async Task<string> ReadAllToString(MemoryStream responseStream)
        {
            // Implement formatting of response data
            var reader = new StreamReader(responseStream);
            string read = await reader.ReadToEndAsync();
            return read;
        }

        private async Task LogRequestAndResponse(HttpContext context, MemoryStream request, MemoryStream response)
        {
            request.Position = 0;
            response.Position = 0;

            await ColorWriteLine(ConsoleColor.Yellow, "Request:");
            await Console.Out.WriteLineAsync(await ReadAllToString(request));
            await ColorWriteLine(ConsoleColor.Yellow, "Response:");
            await Console.Out.WriteLineAsync(await ReadAllToString(response));
        }


        private async Task ColorWriteLine(ConsoleColor color, string text)
        {
            var origFC = Console.ForegroundColor;
            Console.ForegroundColor = color;
            await Console.Out.WriteLineAsync(text);
            Console.ForegroundColor = origFC;
        }
    }
}