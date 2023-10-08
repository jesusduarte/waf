using System.Text.Json;
using WAF.Configuration;
using WAF.Middlewares;

namespace WAF
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var configJson = File.ReadAllText("rules.json");
            var config = JsonSerializer.Deserialize<Config>(configJson, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                IncludeFields = true,
            });

            if (config != null)
            {
                File.WriteAllText("backup.json", JsonSerializer.Serialize<Config>(config));
            }
            
            var rules = config.Rules;
            Dictionary<string, List<Rule>> rulesByMethod;
            Dictionary<string, List<Rule>> rulesMixedByMethod;

            // Organize rules by method for efficient filtering
            rulesByMethod = rules
                .GroupBy(rule => rule.Method)
                .ToDictionary(group => group.Key, group => group.ToList());

            // Amalgamate and cache rules
            rulesMixedByMethod = new Dictionary<string, List<Rule>>();
            foreach (var method in rulesByMethod.Keys)
            {
                rulesMixedByMethod[method] = new List<Rule>();
                if (rulesByMethod.ContainsKey(method))
                    rulesMixedByMethod[method].AddRange(rulesByMethod[method]);
                if (rulesByMethod.ContainsKey("ANY"))
                    rulesMixedByMethod[method].AddRange(rulesByMethod["ANY"]);
            }

            var builder = WebApplication.CreateBuilder(args);
            builder.WebHost.ConfigureKestrel(serverOptions =>
            {
                serverOptions.AddServerHeader = false;
            });
            // Add services to the container.

            //builder.Services.AddControllers();
            builder.Services.AddHttpClient();
            
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            //builder.Services.AddEndpointsApiExplorer();
            //builder.Services.AddSwaggerGen();

            var app = builder.Build();

            app.UseMiddleware<NetMiddleware>(config);
            app.UseMiddleware<WafMiddleware>(config,rulesMixedByMethod);
            app.UseMiddleware<DlpMiddleware>(config);
            app.UseMiddleware<ProxyMiddleware>(config);

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                //app.UseSwagger();
                //app.UseSwaggerUI();
            }
 
            //app.UseHttpsRedirection();

            //app.UseAuthorization();


            //app.MapControllers();

            app.Run();
        }
    }
}