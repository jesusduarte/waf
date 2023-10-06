using System.Text.Json;
using WAF.Rules;

namespace WAF
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var rulesJson = File.ReadAllText("rules.json");
            var rules = JsonSerializer.Deserialize<List<Rule>>(rulesJson);
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

            // Add services to the container.

            //builder.Services.AddControllers();
            builder.Services.AddHttpClient();
            
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            //builder.Services.AddEndpointsApiExplorer();
            //builder.Services.AddSwaggerGen();

            var app = builder.Build();

            app.UseMiddleware<ProxyMiddleware>(rulesMixedByMethod);

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