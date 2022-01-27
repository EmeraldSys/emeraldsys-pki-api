using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using AspNetCoreRateLimit;
using AspNetCoreRateLimit.Redis;

using Quartz;

namespace EmeraldSysPKIBackend
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddOptions();
            services.AddMemoryCache();
            services.Configure<IpRateLimitOptions>(options =>
            {
                options.EnableEndpointRateLimiting = false;
                options.StackBlockedRequests = false;
                options.HttpStatusCode = 429;
                options.GeneralRules = new List<RateLimitRule>()
                {
                    new RateLimitRule()
                    {
                        Endpoint = "*",
                        Period = "10s",
                        Limit = 15
                    }
                };
                options.QuotaExceededResponse = new QuotaExceededResponse()
                {
                    Content = "{{\"success\": false, \"message\": \"You are being rate limited.\", \"info\": {{\"limit\": {0}, \"period\": \"{1}\", \"retryAfter\": {2}}}}}",
                    ContentType = "application/json",
                    StatusCode = 429
                };
            });
            services.AddInMemoryRateLimiting();
            services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();

            services.Configure<KestrelServerOptions>(options =>
            {
                options.AllowSynchronousIO = true;
            });

            services.AddMvc().AddNewtonsoftJson();

            services.AddControllers();

            services.AddCors(options => options.AddPolicy("default", builder =>
            {
                builder.AllowAnyMethod().AllowAnyHeader().AllowCredentials().SetIsOriginAllowed(host => true);
            }));

            DotNetEnv.Env.Load();

            services.AddQuartz(q =>
            {
                q.SchedulerId = "SchedulerMain";
                q.SchedulerName = "Scheduler Main";

                q.UseMicrosoftDependencyInjectionJobFactory();

                q.UseSimpleTypeLoader();
                q.UseInMemoryStore();
                q.UseDefaultThreadPool(tp =>
                {
                    tp.MaxConcurrency = 10;
                });

                q.ScheduleJob<AutoUpd>(tr => tr
                    .WithIdentity("Auto Update CRL Trigger")
                    .StartNow()
                    .WithCalendarIntervalSchedule(x => x.WithIntervalInWeeks(2))
                    .WithDescription("Auto updates CRLs with Amazon S3")
                );
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            //app.UseHttpsRedirection();

            app.Use(async (ctx, next) =>
            {
                await next();

                if (ctx.Response.StatusCode == 404 && !ctx.Response.HasStarted)
                {
                    ctx.Request.Path = "/error/404";
                    await next();
                }
            });

            app.UseIpRateLimiting();
            app.UseRouting();
            app.UseCors("default");
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}