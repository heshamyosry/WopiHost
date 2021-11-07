﻿using System.Collections.Generic;
using Autofac;
using Autofac.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WopiHost.Abstractions;
using WopiHost.Core;
using WopiHost.Core.Models;
using Microsoft.Extensions.Hosting;
using Serilog;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System;
using Microsoft.AspNetCore.HttpOverrides;

namespace WopiHost
{
    public class Startup
    {
        public IConfiguration Configuration { get; set; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public void ConfigureContainer(ContainerBuilder builder)
        {
            var config = Configuration.GetSection(WopiConfigurationSections.WOPI_ROOT).Get<WopiHostOptions>();
            // Add file provider
            builder.AddFileProvider(config.StorageProviderAssemblyName);

            if (config.UseCobalt)
            {
                // Add cobalt
                builder.AddCobalt();
            }
        }

        /// <summary>
        /// Sets up the DI container. Loads types dynamically (http://docs.autofac.org/en/latest/register/scanning.html)
        /// </summary>
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers(); //.AddControllersAsServices(); https://autofaccn.readthedocs.io/en/latest/integration/aspnetcore.html#controllers-as-services

            // Ideally, pass a persistent dictionary implementation
            services.AddSingleton<IDictionary<string, LockInfo>>(d => new Dictionary<string, LockInfo>());

            services.AddLogging(loggingBuilder =>
            {
                loggingBuilder.AddConsole(); //Configuration.GetSection("Logging")
                loggingBuilder.AddDebug();
            });

            // Configuration
            services.AddOptions();

            var config = Configuration.GetSection(WopiConfigurationSections.WOPI_ROOT);

            services.Configure<WopiHostOptions>(config);
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.Authority = Configuration["AuthServer:Authority"];
                    options.RequireHttpsMetadata = Convert.ToBoolean(Configuration["AuthServer:RequireHttpsMetadata"]);
                    options.Audience = "wopi";
                });
            services.Configure<ForwardedHeadersOptions>(options =>
            {
                options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
                options.KnownNetworks.Clear();
                options.KnownProxies.Clear();
            });
            // Add WOPI (depends on file provider)
            services.AddWopi(GetSecurityHandler(services, config.Get<WopiHostOptions>().StorageProviderAssemblyName));
        }

        private IWopiSecurityHandler GetSecurityHandler(IServiceCollection services, string storageProviderAssemblyName)
        {
            var providerBuilder = new ContainerBuilder();
            // Add file provider implementation
            providerBuilder.AddFileProvider(storageProviderAssemblyName); //TODO: why?
            providerBuilder.Populate(services);
            var providerContainer = providerBuilder.Build();
            return providerContainer.Resolve<IWopiSecurityHandler>();
        }

        /// <summary>
        /// Configure is called after ConfigureServices is called.
        /// </summary>
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseForwardedHeaders();

            app.UseStaticFiles();
            //app.UseHttpsRedirection();
            app.UseSerilogRequestLogging(options =>
            {
                options.EnrichDiagnosticContext = LogHelper.EnrichWithWopiDiagnostics;
                options.MessageTemplate = "HTTP {RequestMethod} {RequestPath} with [WOPI CorrelationID: {" + nameof(WopiHeaders.CORRELATION_ID) + "}, WOPI SessionID: {" + nameof(WopiHeaders.SESSION_ID) + "}] responded {StatusCode} in {Elapsed:0.0000} ms";
            });

            app.UseRouting();

            // Automatically authenticate
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
