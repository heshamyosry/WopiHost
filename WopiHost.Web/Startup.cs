using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using WopiHost.Abstractions;
using WopiHost.Discovery;
using WopiHost.FileSystemProvider;
using WopiHost.Web.Models;

namespace WopiHost.Web
{
    public class Startup
    {
        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        /// <summary>
        /// Sets up the DI container.
        /// </summary>
        public void ConfigureServices(IServiceCollection services)
        {


            services.AddControllersWithViews()
                .AddRazorRuntimeCompilation(); // Add browser link
            services.AddSingleton(Configuration);

            // Configuration
            services.AddOptions();
            services.Configure<WopiOptions>(Configuration.GetSection(WopiConfigurationSections.WOPI_ROOT));

            services.AddHttpClient<IDiscoveryFileProvider, HttpDiscoveryFileProvider>(client =>
            {
                client.BaseAddress = new Uri(Configuration[$"{WopiConfigurationSections.WOPI_ROOT}:{nameof(WopiOptions.ClientUrl)}"]);
            }).ConfigurePrimaryHttpMessageHandler(() => new System.Net.Http.HttpClientHandler
            {
                ClientCertificateOptions = System.Net.Http.ClientCertificateOption.Manual,
                ServerCertificateCustomValidationCallback =
                (httpRequestMessage, cert, cetChain, policyErrors) =>
                {
                    return true;
                }
            }); ;
            services.Configure<ForwardedHeadersOptions>(options =>
            {
                options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
                options.KnownNetworks.Clear();
                options.KnownProxies.Clear();
            });
            services.Configure<DiscoveryOptions>(Configuration.GetSection($"{WopiConfigurationSections.DISCOEVRY_OPTIONS}"));
            services.AddSingleton<IDiscoverer, WopiDiscoverer>();

            services.AddScoped<IWopiStorageProvider, WopiFileSystemProvider>();

            services.AddLogging(loggingBuilder =>
            {
                loggingBuilder.AddConsole();//Configuration.GetSection("Logging")
                loggingBuilder.AddDebug();
            });


            services.AddAuthentication(options =>
            {
                options.DefaultScheme = "Cookies";
                options.DefaultChallengeScheme = "oidc";
            })
                .AddCookie("Cookies", options =>
                {
                    options.ExpireTimeSpan = TimeSpan.FromDays(365);
                })
                .AddOpenIdConnect("oidc", options =>
                {
                    options.Authority = Configuration["AuthServer:Authority"];
                    options.RequireHttpsMetadata = Convert.ToBoolean(Configuration["AuthServer:RequireHttpsMetadata"]);
                    options.ResponseType = OpenIdConnectResponseType.CodeIdToken;
                    options.NonceCookie.SameSite = (SameSiteMode)(-1);
                    options.CorrelationCookie.SameSite = (SameSiteMode)(-1);

                    options.ClientId = Configuration["AuthServer:ClientId"];
                    options.ClientSecret = Configuration["AuthServer:ClientSecret"];

                    options.SaveTokens = true;
                    options.GetClaimsFromUserInfoEndpoint = true;

                    options.Scope.Add("role");
                    options.Scope.Add("email");
                    options.Scope.Add("phone");
                    options.Scope.Add("wopi");
                });

        }

        /// <summary>
        /// Configure is called after ConfigureServices is called.
        /// </summary>
        public void Configure(IApplicationBuilder app)
        {
            System.Net.ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, error) => { return true; };

            app.UseDeveloperExceptionPage();
            app.UseForwardedHeaders();
            //app.UseHttpsRedirection();

            // Add static files to the request pipeline.
            app.UseStaticFiles();
            app.UseCookiePolicy(new CookiePolicyOptions
            {
                Secure = CookieSecurePolicy.None
            });

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();


            // Add MVC to the request pipeline.
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}