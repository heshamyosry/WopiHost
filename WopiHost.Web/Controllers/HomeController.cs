using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http;
using System.Threading.Tasks;
using WopiHost.Discovery;
using WopiHost.Discovery.Enumerations;
using WopiHost.Url;
using WopiHost.Abstractions;
using WopiHost.FileSystemProvider;
using WopiHost.Web.Models;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;

namespace WopiHost.Web.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private WopiUrlBuilder _urlGenerator;

        private WopiOptions WopiOptions { get; }
        private IWopiStorageProvider StorageProvider { get; }
        private IDiscoverer Discoverer { get; }
        private ILoggerFactory LoggerFactory { get; }

        private readonly IConfiguration _configuration;

        //TODO: remove test culture value and load it from configuration SECTION
        public WopiUrlBuilder UrlGenerator => _urlGenerator ??= new WopiUrlBuilder(Discoverer, new WopiUrlSettings { UiLlcc = new CultureInfo("en-US") });

        public HomeController(IConfiguration configuration, IWopiStorageProvider storageProvider, IDiscoverer discoverer, ILoggerFactory loggerFactory)
        {
            WopiOptions = new WopiOptions();
            configuration.GetSection(WopiConfigurationSections.WOPI_ROOT).Bind(WopiOptions);
            _configuration = configuration;
            StorageProvider = storageProvider;
            Discoverer = discoverer;
            LoggerFactory = loggerFactory;
        }

        public async Task<ActionResult> Index()
        {
            try
            {
                var files = StorageProvider.GetWopiFiles(StorageProvider.RootContainerPointer.Identifier);
                var fileViewModels = new List<FileViewModel>();
                foreach (var file in files)
                {
                    fileViewModels.Add(new FileViewModel
                    {
                        FileId = file.Identifier,
                        FileName = file.Name,
                        SupportsEdit = await Discoverer.SupportsActionAsync(file.Extension, WopiActionEnum.Edit),
                        SupportsView = await Discoverer.SupportsActionAsync(file.Extension, WopiActionEnum.View),
                        IconUri = (await Discoverer.GetApplicationFavIconAsync(file.Extension)) ?? new Uri("file.ico", UriKind.Relative)
                    });
                }
                return View(fileViewModels);
            }
            catch (DiscoveryException ex)
            {
                return View("Error", ex);
            }
            catch (HttpRequestException ex)
            {
                return View("Error", ex);
            }
        }

        public async Task<ActionResult> Detail(string id, string wopiAction)
        {
            var actionEnum = Enum.Parse<WopiActionEnum>(wopiAction);
            var securityHandler = new WopiSecurityHandler(LoggerFactory,_configuration); //TODO: via DI

            var file = StorageProvider.GetWopiFile(id);
            var x = await HttpContext.GetTokenAsync("access_token");
            var token = securityHandler.GenerateAccessToken("Anonymous", file.Identifier);


            ViewData["access_token"] = x;// securityHandler.WriteToken(token);
            //TODO: fix
            //ViewData["access_token_ttl"] = //token.ValidTo

            //http://dotnet-stuff.com/tutorials/aspnet-mvc/how-to-render-different-layout-in-asp-net-mvc


            var extension = file.Extension.TrimStart('.');
            ViewData["urlsrc"] = await UrlGenerator.GetFileUrlAsync(extension, new Uri(WopiOptions.HostUrl, $"/wopi/files/{id}"), actionEnum); //TODO: add a test for the URL not to contain double slashes between host and path
            ViewData["favicon"] = await Discoverer.GetApplicationFavIconAsync(extension);
            return View();
        }

    }
}
