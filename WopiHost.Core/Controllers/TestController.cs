using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using WopiHost.Abstractions;
using WopiHost.Core.Models;
using RouteAttribute = Microsoft.AspNetCore.Mvc.RouteAttribute;

namespace WopiHost.Core.Controllers
{
    [Route("wopi/[controller]")]
    [Authorize]
    public class TestController : WopiControllerBase
    {
        public TestController(IOptionsSnapshot<WopiHostOptions> wopiHostOptions, IWopiStorageProvider storageProvider, IWopiSecurityHandler securityHandler) : base(storageProvider, securityHandler, wopiHostOptions)
        {
        }
        public IActionResult Index() {
            return Ok(User.Identity.Name);
        }
    }
}
