using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;
using Common.Auth.WebTokens;

namespace Common.Auth.Filters
{
    public class AuthorizeFilter : AuthorizeAttribute
    {
        private readonly IWebTokenService _webTokenService;

        public AuthorizeFilter(IWebTokenService webTokenService)
        {
            _webTokenService = webTokenService;
        }

        protected override bool IsAuthorized(HttpActionContext actionContext)
        {
            _webTokenService.Authenticate(actionContext.Request);

            // Check the signed in user
            // is allowed to access the resource

            return base.IsAuthorized(actionContext);
        }
    }
}
