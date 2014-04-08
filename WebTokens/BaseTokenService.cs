using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading;
using System.Web;
using System.Web.Http;
using Common.Auth.Models;
using Common.Web.ExtensionMethods;

namespace Common.Auth.WebTokens
{
    public abstract class BaseTokenService : IWebTokenService
    {
        protected abstract string Scheme { get; }
        protected readonly byte[] Key;

        protected BaseTokenService(string keyString)
        {
            Key = Convert.FromBase64String(keyString);
        }

        public abstract string CreateToken(ClaimsIdentity identity, DateTime expiration);
        public abstract ClaimsIdentity ValidateToken(AuthenticationHeaderValue header);

        public HttpResponseMessage SetCookie(
            HttpResponseMessage response, 
            ClaimsIdentity identity, 
            DateTime expirationDate)
        {
            var token = CreateToken(identity, expirationDate);
            SetPrincipal(identity);
            SetToken(response, token);
            return response;
        }

        public void Authenticate(HttpRequestMessage request)
        {
            try
            {
                var authHeader = GetToken(request);
                if (authHeader == null) throw new Exception("The authorization header has not been set");
                var identity = ValidateToken(authHeader);
                SetPrincipal(identity);
            }
            catch (Exception e)
            {
                var response = request.CreateErrorResponse(HttpStatusCode.Unauthorized, e);
                ClearToken(response);
                SetPrincipal(null);
                throw new HttpResponseException(response);
            }
        }

        public HttpResponseMessage ClearAuthentication(HttpResponseMessage response)
        {
            SetPrincipal(null);
            return ClearToken(response);
        }

        public AuthenticationHeaderValue GetToken(HttpRequestMessage request)
        {
            var cookies = request.Headers.GetCookies("Authorization")
                .SelectMany(cookieList => cookieList.Cookies);

            foreach (var cookie in cookies)
            {
                AuthenticationHeaderValue token;
                if (AuthenticationHeaderValue.TryParse(cookie.Value, out token)
                 && token.Scheme == Scheme)
                {
                    return token;
                }
            }

            return null;
        }

        public void SetToken(HttpResponseMessage response, string token)
        {
            response.SetCookie("Authorization", token);
        }

        public HttpResponseMessage ClearToken(HttpResponseMessage response)
        {
            response.ClearCookie("Authorization");
            return response;
        }

        public void SetPrincipal(ClaimsIdentity identity)
        {
            ClaimsPrincipal principal = null;
            if (identity != null)
            {
                var roles = identity.Claims
                    .Where(claim => claim.Type == ClaimTypes.Role)
                    .Select(claim => claim.Value);
                principal = new GenericPrincipal(identity, roles.ToArray());
            }
            Thread.CurrentPrincipal = principal;
            HttpContext.Current.User = principal;
        }
    }
}
