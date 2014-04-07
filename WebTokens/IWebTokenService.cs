using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using Common.Auth.Models;

namespace Common.Auth.WebTokens
{
    public interface IWebTokenService
    {
        HttpResponseMessage SetCookie(
            HttpResponseMessage response,
            ClaimsIdentity identity,
            DateTime expirationDate);

        void Authenticate(HttpRequestMessage request);

        HttpResponseMessage ClearAuthentication(HttpResponseMessage response);
    }
}
