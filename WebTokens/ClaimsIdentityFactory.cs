using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Common.Auth.Models;

namespace Common.Auth.WebTokens
{
    public interface IClaimsIdentityFactory
    {
        ClaimsIdentity CreateIdentity<TCredentials>(TCredentials credentials) where TCredentials : BaseCredential;
    }

    public class ClaimsIdentityFactory : IClaimsIdentityFactory
    {
        public ClaimsIdentity CreateIdentity<TCredentials>(TCredentials credentials) where TCredentials : BaseCredential
        {
            var baseClaims = new List<Claim>
            {
                new Claim("Id", credentials.Id.ToString()),
            };
            baseClaims.AddRange(GetClaimsList());

            return new ClaimsIdentity(baseClaims);
        }

        protected virtual List<Claim> GetClaimsList()
        {
            return new List<Claim>();
        } 
    }
}
