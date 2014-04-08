using System;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Authentication;
using System.Security.Claims;
using System.Security.Principal;
using System.ServiceModel.Security.Tokens;
using System.Threading;
using System.Web;

namespace Common.Auth.WebTokens
{
    public class JwtService : BaseTokenService
    {
        protected override string Scheme { get { return "JWT"; } }

        private readonly JwtSecurityTokenHandler _tokenHandler = new JwtSecurityTokenHandler();
        private readonly TokenValidationParameters _validationParameters;
        private readonly string _name;
        private readonly string _address;

        public JwtService(string name, string address, string keyString)
            : base(keyString)
        {
            _name = name;
            _address = address;
            _validationParameters = new TokenValidationParameters()
            {
                ValidIssuer = _name,
                AllowedAudience = _address,
                SigningToken = new BinarySecretSecurityToken(Key),
            };
        }

        public override string CreateToken(ClaimsIdentity identity, DateTime expiration)
        {
            var now = DateTime.UtcNow;
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                TokenIssuerName = _name,
                AppliesToAddress = _address,
                Lifetime = new Lifetime(now, null),
                SigningCredentials = new SigningCredentials(
                    new InMemorySymmetricSecurityKey(Key),
                    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
                    "http://www.w3.org/2001/04/xmlenc#sha256"),


            };
            var token = _tokenHandler.CreateToken(tokenDescriptor);
            return Scheme+" "+ _tokenHandler.WriteToken(token);
        }

        public override ClaimsIdentity ValidateToken(AuthenticationHeaderValue header)
        {
            if (header.Scheme != Scheme)
            {
                throw new AuthenticationException(
                    string.Format("Token is of the scheme {0} when it should be JWT", header.Scheme));
            }

            if (!_tokenHandler.CanReadToken(header.Parameter))
            {
                throw new AuthenticationException("Could not read the supplied token");
            }

            var token = _tokenHandler.ReadToken(header.Parameter);
            if (token.ValidFrom > DateTime.UtcNow) throw new AuthenticationException("Token is not valid yet");
            if (DateTime.UtcNow > token.ValidTo) throw new AuthenticationException("Token has expired");

            var identityList = _tokenHandler.ValidateToken(header.Parameter, _validationParameters);
            return identityList.Identities.First();
        }
    }
}
