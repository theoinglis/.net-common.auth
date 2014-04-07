using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Common.Auth.Services
{
    public interface ISessionService
    {
        bool TryGetId(out int id);
    }

    public class SessionService : ISessionService
    {
        public bool TryGetId(out string id)
        {
            id = null;
            var principal = Thread.CurrentPrincipal;
            var identity = principal.Identity as ClaimsIdentity;
            if (identity == null) return false;
            var companyIdClaim = identity.Claims.SingleOrDefault(claim => claim.Type == "Id");
            if (companyIdClaim == null) return false;

            id = companyIdClaim.Value;
            return true;
        }

        public bool TryGetId(out int id)
        {
            id = -1;
            string companyIdString;
            return TryGetId(out companyIdString) && int.TryParse(companyIdString, out id);
        }
    }
}
