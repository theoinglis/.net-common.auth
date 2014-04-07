using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Security.Claims;
using System.Security.Policy;
using System.Web.Http;
using Common.Auth.Hashing;
using Common.Auth.Models;
using Common.Auth.Services;
using Common.Auth.WebTokens;
using Common.Db.Repository;
using Common.Db.UnitOfWork;

namespace Common.Auth.Controllers
{
    public abstract class SessionsController<TCredential, TRegister> : ApiController 
        where TCredential : BaseCredential, new() where TRegister : BaseCredential
    {
        protected readonly IUnitOfWork UnitOfWork;
        private readonly IHashService _hashService;
        private readonly IWebTokenService _webTokenService;
        private readonly ISessionService _sessionService;
        private readonly IRepository<TCredential> _credentialRepository;

        protected SessionsController(
            IUnitOfWork unitOfWork,
            IHashService hashService,
            IWebTokenService webTokenService,
            ISessionService sessionService)
        {
            _credentialRepository = unitOfWork.CreateRepository<TCredential>();
            UnitOfWork = unitOfWork;
            _hashService = hashService;
            _webTokenService = webTokenService;
            _sessionService = sessionService;
        }

        protected abstract void CreateUser(TRegister registrationInfo, TCredential newCredentials);

        protected virtual List<Claim> GetClaimsList()
        {
            return new List<Claim>();
        } 

        protected ClaimsIdentity CreateIdentity(TCredential credentials)
        {
            var baseClaims = new List<Claim>
            {
                new Claim("Id", credentials.Id.ToString()),
            };
            baseClaims.AddRange(GetClaimsList());

            return new ClaimsIdentity(baseClaims);
        }

        [HttpGet]
        [AllowAnonymous]
        public virtual HttpResponseMessage IsAuthenticated()
        {
            var isAuthenticated = true;
            try
            {
                _webTokenService.Authenticate(Request);
            }
            catch (Exception)
            {
                isAuthenticated = false;
            }
            return Request.CreateResponse(HttpStatusCode.OK, isAuthenticated);
        }

        [HttpPost]
        [AllowAnonymous]
        public virtual HttpResponseMessage Register(TRegister registrationInfo)
        {
            var name = registrationInfo.Name;

            BaseCredential matchingCredentials = _credentialRepository
                .Get(c => c.Name == name).FirstOrDefault();

            if (matchingCredentials != null)
            {
                return Request.CreateErrorResponse(
                    HttpStatusCode.NotAcceptable,
                    new AuthenticationException("User Name '" + name + "' is already in use"));
            }

            var hashedPassword = _hashService.HashText(registrationInfo.Password);
            var newCredentials = new TCredential
            {
                Name = registrationInfo.Name,
                Password = hashedPassword
            };
            CreateUser(registrationInfo, newCredentials);

            var response = Request.CreateResponse(HttpStatusCode.OK);
            return _webTokenService.SetCookie(response, CreateIdentity(newCredentials), GetExpirationDate(newCredentials));
        }

        [HttpPost]
        [AllowAnonymous]
        public virtual HttpResponseMessage Login(TCredential credentials)
        {
            var name = credentials.Name;
            var password = _hashService.HashText(credentials.Password);

            var matchingCredentials = _credentialRepository
                .Get(c => c.Name == name).SingleOrDefault();

            if (matchingCredentials == null)
            {
                return Request.CreateErrorResponse(
                    HttpStatusCode.Unauthorized,
                    new AuthenticationException("No credentials are found with the name '" +
                                                credentials.Name +
                                                "'"));
            }
            else if (matchingCredentials.Password != password)
            {
                return Request.CreateErrorResponse(
                    HttpStatusCode.Unauthorized,
                    new AuthenticationException("The password provided is incorrect"));
            }

            var response = Request.CreateResponse(HttpStatusCode.OK);
            return _webTokenService.SetCookie(response, CreateIdentity(matchingCredentials), GetExpirationDate(matchingCredentials));
        }

        [HttpPost]
        public virtual HttpResponseMessage Logout()
        {
            var response = Request.CreateResponse();
            return _webTokenService.ClearAuthentication(response);
        }

        [HttpPost]
        public HttpResponseMessage ChangePassword(ChangePasswordInfo changePasswordInfo)
        {
            int id;
            if (!_sessionService.TryGetId(out id))
            {
                return Request.CreateErrorResponse(
                    HttpStatusCode.Unauthorized,
                    new AuthenticationException("Could not find your Id. You must be signed in to change your password."));
            }

            var matchingCredentials = _credentialRepository.GetById(id);
            if (matchingCredentials == null)
            {
                return Request.CreateErrorResponse(
                    HttpStatusCode.InternalServerError,
                    new AuthenticationException("Your credentials could not be found to change your password."));
            }

            var hashedOldPassword = _hashService.HashText(changePasswordInfo.OldPassword);
            if (!hashedOldPassword.Equals(matchingCredentials.Password, StringComparison.InvariantCulture))
            {
                return Request.CreateErrorResponse(
                    HttpStatusCode.Unauthorized,
                    new AuthenticationException("The password you provided is incorrect."));
            }

            matchingCredentials.Password = _hashService.HashText(changePasswordInfo.NewPassword);
            UnitOfWork.Save();

            return Request.CreateResponse(HttpStatusCode.OK);
        }

        protected virtual DateTime GetExpirationDate(TCredential credential)
        {
            return DateTime.MaxValue;
        }
    }

    public class ChangePasswordInfo
    {
        public string OldPassword { get; set; }
        public string NewPassword { get; set; }
    }
}
