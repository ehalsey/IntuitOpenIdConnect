using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;
using TestIntuitOICD.Models;

namespace TestIntuitOICD.Services
{
    public class LoggingEvents
    {
        public const int HttpPost = 1000;
    }

    public class QuickBooksService : IQuickBooksService
    {
        private readonly IConfiguration _configuration;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger _logger;
        private readonly TelemetryClient _telemetry;

        public QuickBooksService(IConfiguration Configuration, IHttpContextAccessor HttpContextAccessor, UserManager<ApplicationUser> UserManager, ILogger<QuickBooksService> Logger)
        {
            _configuration = Configuration;
            _httpContextAccessor = HttpContextAccessor;
            _userManager = UserManager;
            _logger = Logger;
            _telemetry = new TelemetryClient();
        }

        public async Task<string> PostToQuickBooks(string endPoint, string body)
        {
            ClaimsPrincipal User = _httpContextAccessor.HttpContext.User;
            var result = "";
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            if (User.Identity.IsAuthenticated)
            {
                var externalAccessToken = await _userManager.GetAuthenticationTokenAsync(user, "OpenIdConnect", "access_token");
                var company = user.QBCompany;
                var baseUrl = _configuration["QuickBooksAPIEndpoint"].Replace("{company}", user.QBCompany);
                // send the request
                _logger.LogInformation(LoggingEvents.HttpPost,"Posting to QBO:\r\n{body}",body);
                // Establish an operation context and associated telemetry item:
                using (var operation = _telemetry.StartOperation<RequestTelemetry>("QuickBooks Post"))
                {
                    result = await MakePostRequest(externalAccessToken, body, baseUrl + endPoint);
                    _telemetry.StopOperation(operation);

                } // When operation is disposed, telemetry item is sent.
            }
            return result;
        }

        private async Task<string> MakePostRequest(string externalAccessToken, string jsonString, string baseUrl)
        {
            HttpWebRequest qboApiRequest = (HttpWebRequest)WebRequest.Create(baseUrl);
            qboApiRequest.Method = "POST";
            qboApiRequest.Headers["Authorization"] = string.Format("Bearer {0}", externalAccessToken);
            qboApiRequest.ContentType = "application/json;charset=UTF-8";
            var stream = await qboApiRequest.GetRequestStreamAsync();

            using (var streamWriter = new StreamWriter(stream))
            {
                streamWriter.Write(jsonString);
                streamWriter.Flush();
            }

            try
            {
                // get the response
                var response = await qboApiRequest.GetResponseAsync();
                HttpWebResponse qboApiResponse = (HttpWebResponse)response;
                //read qbo api response
                using (var qboApiReader = new StreamReader(qboApiResponse.GetResponseStream()))
                {
                    var result = qboApiReader.ReadToEnd();
                    return result;
                }
            }
            catch (WebException ex)
            {
                if (ex.Message.Contains("401"))
                {
                    //need to get new token from refresh token
                    System.Diagnostics.Debug.WriteLine(ex.Message);
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine(ex.Message);
                    //return "";
                }
                return ex.Message;
            }
        }

    }
}
