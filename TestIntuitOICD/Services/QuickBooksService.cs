using Microsoft.AspNetCore.Identity;
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
    public class QuickBooksService : IQuickBooksService
    {
        public async Task<string> PostToQuickBooks(UserManager<ApplicationUser> UserManager, ClaimsPrincipal User, string endPoint, string body)
        {
            var result = "";
            var user = await UserManager.GetUserAsync(User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{UserManager.GetUserId(User)}'.");
            }

            if (User.Identity.IsAuthenticated)
            {
                var externalAccessToken = await UserManager.GetAuthenticationTokenAsync(user, "OpenIdConnect", "access_token");
                var company = user.QBCompany;
                var baseUrl = $"https://sandbox-quickbooks.api.intuit.com/v3/company/{company}/";
                // send the request
                result = await MakePostRequest(externalAccessToken, body, baseUrl + endPoint);
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
