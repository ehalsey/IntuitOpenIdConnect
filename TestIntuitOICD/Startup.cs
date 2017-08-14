using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using TestIntuitOICD.Data;
using TestIntuitOICD.Models;
using TestIntuitOICD.Services;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using Newtonsoft.Json.Linq;
using Microsoft.AspNetCore.Http.Extensions;

namespace TestIntuitOICD
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));

            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            // Add application services.
            services.AddTransient<IEmailSender, EmailSender>();
            services.AddTransient<IQuickBooksService, QuickBooksService>();

            services.AddAuthentication(sharedOptions =>
            {
            })
                .AddCookie(o=> {
                    o.Events = new CookieAuthenticationEvents()
                    {
                        OnValidatePrincipal = context =>
                        {
                            if (context.Properties.Items.ContainsKey(".Token.expires_at"))
                            {
                                var expire = DateTime.Parse(context.Properties.Items[".Token.expires_at"]);
                                if (expire > DateTime.Now) //TODO:change to check expires in next 5 mintues.
                                    {
                                        System.Diagnostics.Debug.WriteLine($"Access token has expired, user: {context.HttpContext.User.Identity.Name}");

                                        //TODO: send refresh token to ASOS. Update tokens in context.Properties.Items
                                        //context.Properties.Items["Token.access_token"] = newToken;
                                        context.ShouldRenew = true;
                                }
                            }
                            return Task.FromResult(0);
                        }
                    };
                })
                .AddOpenIdConnect(o =>
                {
                    o.ClientId = Configuration["intuit:oidc:clientid"]; 
                    o.ClientSecret = Configuration["intuit:oidc:clientsecret"];  
                    o.ResponseType = OpenIdConnectResponseType.Code;
                    o.MetadataAddress = "https://developer.api.intuit.com/.well-known/openid_sandbox_configuration/";
                    o.ProtocolValidator.RequireNonce = false;
                    o.SaveTokens = true;
                    o.GetClaimsFromUserInfoEndpoint = true;
                    o.ClaimActions.MapUniqueJsonKey("given_name", "givenName");
                    o.ClaimActions.MapUniqueJsonKey("family_name", "familyName");
                    o.ClaimActions.MapUniqueJsonKey(ClaimTypes.Email, "email"); //should work but because the middleware checks for claims w/ the same value and the claim for "email" already exists it doesn't get mapped.
                    o.Scope.Add("phone");
                    o.Scope.Add("email");
                    o.Scope.Add("address");
                    o.Scope.Add("com.intuit.quickbooks.accounting");
                    o.Events = new OpenIdConnectEvents()
                    {
                        OnAuthenticationFailed = c =>
                        {
                            c.HandleResponse();

                            c.Response.StatusCode = 500;
                            c.Response.ContentType = "text/plain";
                            return c.Response.WriteAsync(c.Exception.ToString());
                        },
                        OnUserInformationReceived = context =>
                        {
                            var identity = (ClaimsIdentity)context.Principal.Identity;
                            string fullName = GetFullName(context);
                            if (fullName.Length > 0)
                            {
                                identity.AddClaim(new Claim("name", fullName, "Intuit"));
                            }
                            string email = GetEmail(context);
                            if (email.Length > 0)
                            {
                                identity.AddClaim(new Claim(ClaimTypes.Email, email,null,"Intuit"));
                            }
                            var token = context.Properties.GetTokenValue("access_token");
                            identity.AddClaim(new Claim("access_token", token));
                            token = context.Properties.GetTokenValue("refresh_token");
                            identity.AddClaim(new Claim("refresh_token", token));

                            context.Principal.AddIdentity(identity);
                            return Task.CompletedTask;
                        },
                        OnAuthorizationCodeReceived = async context =>
                        {
                            //var request = context.HttpContext.Request;
                            //var currentUri = UriHelper.BuildAbsolute(request.Scheme, request.Host, request.PathBase, request.Path);
                            //var credential = new ClientCredential(ClientId, ClientSecret);
                            //var authContext = new AuthenticationContext(Authority, AuthPropertiesTokenCache.ForCodeRedemption(context.Properties));

                            //var result = await authContext.AcquireTokenByAuthorizationCodeAsync(
                            //    context.ProtocolMessage.Code, new Uri(currentUri), credential, Resource);

                            //context.HandleCodeRedemption(result.AccessToken, result.IdToken);
                        }

                    };
                });

            services.AddSingleton<IConfiguration>(provider => Configuration);

            services.AddMvc();
        }
        private static string GetEmail(UserInformationReceivedContext context)
        {
            string email = "";

            JToken emailToken;
            if (context.User.TryGetValue("email", out emailToken))
            {
                email = emailToken.Value<string>();
            }
            return email;
        }

        private static string GetFullName(UserInformationReceivedContext context)
        {
            string fullName = "";

            JToken givenName, familyName;
            if (context.User.TryGetValue("givenName", out givenName))
            {
                fullName = givenName.Value<string>() + " ";
            }
            if (context.User.TryGetValue("familyName", out familyName))
            {
                fullName += familyName.Value<string>();
            }

            return fullName;
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseAuthentication();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
