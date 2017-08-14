using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using TestIntuitOICD.Models;

namespace TestIntuitOICD.Services
{
    public interface IQuickBooksService
    {
        Task<string> PostToQuickBooks(UserManager<ApplicationUser> UserManager, ClaimsPrincipal User, string endPoint, string body);
    }
}
