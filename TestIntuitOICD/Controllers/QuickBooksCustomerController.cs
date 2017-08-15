using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using TestIntuitOICD.Models.QuickBooksViewModels;
using TestIntuitOICD.Services;
using TestIntuitOICD.Models.QuickBooks;
using Newtonsoft.Json;

namespace TestIntuitOICD.Controllers
{
    public class QuickBooksCustomerController : Controller
    {
        private readonly IQuickBooksService _quickbookservice;

        public QuickBooksCustomerController(IQuickBooksService quickBooksService)
        {
            _quickbookservice = quickBooksService;
        }

        [TempData]
        public string StatusMessage { get; set; }

        // GET: QuickBooksInvoice
        public async Task<ActionResult> Index()
        {
            var model = new CustomerViewModel
            {
                Title="",
                GivenName="",
                MiddleName="",
                FamilyName="",
                Suffix="",
                FullyQualifiedName="",
                CompanyName="",
                DisplayName="",
                PrimaryPhone="",
                PrimaryEmailAddr="",
                Line1="",
                City="",
                Country="",
                CountrySubDivisionCode="",
                PostalCode="",
                Notes="",
                StatusMessage = StatusMessage
            };
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Index(CustomerViewModel model)
        {
            try
            {
                BillAddr billAddr = new BillAddr
                {
                    Line1 = model.Line1,
                    City = model.City,
                    Country = model.Country,
                    CountrySubDivisionCode = model.CountrySubDivisionCode,
                    PostalCode = model.PostalCode
                };
                PrimaryPhone priPhone = new PrimaryPhone
                {
                    FreeFormNumber = model.PrimaryPhone
                };
                PrimaryEmailAddr priEmail = new PrimaryEmailAddr
                {
                    Address = model.PrimaryEmailAddr
                };
                Customer customer = new Customer
                {
                    Title = model.Title,
                    GivenName = model.GivenName,
                    MiddleName = model.MiddleName,
                    FamilyName = model.FamilyName,
                    Suffix = model.Suffix,
                    FullyQualifiedName = model.FullyQualifiedName,
                    CompanyName = model.CompanyName,
                    DisplayName = model.DisplayName,
                    PrimaryPhone = priPhone,
                    PrimaryEmailAddr = priEmail,
                    BillAddr = billAddr,
                    Notes = ""
                };
                
                string json = JsonConvert.SerializeObject(customer,
                                            Newtonsoft.Json.Formatting.None,
                                            new JsonSerializerSettings
                                            {
                                                NullValueHandling = NullValueHandling.Ignore
                                            });
                System.IO.File.WriteAllText(@"e:\training\TestIntuitOICD\TestIntuitOICD\Data\CustomerSample-out.json", json);
                StatusMessage = await _quickbookservice.PostToQuickBooks("/customer", json);
                return RedirectToAction(nameof(Index));
            }
            catch (Exception ex)
            {
                model.StatusMessage = ex.Message;
                return View(model);
            }
        }

        // GET: QuickBooksCustomer/Details/5
        public ActionResult Details(int id)
        {
            return View();
        }

        // GET: QuickBooksCustomer/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: QuickBooksCustomer/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(IFormCollection collection)
        {
            try
            {
                // TODO: Add insert logic here

                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: QuickBooksCustomer/Edit/5
        public ActionResult Edit(int id)
        {
            return View();
        }

        // POST: QuickBooksCustomer/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(int id, IFormCollection collection)
        {
            try
            {
                // TODO: Add update logic here

                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: QuickBooksCustomer/Delete/5
        public ActionResult Delete(int id)
        {
            return View();
        }

        // POST: QuickBooksCustomer/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(int id, IFormCollection collection)
        {
            try
            {
                // TODO: Add delete logic here

                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }
    }
}