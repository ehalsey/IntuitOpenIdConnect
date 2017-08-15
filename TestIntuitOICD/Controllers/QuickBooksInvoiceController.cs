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
    public class QuickBooksInvoiceController : Controller
    {
        private readonly IQuickBooksService _quickbookservice;

        public QuickBooksInvoiceController(IQuickBooksService quickBooksService)
        {
            _quickbookservice = quickBooksService;
        }

        [TempData]
        public string StatusMessage { get; set; }

        // GET: QuickBooksInvoice
        public async Task<ActionResult> Index()
        {
            var model = new InvoiceViewModel
            {
                CustomerRef = "1",
                ItemRef = "1",
                ItemName = "Services",
                Amount = 420.00M,
                StatusMessage = StatusMessage
            };
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Index(InvoiceViewModel model)
        {
            try
            {
                Invoice inv = new Invoice() {
                    CustomerRef = new CustomerRef() { value = model.CustomerRef},
                    Lines = new List<Line>() { new Line() { Amount = model.Amount, SalesItemLineDetail = new SalesItemLineDetail() { ItemRef = new ItemRef() { name = model.ItemName, value = model.ItemRef } } } }
                };
                StatusMessage = await _quickbookservice.PostToQuickBooks("/invoice", JsonConvert.SerializeObject(inv));
                return RedirectToAction(nameof(Index));
            }
            catch (Exception ex)
            {
                model.StatusMessage = ex.Message;
                return View(model);
            }
        }

        // GET: QuickBooksInvoice/Details/5
        public ActionResult Details(int id)
        {
            return View();
        }

        // GET: QuickBooksInvoice/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: QuickBooksInvoice/Create
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

        // GET: QuickBooksInvoice/Edit/5
        public ActionResult Edit(int id)
        {
            return View();
        }

        // POST: QuickBooksInvoice/Edit/5
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

        // GET: QuickBooksInvoice/Delete/5
        public ActionResult Delete(int id)
        {
            return View();
        }

        // POST: QuickBooksInvoice/Delete/5
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