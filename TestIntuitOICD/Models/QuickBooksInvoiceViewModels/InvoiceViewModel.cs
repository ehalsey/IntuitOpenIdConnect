using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace TestIntuitOICD.Models.QuickBooksViewModels
{
    public class InvoiceViewModel
    {
        //string jsonString = "{\"Line\": [{\"Amount\": 420.00,\"DetailType\": \"SalesItemLineDetail\",\"SalesItemLineDetail\": {\"ItemRef\": {\"value\": \"1\",\"name\": \"Services\"}}}],\"CustomerRef\": {\"value\": \"1\"}}";
        [Display(Name = "Customer ID")]
        [Required]
        public string CustomerRef { get; set; }

        [Display(Name = "Item ID")]
        [Required]
        public string ItemRef { get; set; }

        [Required]
        public decimal Amount { get; set; }

        [Display(Name = "Item Name")]
        [Required]
        public string ItemName { get; set; }

        public string StatusMessage { get; set; }

    }
}
