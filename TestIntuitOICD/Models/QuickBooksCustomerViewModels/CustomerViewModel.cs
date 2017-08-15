using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace TestIntuitOICD.Models.QuickBooksViewModels
{
    public class CustomerViewModel
    {
        public string Title { get; set; }
        public string GivenName { get; set; }
        public string MiddleName { get; set; }
        public string FamilyName { get; set; }
        public string Suffix { get; set; }
        public string FullyQualifiedName { get; set; }
        public string CompanyName { get; set; }
        public string DisplayName { get; set; }
        public string PrimaryPhone { get; set; }
        public string PrimaryEmailAddr { get; set; }
        public string Line1 { get; set; }
        public string City { get; set; }
        public string Country { get; set; }
        public string CountrySubDivisionCode { get; set; }
        public string PostalCode { get; set; }
        public string Notes { get; set; }
        public string StatusMessage { get; set; }
    }

}
