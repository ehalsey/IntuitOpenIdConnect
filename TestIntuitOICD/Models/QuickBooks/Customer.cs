using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TestIntuitOICD.Models.QuickBooks
{
    public class BillAddr
    {
        public string Line1 { get; set; }
        public string City { get; set; }
        public string Country { get; set; }
        public string CountrySubDivisionCode { get; set; }
        public string PostalCode { get; set; }
    }

    public class PrimaryPhone
    {
        public string FreeFormNumber { get; set; }
    }

    public class PrimaryEmailAddr
    {
        public string Address { get; set; }
    }

    public class Customer
    {
        public BillAddr BillAddr { get; set; }
        public string Notes { get; set; }
        public string Title { get; set; }
        public string GivenName { get; set; }
        public string MiddleName { get; set; }
        public string FamilyName { get; set; }
        public string Suffix { get; set; }
        public string FullyQualifiedName { get; set; }
        public string CompanyName { get; set; }
        public string DisplayName { get; set; }
        public PrimaryPhone PrimaryPhone { get; set; }
        public PrimaryEmailAddr PrimaryEmailAddr { get; set; }
    }
}
