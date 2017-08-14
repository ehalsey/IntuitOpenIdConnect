using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TestIntuitOICD.Models.QuickBooks
{
    public class Invoice
    {
        public CustomerRef CustomerRef { get; set; }

        [JsonProperty(PropertyName = "Line")]
        public List<Line> Lines { get; set; } = new List<QuickBooks.Line>();
    }

    public class CustomerRef
    {
        public string value { get; set; }
    }

    public class Line
    {
        public decimal Amount { get; set; }
        public string DetailType
        {
            get { return "SalesItemLineDetail"; }
        }

        public SalesItemLineDetail SalesItemLineDetail {get;set;}
    }

    public class SalesItemLineDetail
    {
        public ItemRef ItemRef { get; set; }

    }

    public class ItemRef
    {
        public string value { get; set; }
        public string name { get; set; }
    }
}
