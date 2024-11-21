using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace ManageTaskWeb.Models
{
    public class Members
    {
        public string MemberID { get; set; }
        public string FullName { get; set; }
        public string Email { get; set; }
        public string Phone { get; set; }
        public string Role { get; set; }
        public DateTime? HireDate { get; set; }
        public string Status { get; set; }
        public string Password { get; set; }
        public string ImageMember { get; set; }
        public DateTime? deleteTime { get; set; }
        public int MemberCount { get; set; }
    }
}