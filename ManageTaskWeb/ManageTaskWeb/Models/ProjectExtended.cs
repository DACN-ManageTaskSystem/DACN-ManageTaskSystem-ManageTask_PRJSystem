using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace ManageTaskWeb.Models
{
    public class ProjectExtended : Project
    {
        public int MemberCount { get; set; }

        public List<MemberDTO> Members { get; set; }
    }
}