using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace ManageTaskWeb.Models
{
    public class GroupChatViewModel
    {
        public List<ManageTaskWeb.Models.Interaction> Interactions { get; set; }
        public List<ManageTaskWeb.Models.MemberViewModel> Members { get; set; }
        public ManageTaskWeb.Models.Project Project { get; set; }

    }
}