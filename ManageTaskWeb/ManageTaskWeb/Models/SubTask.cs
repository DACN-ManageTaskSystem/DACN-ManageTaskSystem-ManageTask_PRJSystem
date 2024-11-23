using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace ManageTaskWeb.Models
{
    public class SubTask
    {
        public int TaskID { get; set; }
        public string TaskName { get; set; }
        public string Status { get; set; } = "Pending"; // Mặc định là Pending
        public string Description { get; set; }
        public string ProjectID { get; set; }
        public int ParentTaskID { get; set; }
    
    }

}