﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace ManageTaskWeb.Models
{
    public class SubTask
    {
        public string TaskName { get; set; }
        public string Status { get; set; } = "Pending"; // Mặc định là Pending
        public string Description { get; set; }
        public string createBy { get; set; }
        public string ProjectID { get; set; }
        public int ParentTaskID { get; set; }

        public string MemberID { get; set; }
        public DateTime StartDate { get; set; }
        public DateTime EndDate { get; set; }
    }

}