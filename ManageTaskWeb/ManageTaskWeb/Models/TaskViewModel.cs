using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace ManageTaskWeb.Models
{
    public class TaskViewModel
    {
        public int TaskID { get; set; }
        public int? ParentTaskID { get; set; }
        public string TaskName { get; set; }
        public string ProjectID { get; set; }
        public string Description { get; set; }
        public DateTime? StartDate { get; set; } // Nullable DateTime
        public DateTime? EndDate { get; set; }   // Nullable DateTime
        public int? Priority { get; set; }       // Nullable int
        public string Status { get; set; }
        public List<TaskViewModel> ListTasks { get; set; }
        public List<MemberViewModel> AssignedMembers { get; set; }
       
        public MemberViewModel Creator { get; set; }            // Người tạo
    }
     
}