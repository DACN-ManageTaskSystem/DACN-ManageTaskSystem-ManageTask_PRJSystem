using ManageTaskWeb.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace ManageTaskWeb.Controllers
{
    public class HomeController : Controller
    {
        //
        // GET: /Home/
        QLCVDataContext data = new QLCVDataContext();
        public ActionResult DangNhap()
        {
            return View();
        }

        public ActionResult TrangChu()
        {
            return View();
        }
        public ActionResult DSProject()
        {
             // Lấy danh sách dự án từ cơ sở dữ liệu
            //var projects = data.Projects.ToList();

            // Truyền dữ liệu dự án sang view
            return View();
        }

        //public ActionResult MembersOfProject(int projectId)
        //{
        //    // Lấy danh sách thành viên theo projectId
        //    var members = data.Members.Where(m => m.ProjectId == projectId).ToList();

        //    // Truyền dữ liệu thành viên qua view
        //    return View(members);
        //}

        public ActionResult DSMember()
        {
            return View();
        }

        public ActionResult DSTask()
        {
            return View();
        }

        public ActionResult GroupChat()
        {
            return View();
        }
    }
}
