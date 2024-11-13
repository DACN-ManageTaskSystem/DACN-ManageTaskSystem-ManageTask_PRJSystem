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
        QLCVDataContext data = new QLCVDataContext();

        //DangNhap-GET
        public ActionResult DangNhap()
        {
            return View();
        }

        //DangNhap-POST
        [HttpPost]
        public ActionResult DangNhap(string username, string password)
        {
            // Kiểm tra xem tên đăng nhập và mật khẩu có hợp lệ không
            var member = data.Members.FirstOrDefault(m => m.MemberID == username && m.Password == password && m.deleteTime == null);

            if (member != null)
            {
                member.Status = "Active";
                data.SubmitChanges();

                // Nếu đăng nhập thành công, lưu thông tin vào session
                Session["MemberID"] = member.MemberID;
                Session["FullName"] = member.FullName;
                Session["Role"] = member.Role;
                Session["Email"] = member.Email;
                Session["Phone"] = member.Phone;
                Session["ImageMember"] = member.ImageMember;

                // Chuyển hướng về trang chủ sau khi đăng nhập thành công
                return RedirectToAction("TrangChu");
            }
            else
            {
                // Nếu đăng nhập không thành công, hiển thị thông báo lỗi
                ViewBag.ErrorMessage = "*Tên đăng nhập hoặc mật khẩu không đúng.";
                return View();
            }
        }
        //DangXuat
        public ActionResult Logout()
        {
            // Lấy MemberID từ session để cập nhật trạng thái thành Offline
            var memberId = Session["MemberID"]?.ToString();
            if (memberId != null)
            {
                var member = data.Members.FirstOrDefault(m => m.MemberID == memberId);
                if (member != null)
                {
                    member.Status = "Offline";
                    data.SubmitChanges();
                }
            }

            // Xóa session
            Session.Clear();

            // Chuyển hướng về trang đăng nhập
            return RedirectToAction("DangNhap");
        }


        //TrangChu
        public ActionResult TrangChu()
        {
            return View();
        }

        //Danh sach project
        public ActionResult DSProject()
        {
            var role = Session["Role"]?.ToString();
            List<ProjectExtended> projects;

            if (role == "Manager" || role == "Admin")
            {
                projects = data.Projects
                               .Select(p => new ProjectExtended
                               {
                                   ProjectID = p.ProjectID,
                                   ProjectName = p.ProjectName,
                                   StartDate = p.StartDate,
                                   EndDate = p.EndDate,
                                   Status = p.Status,
                                   MemberCount = data.Assignments
                                                     .Where(a => a.ProjectID == p.ProjectID)
                                                     .Select(a => a.AssignedTo)
                                                     .Distinct()
                                                     .Count()
                               }).ToList();
            }
            else
            {
                var memberId = Session["MemberID"]?.ToString();
                projects = data.Assignments
                               .Where(a => a.AssignedTo == memberId)
                               .Select(a => a.Project)
                               .Distinct()
                               .Select(p => new ProjectExtended
                               {
                                   ProjectID = p.ProjectID,
                                   ProjectName = p.ProjectName,
                                   StartDate = p.StartDate,
                                   EndDate = p.EndDate,
                                   Status = p.Status,
                                   MemberCount = data.Assignments
                                                     .Where(a => a.ProjectID == p.ProjectID)
                                                     .Select(a => a.AssignedTo)
                                                     .Distinct()
                                                     .Count()
                               }).ToList();
            }

            return View(projects);
        }


        //Danh sach Member trong Project
        public ActionResult MembersOfProject(string projectId)
        {
            var members = data.Assignments
                             .Where(a => a.ProjectID == projectId)
                             .Select(a => a.Member)
                             .GroupBy(m => m.MemberID) // Nhóm theo MemberID để loại bỏ trùng lặp
                             .Select(g => g.First()) // Lấy bản ghi đầu tiên trong mỗi nhóm
                             .ToList();

            return View(members);
        }


        //Thong tin ca nhan
        public ActionResult TTCaNhan()
        {
            return View();            
        }

        //Danh sach task
        public ActionResult DSTask(string projectId)
        {
            var role = Session["Role"]?.ToString();
            var memberId = Session["MemberID"]?.ToString();

            // Kiểm tra nếu là Manager hoặc Admin, lấy tất cả task
            if (role == "Manager" || role == "Admin")
            {
                // Nếu là Manager hoặc Admin, lấy tất cả task của dự án
                var tasks = data.Tasks.Where(t => t.ProjectID == projectId).ToList();
                return View(tasks);
            }
            else
            {
                // Nếu là các role khác, chỉ lấy task mà người dùng tham gia
                var tasks = data.Tasks
                                .Where(t => t.ProjectID == projectId && t.AssignedTo == memberId)
                                .ToList();
                return View(tasks);
            }

        }

        //Chat
        public ActionResult GroupChat(string projectId, int page = 1)
        {
            int pageSize = 6;

            // Lấy danh sách các đoạn chat của dự án dựa trên projectId và phân trang
            var interactions = data.Interactions
                                  .Where(i => i.ProjectID == projectId)
                                  .OrderByDescending(i => i.InteractionDate)
                                  .Skip((page - 1) * pageSize)
                                  .Take(pageSize)
                                  .ToList();

            var project = data.Projects.FirstOrDefault(p => p.ProjectID == projectId);
            if (project == null)
            {
                return HttpNotFound("Project not found.");
            }
            // Đếm tổng số đoạn chat để tính tổng số trang
            int totalChatCount = data.Interactions.Count(i => i.ProjectID == projectId);
            int totalPages = (int)Math.Ceiling((double)totalChatCount / pageSize);

            // Lấy danh sách thành viên của project
            var members = data.Assignments
                 .Where(a => a.ProjectID == projectId)
                 .Select(a => a.Member)
                 .Distinct()
                 .Select(m => new MemberViewModel
                 {
                     FullName = m.FullName,
                     Status = m.Status,
                     Role = m.Role,
                     ImageMember = m.ImageMember
                 })
                 .ToList();

            ViewBag.Members = members;


            // Truyền các giá trị cần thiết cho view
            ViewBag.ProjectID = projectId;
            ViewBag.CurrentPage = page;
            ViewBag.TotalPages = totalPages;

            var viewModel = new GroupChatViewModel
            {
                Interactions = interactions,
                Members = members,
                Project = project
            };
            return View(viewModel);
        }
    }
}
