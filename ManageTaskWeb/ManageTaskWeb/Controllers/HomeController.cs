using ManageTaskWeb.Models;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.IO;
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

            // Kiểm tra nếu người dùng là Manager hoặc Admin
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
                                   Priority = p.Priority,
                                   ImageProject = p.ImageProject,
                                   deleteTime = p.deleteTime,
                                   MemberCount = data.Assignments
                                                      .Where(a => a.ProjectID == p.ProjectID)
                                                      .Select(a => a.AssignedTo)
                                                      .Distinct()
                                                      .Count(),
                                   
                               }).ToList();
            }
            else
            {
                var memberId = Session["MemberID"]?.ToString();
                projects = data.Assignments
                               .Where(a => a.AssignedTo == memberId)
                               .Select(a => a.Project)
                               .Distinct()
                               .Where(p => p.deleteTime == null)  
                               .Select(p => new ProjectExtended
                               {
                                   ProjectID = p.ProjectID,
                                   ProjectName = p.ProjectName,
                                   StartDate = p.StartDate,
                                   EndDate = p.EndDate,
                                   Status = p.Status,
                                   Priority = p.Priority,
                                   ImageProject = p.ImageProject,
                                   MemberCount = data.Assignments
                                                      .Where(a => a.ProjectID == p.ProjectID)
                                                      .Select(a => a.AssignedTo)
                                                      .Distinct()
                                                      .Count(),
                               }).ToList();
            }

            // Kiểm tra nếu projects vẫn là null hoặc rỗng, gán giá trị mặc định là danh sách rỗng
            if (projects == null)
            {
                projects = new List<ProjectExtended>();
            }

            return View(projects);
        }

        public string GenerateUniqueProjectID()
        {
            string prefix = "PRJ";
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var random = new Random();
            var randomString = new string(Enumerable.Repeat(chars, 6)
                .Select(s => s[random.Next(s.Length)]).ToArray());
            return prefix + randomString;
        }
        public string GetUniqueProjectID()
        {
            string projectIDnew = string.Empty;
            bool isUnique = false;

            while (!isUnique)
            {
                projectIDnew = GenerateUniqueProjectID();
                isUnique = !data.Projects.Any(p => p.ProjectID == projectIDnew); 
            }

            return projectIDnew;
        }
        //Add Project
        [HttpPost]
        public ActionResult AddProject(string ProjectName, string Description, DateTime StartDate, DateTime EndDate, int Priority, string Status, string ImageProject, HttpPostedFileBase ImageFile)
        {
            try
            {
                // Lưu hình ảnh vào thư mục ~/Content/images/project-img nếu có file upload
                string imagePath = null;
                if (ImageFile != null && ImageFile.ContentLength > 0)
                {
                    // Lưu ảnh vào thư mục
                    string path = Server.MapPath("~/Content/images/project-img/");
                    Directory.CreateDirectory(path); // Tạo thư mục nếu chưa có
                    imagePath = Path.Combine(path, ImageProject);
                    ImageFile.SaveAs(imagePath);
                }

                // Tạo một đối tượng Project mới và lưu thông tin
                var project = new Project
                {
                    ProjectID = GetUniqueProjectID(), // Tạo ID duy nhất
                    ProjectName = ProjectName,
                    Description = Description,
                    StartDate = StartDate,
                    EndDate = EndDate,
                    Priority = Priority, // Lưu giá trị Priority (1: Highest, 5: Lowest)
                    Status = Status,
                    ImageProject = ImageProject, // Lưu tên file ảnh
                    deleteTime = null
                };

                // Thêm project vào database
                data.Projects.InsertOnSubmit(project);
                data.SubmitChanges();

                // Redirect with success message
                return RedirectToAction("DSProject", new { notificationMessage = "Thêm Project mới thành công!", notificationType = "success" });
            }
            catch (Exception)
            {
                // Redirect with error message
                return RedirectToAction("DSProject", new { notificationMessage = "Đã xảy ra lỗi khi thêm dự án!", notificationType = "error" });
            }
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

        public ActionResult DetailTask()
        {
            return View();
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
        public ActionResult DSMember()
        {
            return View();
        }
    }
}
