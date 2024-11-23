using ManageTaskWeb.Models;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.IO;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Security.Cryptography;
using System.Text;
using System.Net;


namespace ManageTaskWeb.Controllers
{
    public class HomeController : Controller
    {
        QLCVDataContext data = new QLCVDataContext();
        //TrangChu
        public ActionResult TrangChu()
        {
            return View();
        }
        //DangNhap-GET
        public ActionResult DangNhap()
        {

            return View();
        }
        public static string EncryptPassword(string plainText, string key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32)); // Khóa 256-bit
                aes.IV = new byte[16]; // Vector khởi tạo mặc định (16 byte)

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                    byte[] encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

                    return Convert.ToBase64String(encryptedBytes);
                }
            }
        }
        public static string DecryptPassword(string encryptedText, string key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32)); // Khóa 256-bit
                aes.IV = new byte[16]; // Vector khởi tạo mặc định (16 byte)
                aes.Padding = PaddingMode.PKCS7; // Chế độ padding (nên đồng nhất khi mã hóa)

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    try
                    {
                        byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
                        byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
                        return Encoding.UTF8.GetString(decryptedBytes);
                    }
                    catch (CryptographicException ex)
                    {
                        throw new Exception("Giải mã thất bại: Dữ liệu không hợp lệ hoặc khóa sai.", ex);
                    }
                }
            }
        }
        //DangNhap-POST
        [HttpPost]
        public ActionResult DangNhap(string username, string password)
        {

            // Tìm kiếm thành viên
            var member = data.Members.FirstOrDefault(m => m.MemberID == username && m.deleteTime == null);

            if (member == null)
            {
                // Không tìm thấy người dùng
                ViewBag.ErrorMessage = "*Tên đăng nhập hoặc mật khẩu không đúng.";
                return View();
            }

            // Giải mã mật khẩu
            string decryptedPassword = DecryptPassword(member.Password, "mysecretkey");
            if (decryptedPassword != password)
            {
                // Sai mật khẩu
                ViewBag.ErrorMessage = "*Tên đăng nhập hoặc mật khẩu không đúng.";
                return View();
            }

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

        //Load Thong bao 
        public JsonResult GetNotifications()
        {
            if (Session["MemberID"] != null)
            {
                string memberId = Session["MemberID"].ToString();

                // Fetch the notifications from the database
                var notifications = data.Notifications
                .Where(n => n.MemberID == memberId)
                .OrderByDescending(n => n.NotificationDate)
                .Select(n => new
                {
                    n.NotificationID,
                    n.Content,
                    NotificationDate = n.NotificationDate.ToString(), // Format date to a more readable format
                    IsRead = n.IsRead.HasValue ? n.IsRead.Value : false, // Ensure IsRead is not null, default to false if null
                    n.NotificationType,
                    ShowAcceptReject = n.NotificationType == "JoinRequest" // Flag to show buttons
                })
                .ToList();


                // If no notifications, return an empty list
                if (!notifications.Any())
                {
                    return Json(new { success = true, message = "No notifications" }, JsonRequestBehavior.AllowGet);
                }

                return Json(new { success = true, notifications }, JsonRequestBehavior.AllowGet);
            }

            // If MemberID is null, return an error response
            return Json(new { success = false, message = "User not logged in" }, JsonRequestBehavior.AllowGet);
        }
        //Accept trong thong bao
        [HttpPost]
        public JsonResult AcceptJoinRequest(string notificationId)
        {
            try
            {
                if (Session["MemberID"] == null)
                {
                    return Json(new { success = false, message = "User not logged in" });
                }

                string memberId = Session["MemberID"].ToString();

                // Lấy thông báo từ bảng Notifications theo NotificationID
                var notification = data.Notifications.FirstOrDefault(n => n.NotificationID.ToString() == notificationId);
                if (notification == null)
                {
                    return Json(new { success = false, message = "Notification not found" });
                }

                // Phân tích extraData để lấy RequestMemberID và ProjectID
                var extraData = JsonConvert.DeserializeObject<Dictionary<string, string>>(notification.ExtraData);
                string requestMemberId = extraData["RequestMemberID"];
                string projectId = extraData["ProjectID"];

                // Cập nhật trạng thái thành viên trong bảng ProjectMembers
                var projectMember = data.ProjectMembers
                    .FirstOrDefault(pm => pm.MemberID == requestMemberId && pm.ProjectID == projectId && pm.Status == "Pending");
                if (projectMember != null)
                {
                    projectMember.Status = "Accepted";
                    data.SubmitChanges();
                }
                else
                {
                    return Json(new { success = false, message = "Request not found or already accepted" });
                }

                // Xóa tất cả các thông báo có cùng extraData
                var notificationsToDelete = data.Notifications
                    .Where(n => n.ExtraData == notification.ExtraData)
                    .ToList();

                foreach (var notif in notificationsToDelete)
                {
                    data.Notifications.DeleteOnSubmit(notif);
                }
                data.SubmitChanges();

                // Lấy thông tin chi tiết về dự án và thành viên vừa được chấp nhận
                var project = data.Projects.FirstOrDefault(p => p.ProjectID == projectId);
                var newMember = data.Members.FirstOrDefault(m => m.MemberID == requestMemberId);
                if (project == null || newMember == null)
                {
                    return Json(new { success = false, message = "Error: Project or member not found." });
                }

                string projectName = project.ProjectName;
                string fullName = newMember.FullName;

                // Lấy danh sách tất cả thành viên trong dự án (trạng thái Accepted)
                var projectMembers = data.ProjectMembers
                    .Where(pm => pm.ProjectID == projectId && pm.Status == "Accepted")
                    .Select(pm => pm.MemberID)
                    .ToList();

                // Tạo thông báo cho requestMemberId
                data.Notifications.InsertOnSubmit(new Notification
                {
                    MemberID = requestMemberId,
                    Content = $"Bạn đã được thêm vào project '{projectName}'.",
                    NotificationDate = DateTime.Now,
                    IsRead = false,
                    NotificationType = "JoinAccepted"
                });

                // Tạo thông báo cho tất cả thành viên còn lại trong dự án
                foreach (var member in projectMembers)
                {
                    if (member != requestMemberId) // Loại bỏ requestMemberId để không gửi trùng lặp
                    {
                        data.Notifications.InsertOnSubmit(new Notification
                        {
                            MemberID = member,
                            Content = $"Project '{projectName}' has a new member: {fullName}.",
                            NotificationDate = DateTime.Now,
                            IsRead = false,
                            NotificationType = "JoinAccepted"
                        });
                    }
                }
                // Lấy danh sách Admin và Manager từ bảng Members
                var adminAndManagers = data.Members
                    .Where(m => m.Role == "Admin" || m.Role == "Manager")
                    .Select(m => m.MemberID)
                    .ToList();

                // Tạo thông báo riêng cho Admin và Manager
                foreach (var admin in adminAndManagers)
                {
                    data.Notifications.InsertOnSubmit(new Notification
                    {
                        MemberID = admin,
                        Content = $"A new member '{fullName}' has joined your project '{projectName}'.",
                        NotificationDate = DateTime.Now,
                        IsRead = false,
                        NotificationType = "JoinAccepted"
                    });
                }

                // Lưu thay đổi
                data.SubmitChanges();

                return Json(new { success = true, message = "Request accepted successfully, notifications sent." });
            }
            catch (Exception ex)
            {
                // Log lỗi chi tiết
                return Json(new { success = false, message = "Error processing your request: " + ex.Message });
            }
        }
        //Reject trong thong bao
        [HttpPost]
        public JsonResult RejectJoinRequest(int notificationId, string reason)
        {
            try
            {
                if (string.IsNullOrEmpty(reason))
                {
                    return Json(new { success = false, message = "Reason is required." });
                }

                // Tìm thông báo bị từ chối
                var notification = data.Notifications.FirstOrDefault(n => n.NotificationID == notificationId);
                if (notification == null)
                {
                    return Json(new { success = false, message = "Notification not found." });
                }

                // Phân tích ExtraData
                var extraData = JsonConvert.DeserializeObject<Dictionary<string, string>>(notification.ExtraData);
                string requestMemberId = extraData["RequestMemberID"];
                string projectId = extraData["ProjectID"];

                // Tìm và cập nhật trạng thái thành viên trong bảng ProjectMembers
                var projectMember = data.ProjectMembers
                    .FirstOrDefault(pm => pm.MemberID == requestMemberId && pm.ProjectID == projectId && pm.Status == "Pending");
                if (projectMember != null)
                {
                     data.ProjectMembers.DeleteOnSubmit(projectMember);
                }

                // Xóa tất cả thông báo có cùng ExtraData
                var notificationsToDelete = data.Notifications
                    .Where(n => n.ExtraData == notification.ExtraData)
                    .ToList();

                foreach (var notif in notificationsToDelete)
                {
                    data.Notifications.DeleteOnSubmit(notif);
                }

                // Tạo thông báo cho người bị từ chối
                data.Notifications.InsertOnSubmit(new Notification
                {
                    MemberID = requestMemberId,
                    Content = $"Your join request for project '{projectId}' was rejected due to: {reason}.",
                    NotificationDate = DateTime.Now,
                    IsRead = false,
                    NotificationType = "JoinRejected"
                });

                // Lưu thay đổi vào cơ sở dữ liệu
                data.SubmitChanges();

                return Json(new { success = true, message = "Request rejected successfully, notifications updated." });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = "Error: " + ex.Message });
            }
        }

        //Hien danh sach REquest trong moi project
        public ActionResult GetJoinRequests(string projectId)
        {
            // Lấy tất cả các thông báo với NotificationType là "JoinRequest"
            var notifications = data.Notifications
                .Where(n => n.NotificationType == "JoinRequest")
                .ToList(); // Tải tất cả thông báo vào bộ nhớ

            // Lọc các thông báo có chứa "ProjectID" trong ExtraData và so sánh với projectId
            var requestMemberData = notifications
                .Where(n =>
                {
                    try
                    {
                        // Giải mã ExtraData từ chuỗi JSON thành Dictionary
                        var extraData = JsonConvert.DeserializeObject<Dictionary<string, string>>(n.ExtraData);

                        // Kiểm tra xem ExtraData có chứa ProjectID và có giá trị khớp với projectId không
                        return extraData.ContainsKey("ProjectID") && extraData["ProjectID"] == projectId;
                    }
                    catch
                    {
                        // Bỏ qua thông báo có ExtraData không hợp lệ
                        return false;
                    }
                })
                .Select(n =>
                {
                    // Giải mã ExtraData một lần nữa để lấy thông tin RequestMemberID
                    var extraData = JsonConvert.DeserializeObject<Dictionary<string, string>>(n.ExtraData);
                    return new
                    {
                        NotificationID = n.NotificationID,  // Thêm NotificationID vào kết quả
                        RequestMemberID = extraData.ContainsKey("RequestMemberID") ? extraData["RequestMemberID"] : null
                    };
                })
                .ToList();  // Chỉ xử lý sau khi đã tải dữ liệu vào bộ nhớ

            // Lấy danh sách các MemberID từ dữ liệu đã truy vấn
            var requestMemberIds = requestMemberData.Select(r => r.RequestMemberID).ToList();

            // Truy vấn bảng Members để lấy thông tin chi tiết của thành viên
            var members = data.Members
                .Where(m => requestMemberIds.Contains(m.MemberID)) // Lọc thành viên theo MemberID đã lấy
                .ToList();

            // Kết hợp thông tin của members và requestMemberData (NotificationID)
            var result = members.Select(m => new
            {
                m.MemberID,
                m.FullName,
                m.Role,
                NotificationIDs = requestMemberData
                    .Where(r => r.RequestMemberID == m.MemberID)
                    .Select(r => r.NotificationID)
                    .ToList()
            }).ToList();

            // Trả về JSON danh sách các thành viên yêu cầu tham gia cùng với NotificationID
            return Json(result, JsonRequestBehavior.AllowGet);
        }










        //Accept Request trong View



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
        //PROJECT - START
        //Danh sach project
        public ActionResult DSProject(string statusFilter = "All")
        {
            var role = Session["Role"]?.ToString();
            List<ProjectExtended> projects;

            // Kiểm tra nếu người dùng là Manager hoặc Admin
            if (role == "Manager" || role == "Admin")
            {
                projects = data.Projects
                               .Where(p => statusFilter == "All" || p.Status == statusFilter)
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
                                   MemberCount = data.ProjectMembers
                                                      .Where(pm => pm.ProjectID == p.ProjectID && pm.Status == "Accepted")
                                                      .Select(pm => pm.MemberID)
                                                      .Distinct()
                                                      .Count(),
                               })
                               .ToList();

                // Fetch members for each project separately
                foreach (var project in projects)
                {
                    project.Members = data.ProjectMembers
                                           .Where(pm => pm.ProjectID == project.ProjectID && pm.Status == "Accepted")
                                           .Join(data.Members, pm => pm.MemberID, m => m.MemberID, (pm, m) => new MemberDTO
                                           {
                                               MemberID = m.MemberID,
                                               FullName = m.FullName,
                                               ImageMember = m.ImageMember
                                           })
                                           .ToList();
                }
            }
            else
            {
                var memberId = Session["MemberID"]?.ToString();
                projects = data.ProjectMembers
                               .Where(pm => pm.MemberID == memberId && pm.Status == "Accepted")
                               .Select(pm => pm.Project)
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
                                   MemberCount = data.ProjectMembers
                                                      .Where(pm => pm.ProjectID == p.ProjectID && pm.Status == "Accepted")
                                                      .Select(pm => pm.MemberID)
                                                      .Distinct()
                                                      .Count(),
                               })
                               .ToList();

                // Fetch members for each project separately
                foreach (var project in projects)
                {
                    project.Members = data.ProjectMembers
                                           .Where(pm => pm.ProjectID == project.ProjectID && pm.Status == "Accepted")
                                           .Join(data.Members, pm => pm.MemberID, m => m.MemberID, (pm, m) => new MemberDTO
                                           {
                                               MemberID = m.MemberID,
                                               FullName = m.FullName,
                                               ImageMember = m.ImageMember
                                           })
                                           .ToList();
                }
            }
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
        //Them Project
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
        //Sua Project
        [HttpPost]
        public ActionResult EditProject(string ProjectID, string ProjectName, string Description, DateTime StartDate, DateTime EndDate, int Priority, string Status, HttpPostedFileBase ImageFile)
        {
            try
            {
                var project = data.Projects.FirstOrDefault(p => p.ProjectID == ProjectID);
                if (project == null)
                {
                    return RedirectToAction("DSProject", new { notificationMessage = "Project not found!", notificationType = "error" });
                }

                // Update project details
                project.ProjectName = ProjectName;
                project.Description = Description;
                project.StartDate = StartDate;
                project.EndDate = EndDate;
                project.Priority = Priority;
                project.Status = Status;

                // Update image if a new file is uploaded
                if (ImageFile != null && ImageFile.ContentLength > 0)
                {
                    string path = Server.MapPath("~/Content/images/project-img/");
                    Directory.CreateDirectory(path); // Ensure directory exists
                    string imagePath = Path.Combine(path, ImageFile.FileName);
                    ImageFile.SaveAs(imagePath);
                    project.ImageProject = ImageFile.FileName;
                }

                data.SubmitChanges();

                return RedirectToAction("DSProject", new { notificationMessage = "Project updated successfully!", notificationType = "success" });
            }
            catch (Exception)
            {
                return RedirectToAction("DSProject", new { notificationMessage = "An error occurred while updating the project!", notificationType = "error" });
            }
        }
        //Xoa project 
        [HttpPost]
        public JsonResult DeleteProjects(List<string> projectIds)
        {
            try
            {
                if (projectIds == null || !projectIds.Any())
                {
                    return Json(new { success = false, message = "Không có dự án nào được chọn để xóa!" });
                }

                // Danh sách các project không thể xóa (có task)
                List<string> failedProjects = new List<string>();
                List<string> deletedProjects = new List<string>();

                foreach (var projectId in projectIds)
                {
                    var project = data.Projects.FirstOrDefault(p => p.ProjectID == projectId);
                    if (project == null) continue;

                    // Kiểm tra nếu project có task thì thêm vào danh sách failedProjects
                    bool hasTasks = data.Tasks.Any(t => t.ProjectID == projectId);
                    if (hasTasks)
                    {
                        failedProjects.Add(projectId);
                    }
                    else
                    {
                        // Xóa project nếu không có task
                        data.Projects.DeleteOnSubmit(project);
                        deletedProjects.Add(projectId);
                    }
                }

                // Lưu thay đổi vào database
                data.SubmitChanges();

                // Tạo thông báo kết quả
                if (deletedProjects.Any() && failedProjects.Any())
                {
                    string deleted = string.Join(", ", deletedProjects);
                    string failed = string.Join(", ", failedProjects);
                    return Json(new { success = true, message = $"Đã xóa các dự án: {deleted}. Không thể xóa các dự án: {failed} do có task." });
                }
                else if (deletedProjects.Any())
                {
                    string deleted = string.Join(", ", deletedProjects);
                    return Json(new { success = true, message = $"Đã xóa các dự án: {deleted}." });
                }
                else
                {
                    string failed = string.Join(", ", failedProjects);
                    return Json(new { success = false, message = $"Không thể xóa các dự án: {failed} do có task." });
                }
            }
            catch (Exception)
            {
                return Json(new { success = false, message = "Đã xảy ra lỗi khi xóa dự án!" });
            }
        }
        //Join Project by ProjectID
        [HttpPost]
        [ValidateAntiForgeryToken]
        public JsonResult JoinProject(string projectCode)
        {
            // Kiểm tra xem projectCode có tồn tại trong bảng Projects hay không
            var project = data.Projects.FirstOrDefault(p => p.ProjectID == projectCode && p.deleteTime == null);

            if (project == null)
            {
                return Json(new { success = false, error = "Project does not exist or has been deleted." });
            }

            // Lấy MemberID của người dùng hiện tại từ Session
            var memberID = Session["MemberID"]?.ToString();
            if (string.IsNullOrEmpty(memberID))
            {
                return Json(new { success = false, error = "You need to log in to join a project." });
            }

            // Lấy FullName của Member
            var member = data.Members.FirstOrDefault(m => m.MemberID == memberID);
            if (member == null)
            {
                return Json(new { success = false, error = "Member not found." });
            }

            // Kiểm tra xem Member đã là thành viên của dự án hay chưa
            var isMember = data.ProjectMembers.Any(pm => pm.ProjectID == projectCode && pm.MemberID == memberID && pm.Status == "Accepted");
            if (isMember)
            {
                return Json(new { success = false, error = "You are already a member of this project." });
            }

            // Kiểm tra xem Member đã gửi yêu cầu trước đó hay chưa
            var existingRequest = data.ProjectMembers.FirstOrDefault(pm => pm.ProjectID == projectCode && pm.MemberID == memberID);
            if (existingRequest != null)
            {
                return Json(new { success = false, error = "You have already submitted a join request for this project." });
            }

            // Thêm yêu cầu vào bảng ProjectMembers
            var newRequest = new ProjectMember
            {
                ProjectID = projectCode,
                MemberID = memberID,
                Status = "Pending",
                JoinDate = DateTime.Now
            };
            data.ProjectMembers.InsertOnSubmit(newRequest);
            data.SubmitChanges();

            // Tìm tất cả Admin/Manager trong bảng Members
            var adminOrManagers = data.Members
                .Where(m => m.Role == "Admin" || m.Role == "Manager")
                .Select(m => m.MemberID)
                .ToList();


            // Gửi thông báo cho Admin/Manager
            foreach (var adminID in adminOrManagers)
            {
                var notification = new Notification
                {
                    MemberID = adminID,
                    Content = $"{member.FullName} (ID: {memberID}) requested to join project {project.ProjectName} (ID: {projectCode}).",
                    NotificationType = "JoinRequest",
                    ExtraData = $"{{\"RequestMemberID\": \"{memberID}\", \"ProjectID\": \"{projectCode}\"}}",
                    NotificationDate = DateTime.Now,
                    IsRead = false
                };
                data.Notifications.InsertOnSubmit(notification);
            }
            data.SubmitChanges();

            return Json(new { success = true, message = "Your join request has been submitted successfully." });
        }
        //PROJECT - END

        //Danh sach Member trong Project
        public ActionResult MembersOfProject(string projectId)
        {
            var members = data.ProjectMembers
                             .Where(pm => pm.ProjectID == projectId && pm.Status == "Accepted") // Lọc theo Status

                             .Select(pm => pm.Member)
                             .Distinct()
                             .ToList();
            ViewBag.ProjectId = projectId;
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

            //    // Kiểm tra nếu là Manager hoặc Admin, lấy tất cả task
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
                               .Where(t => t.ProjectID == projectId && data.TaskAssignments
                                                                     .Any(ta => ta.TaskID == t.TaskID && ta.MemberID == memberId))
                               .ToList();
                return View(tasks);
            }

        }

        //Them Task
        [HttpPost]
        public ActionResult AddTask(string TaskName, string Description, DateTime? StartDate, DateTime? EndDate, int Priority, string Status, string ProjectID, int? ParentTaskID = null)
        {
            try
            {
                // Create a new Task object
                var task = new Task
                {
                    TaskName = TaskName,
                    Description = Description,
                    StartDate = StartDate,
                    EndDate = EndDate,
                    Priority = Priority,
                    Status = Status,
                    ProjectID = ProjectID,
                    ParentTaskID = ParentTaskID // Set ParentTaskID, can be null
                };

                // Insert the task into the database
                data.Tasks.InsertOnSubmit(task);
                data.SubmitChanges();

                // Redirect with success message
                return RedirectToAction("DSTask", new { projectId = ProjectID, notificationMessage = "Task added successfully!", notificationType = "success" });
            }
            catch (Exception)
            {
                // Redirect with error message
                return RedirectToAction("DSTask", new { projectId = ProjectID, notificationMessage = "An error occurred while adding the task!", notificationType = "error" });

            }
        }
        //Edit task 
        [HttpPost]
        public ActionResult EditTask(int TaskID, string TaskName, string Description, DateTime? StartDate, DateTime? EndDate, int Priority, string Status, int? ParentTaskID = null)
        {
            try
            {
                var task = data.Tasks.FirstOrDefault(t => t.TaskID == TaskID);
                if (task == null)
                {
                    return RedirectToAction("DSTask", new { notificationMessage = "Task not found!", notificationType = "error" });
                }

                // Update task details
                task.TaskName = TaskName;
                task.Description = Description;
                task.StartDate = StartDate;
                task.EndDate = EndDate;
                task.Priority = Priority;
                task.Status = Status;
                task.ParentTaskID = ParentTaskID; // Update ParentTaskID, can be null

                data.SubmitChanges();

                return RedirectToAction("DSTask", new { projectId = task.ProjectID, notificationMessage = "Task updated successfully!", notificationType = "success" });
            }
            catch (Exception)
            {
                return RedirectToAction("DSTask", new { notificationMessage = "An error occurred while updating the task!", notificationType = "error" });

            }
        }

        //Chi tiet task
        public ActionResult DetailTask(string taskId)
        {
            if (taskId == null)
                return HttpNotFound();  // Nếu không có taskId, trả về lỗi Not Found

            using (var context = new QLCVDataContext())
            {
                // Nếu taskId là kiểu string và cần ép kiểu sang int để tìm kiếm trong CSDL
                if (!int.TryParse(taskId, out int taskIdInt))
                {
                    return HttpNotFound(); // Nếu không thể chuyển đổi taskId thành int, trả về lỗi Not Found
                }

                var task = context.Tasks
                                  .Include(t => t.Project)
                                  .Include(t => t.TaskAssignments.Select(ta => ta.Member))
                                  .FirstOrDefault(t => t.TaskID == taskIdInt); // Sử dụng kiểu int cho truy vấn

                if (task == null)
                    return HttpNotFound();  // Nếu không tìm thấy task trong CSDL, trả về lỗi Not Found
                var creator = task.TaskAssignments
                        .Where(ta => ta.AssignedBy != null)
                        .Join(context.Members,
                              ta => ta.AssignedBy, // Liên kết theo MemberID (AssignedBy)
                              m => m.MemberID,      // Với MemberID trong bảng Members
                              (ta, m) => new MemberViewModel
                              {
                                  MemberID = ta.AssignedBy,
                                  FullName = m.FullName,   // Tên của người giao nhiệm vụ
                                  Role = m.Role,           // Vai trò của người giao nhiệm vụ
                                  ImageMember = m.ImageMember // Hình ảnh của người giao nhiệm vụ
                              })
                        .FirstOrDefault();  // Lấy thông tin của người giao nhiệm vụ đầu tiên

                var viewModel = new TaskViewModel
                {
                    TaskID = task.TaskID,
                    TaskName = task.TaskName,
                    Description = task.Description,
                    StartDate = task.StartDate ?? DateTime.MinValue,
                    EndDate = task.EndDate ?? DateTime.MinValue,
                    Priority = task.Priority ?? 0,
                    Status = task.Status,
                    // If you want to get the MemberID from TaskAssignments, you can map it like so
                    AssignedMembers = (from ta in task.TaskAssignments
                                       join member in context.Members on ta.MemberID equals member.MemberID
                                       select new MemberViewModel
                                       {
                                           MemberID = ta.MemberID,
                                           FullName = member.FullName,
                                           Role = member.Role,
                                           ImageMember = member.ImageMember
                                       }).ToList(),

                    Creator = creator  // Assign the creator here

                };

                return View(viewModel);
            }
        }

        //CHAT - START
        //Load Chat
        public ActionResult GroupChat(string projectId, int page = 1)
        {
            int pageSize = 6;
            // Lấy danh sách các đoạn chat của dự án dựa trên projectId và phân trang
            var interactions = data.Interactions
                .Where(i => i.ProjectID == projectId)
                .OrderByDescending(i => i.IsPinned) // Các tin nhắn được ghim ở trên
                .ThenByDescending(i => i.InteractionDate) // Các tin nhắn không ghim sẽ sắp xếp theo ngày
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

            var members = data.ProjectMembers
                 .Where(pm => pm.ProjectID == projectId && pm.Status == "Accepted")

                 .Select(pm => pm.Member)
                 .Distinct()
                 .Select(m => new MemberViewModel
                 {
                     FullName = m.FullName,
                     Email = m.Email,
                     Phone = m.Phone,
                     Status = m.Status,
                     Role = m.Role,
                     ImageMember = m.ImageMember
                 })
                 .ToList();

            ViewBag.Members = members;
            ViewBag.TotalChatCount = totalChatCount;

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

        //Them Chat
        [HttpPost]
        public ActionResult SendMessage(string Message, string ProjectID)
        {
            // Lấy MemberID của người dùng hiện tại (ví dụ từ Session hoặc User.Identity)
            string memberID = Session["MemberID"]?.ToString(); // Bạn có thể thay thế cách lấy MemberID theo cách của bạn

            if (!string.IsNullOrEmpty(Message) && !string.IsNullOrEmpty(memberID) && !string.IsNullOrEmpty(ProjectID))
            {
                // Tạo đối tượng Interaction để lưu vào cơ sở dữ liệu
                var interaction = new Interaction
                {
                    ProjectID = ProjectID,
                    MemberID = memberID,
                    InteractionDate = DateTime.Now,
                    Message = Message
                };

                // Lưu vào cơ sở dữ liệu
                data.Interactions.InsertOnSubmit(interaction);
                data.SubmitChanges();
            }

            // Sau khi lưu tin nhắn, chuyển hướng về trang GroupChat
            return RedirectToAction("GroupChat", new { projectId = ProjectID });
        }
        //Sua chat
        public ActionResult EditMessage(int messageId, string newMessage, string projectId)
        {
            if (messageId <= 0 || string.IsNullOrEmpty(newMessage) || string.IsNullOrEmpty(projectId))
            {
                return HttpNotFound();
            }
            var message = data.Interactions.FirstOrDefault(m => m.InteractionID == messageId);
            if (message != null)
            {
                message.Message = newMessage;
                data.SubmitChanges();
            }
            return RedirectToAction("GroupChat", new { projectId = projectId });
        }
        //Xoa chat
        public ActionResult DeleteMessage(int messageId, string projectId)
        {
            if (messageId <= 0 || string.IsNullOrEmpty(projectId))
            {
                return HttpNotFound();
            }
            var message = data.Interactions.FirstOrDefault(m => m.InteractionID == messageId);
            if (message != null)
            {
                data.Interactions.DeleteOnSubmit(message);
                data.SubmitChanges();
            }
            return RedirectToAction("GroupChat", new { projectId = projectId });
        }
        //Ghim chat
        public ActionResult PinMessage(int messageId, string projectId)
        {
            if (messageId <= 0 || string.IsNullOrEmpty(projectId))
            {
                return HttpNotFound();
            }
            var message = data.Interactions.FirstOrDefault(m => m.InteractionID == messageId);
            if (message != null)
            {
                //message.IsPinned = true;
                data.SubmitChanges();
            }
            return RedirectToAction("GroupChat", new { projectId = projectId });
        }
        //Bo ghim chat
        [HttpPost]
        public ActionResult TogglePinMessage(int messageId, string projectId)
        {
            var interaction = data.Interactions.FirstOrDefault(i => i.InteractionID == messageId && i.ProjectID == projectId);
            if (interaction != null)
            {
                // Đảo trạng thái ghim và cập nhật ngày tương tác
                //interaction.IsPinned = !(interaction.IsPinned ?? false);
                interaction.InteractionDate = DateTime.Now;
                data.SubmitChanges();
                return Json(new { success = true });
            }
            return Json(new { success = false });
        }

        //CHAT - END


        public ActionResult DSMember()
        {
            var role = Session["Role"]?.ToString();
            var memberId = Session["MemberID"]?.ToString();
            List<Members> members;

            // Kiểm tra quyền truy cập
            if (role == "Manager" || role == "Admin")
            {
                // Quản lý hoặc Admin có thể thấy toàn bộ danh sách members
                members = data.Members
                              .Where(m => m.deleteTime == null) // Lọc bỏ những người đã xóa
                              .Select(m => new Members
                              {
                                  MemberID = m.MemberID,
                                  FullName = m.FullName,
                                  Email = m.Email,
                                  Phone = m.Phone,
                                  Role = m.Role,
                                  HireDate = m.HireDate,
                                  Status = m.Status,
                                  //Password = m.Password,
                                  //ImageMember = m.ImageMember,
                                  MemberCount = data.TaskAssignments
                                                     .Where(a => a.MemberID == m.MemberID)
                                                     .Select(a => a.TaskID)
                                                     .Distinct()
                                                     .Count()
                              })
                              .ToList();
            }
            else
            {
                // Thành viên chỉ thấy các thành viên cùng tham gia dự án với họ
                members = data.TaskAssignments
                              .Where(a => a.AssignedBy == memberId && a.Member.deleteTime == null)
                              .Select(a => a.Member)
                              .Distinct()
                              .Select(m => new Members
                              {
                                  MemberID = m.MemberID,
                                  FullName = m.FullName,
                                  Email = m.Email,
                                  Phone = m.Phone,
                                  Role = m.Role,
                                  HireDate = m.HireDate,
                                  Status = m.Status,
                                  //Password = m.Password,
                                  //ImageMember = m.ImageMember,
                                  MemberCount = data.TaskAssignments
                                                     .Where(a => a.MemberID == m.MemberID)
                                                     .Select(a => a.TaskID)
                                                     .Distinct()
                                                     .Count()
                              })
                              .ToList();
            }

            return View(members);
        }


        public string GenerateMemberID()
        {
            // Lấy thời gian hiện tại
            DateTime now = DateTime.Now;

            // Định dạng thành chuỗi: HHmmssddMMyyyy
            string formattedTime = now.ToString("HHmmssddMMyyyy");

            return formattedTime;
        }

        public string GetUniqueMemberID()
        {
            string memberIDnew;
            bool isUnique;

            do
            {
                memberIDnew = GenerateMemberID(); // Tạo ID dựa trên thời gian hiện tại
                isUnique = !data.Members.Any(m => m.MemberID == memberIDnew); // Kiểm tra xem ID đã tồn tại chưa
            }
            while (!isUnique); // Nếu trùng, tiếp tục kiểm tra

            return memberIDnew;
        }

        //Addmember
        [HttpPost]
        public ActionResult AddMember(string FullName, string Email, string Phone, string Role, string Password, string ImageMember, HttpPostedFileBase ImageFile)
        {
            try
            {
                string imagePath = null;
                if (ImageFile != null && ImageFile.ContentLength > 0)
                {
                    string path = Server.MapPath("~/Content/images/member-img/");
                    Directory.CreateDirectory(path); // Create directory if it doesn't exist
                    imagePath = Path.Combine(path, ImageMember);
                    ImageFile.SaveAs(imagePath); // Save image
                }

                var member = new Member
                {
                    MemberID = GetUniqueMemberID(),
                    FullName = FullName,
                    Email = Email,
                    Phone = Phone,
                    Role = Role,
                    HireDate = DateTime.Now,
                    Status = "Offline",
                    //Password = Password,
                    //ImageMember = ImageMember,
                    deleteTime = null
                };

                data.Members.InsertOnSubmit(member);
                data.SubmitChanges();
                return RedirectToAction("DSMember");
            }
            catch (Exception ex)
            {
                return RedirectToAction("DSMember", new { notificationMessage = "Đã xảy ra lỗi khi thêm thành viên!", notificationType = "error" });
            }
        }
        //Edit Member
        [HttpPost]
        public ActionResult EditMember(string MemberID, string FullName, string Email, string Phone, string Role, string Password, DateTime HireDate, HttpPostedFileBase ImageFile)
        {
            try
            {
                var member = data.Members.FirstOrDefault(m => m.MemberID == MemberID);
                if (member != null)
                {
                    member.FullName = FullName;
                    member.Email = Email;
                    member.Phone = Phone;
                    member.Role = Role;
                    //member.HireDate = HireDate;
                    //member.Password = Password;


                    if (!string.IsNullOrEmpty(Password))
                    {
                        member.Password = Password; // Chỉ cập nhật nếu mật khẩu mới được nhập
                    }

                    if (ImageFile != null && ImageFile.ContentLength > 0)
                    {
                        string imagePath = Path.Combine(Server.MapPath("~/Content/images/member-img/"), ImageFile.FileName);
                        ImageFile.SaveAs(imagePath);
                        member.ImageMember = ImageFile.FileName; // Lưu tên ảnh vào database
                    }

                    data.SubmitChanges();
                    return RedirectToAction("DSMember", new { notificationMessage = "Cập nhật thành viên thành công!", notificationType = "success" });
                }
                return RedirectToAction("DSMember", new { notificationMessage = "Không tìm thấy thành viên!", notificationType = "error" });
            }
            catch (Exception ex)
            {
                return RedirectToAction("DSMember", new { notificationMessage = "Đã xảy ra lỗi khi cập nhật thông tin thành viên!", notificationType = "error" });
            }
        }

        [HttpPost]
        public JsonResult DeleteMember(List<string> memberIds)
        {
            try
            {
                var members = data.Members.Where(m => memberIds.Contains(m.MemberID)).ToList();
                foreach (var member in members)
                {
                    data.Members.DeleteOnSubmit(member);
                }
                data.SubmitChanges();
                return Json(new { success = true, message = "Thành viên đã được xóa thành công!" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = "Có lỗi xảy ra khi xóa thành viên: " + ex.Message });
            }
        }



    }
}
