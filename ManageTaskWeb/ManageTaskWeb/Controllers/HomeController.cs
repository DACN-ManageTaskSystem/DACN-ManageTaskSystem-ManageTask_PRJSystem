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
using System.Net.Mail;
using System.Configuration;
using Newtonsoft.Json.Linq;
using System.Web.Configuration;

namespace ManageTaskWeb.Controllers
{
    public class HomeController : Controller
    {
        QLCVDataContext data = new QLCVDataContext();
        public ActionResult Unauthorized()
        {
            return View();
        }

        [Authorize]
        public ActionResult Help()
        {
            return View();
        }
        //TrangChu
        public ActionResult TrangChu()
        {
            return View();
        }

        #region MA-HOA
        //Ma hoa
        public static string EncryptPassword(string plainText, string key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32)); 
                aes.IV = new byte[16]; 

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                    byte[] encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

                    return Convert.ToBase64String(encryptedBytes);
                }
            }
        }
        //Giai ma
        public static string DecryptPassword(string encryptedText, string key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32)); 
                aes.IV = new byte[16]; 
                aes.Padding = PaddingMode.PKCS7; 

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
        #endregion

        #region LOGIN - LOGOUT - CHANGE PASSWORD - FORGOT PASSWORD
        //DangNhap-GET
        public ActionResult DangNhap()
        {

            return View();
        }
        //DangNhap-POST
        [HttpPost]
        public ActionResult DangNhap(string username, string password)
        {
            var member = data.Members.FirstOrDefault(m => m.MemberID == username);

            if (member == null)
            {
                ViewBag.ErrorMessage = "*Tên đăng nhập hoặc mật khẩu không đúng.";
                return View();
            }

            string decryptedPassword = DecryptPassword(member.Password, "mysecretkey");

            if (decryptedPassword != password)
            {
                ViewBag.ErrorMessage = "*Tên đăng nhập hoặc mật khẩu không đúng.";
                return View();
            }

            if (member.ExpiryTime.HasValue && DateTime.Now > member.ExpiryTime.Value)
            {
                ViewBag.ErrorMessage = "*Mật khẩu tạm thời đã hết hạn. Vui lòng yêu cầu mật khẩu mới.";
                return View();
            }

            member.Status = "Active";
            data.SubmitChanges();

            Session["Password"] = decryptedPassword;
            Session["MemberID"] = member.MemberID;
            Session["FullName"] = member.FullName;
            Session["Role"] = member.Role;
            Session["Email"] = member.Email;
            Session["Phone"] = member.Phone;
            Session["Address"] = member.Address;
            Session["DateOfBirth"] = member.DateOfBirth;
            Session["ImageMember"] = member.ImageMember;

            if (member.ExpiryTime.HasValue)
            {
                return RedirectToAction("ChangePassword");
            }
            return RedirectToAction("TrangChu");
        }
        //DangXuat
        public ActionResult Logout()
        {
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
            Session.Clear();
            return RedirectToAction("DangNhap");
        }
        //Hien thi View Doi MK
        public ActionResult ChangePassword()
        {
            return View();
        }
        //Chuc nang doi mat khau
        [HttpPost]
        public ActionResult ChangePassword(string oldPassword, string newPassword)
        {
            var sessionPassword = Session["Password"]?.ToString();
            if (sessionPassword == null)
            {
                ViewBag.ErrorMessage = "Session expired. Please log in again.";
                return RedirectToAction("Login", "Home");
            }

            var MemberID_Session = Session["MemberID"].ToString();
            var currentMember = data.Members.SingleOrDefault(m => m.MemberID == MemberID_Session);

            
            if (EncryptPassword(oldPassword, "mysecretkey") != currentMember.Password)
            {
                ViewBag.ErrorMessage = "Old password is incorrect.";
                return View();
            }

            
            if (!IsStrongPassword(newPassword))
            {
                ViewBag.ErrorMessage = "Password must be at least 8 characters long and contain: uppercase letter, lowercase letter, number, and special character.";
                return View();
            }

            currentMember.Password = EncryptPassword(newPassword, "mysecretkey");
            currentMember.ExpiryTime = null; 
            data.SubmitChanges();

            return View("TrangChu");
        }
        //Kiem tra mat khau manh
        private bool IsStrongPassword(string password)
        {
            
            if (password.Length < 8) return false;
            bool hasUppercase = password.Any(char.IsUpper);
            bool hasLowercase = password.Any(char.IsLower);
            bool hasDigit = password.Any(char.IsDigit);
            bool hasSpecialChar = password.Any(ch => !char.IsLetterOrDigit(ch));

            return hasUppercase && hasLowercase && hasDigit && hasSpecialChar;
        }
        //Hiem form Quen MK
        public ActionResult ForgotPassword()
        {
            return View();
        }
        //Xu ly Quen MK
        [HttpPost]
        public ActionResult ForgotPassword(string memberID, string email)
        {
            try
            {
                var response = Request["g-recaptcha-response"];
                string secretKey = ConfigurationManager.AppSettings["reCaptcha:SecretKey"];
                var client = new WebClient();

                var result = client.DownloadString(string.Format(
                    "https://www.google.com/recaptcha/api/siteverify?secret={0}&response={1}",
                    secretKey, response));

                var obj = JObject.Parse(result);
                var status = (bool)obj.SelectToken("success");

                if (!status)
                {
                    ViewBag.Message = "Please verify that you are not a robot.";
                    ViewBag.IsError = true;
                    return View();
                }

                var member = data.Members.FirstOrDefault(m =>
                    m.MemberID == memberID &&
                    m.Email == email);
                if (member == null)
                {
                    ViewBag.IsError = true;
                    ViewBag.Message = "Invalid Member ID or Email";
                    return View();
                }

                string newPassword = GenerateRandomPasswordForgot();

                DateTime expiryTime = DateTime.Now.AddMinutes(10);

                member.Password = EncryptPassword(newPassword, "mysecretkey");
                member.ExpiryTime = expiryTime;
                data.SubmitChanges();

                SendPasswordResetEmail(email, newPassword, expiryTime);

                ViewBag.IsError = false;
                ViewBag.Message = "New password has been sent to your email. Please change it within 10 minutes.";
            }
            catch (Exception ex)
            {
                ViewBag.IsError = true;
                ViewBag.Message = "Error processing request. Please try again later.";
            }

            return View();
        }
        //Tao MK moi 8 ki tu
        private string GenerateRandomPasswordForgot()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var random = new Random();
            return new string(Enumerable.Repeat(chars, 8)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }
        //Gui Mail mk moi
        private void SendPasswordResetEmail(string email, string newPassword, DateTime expiryTime)
        {
            try
            {
                var fromEmail = ConfigurationManager.AppSettings["EmailFrom"];
                var fromName = ConfigurationManager.AppSettings["EmailFromName"];
                var emailPassword = ConfigurationManager.AppSettings["EmailPassword"];

                if (string.IsNullOrEmpty(fromEmail) || string.IsNullOrEmpty(emailPassword))
                {
                    throw new ConfigurationErrorsException("Email settings are missing in Web.config");
                }

                var fromAddress = new MailAddress(fromEmail, fromName ?? "System Admin");
                var toAddress = new MailAddress(email);

                string subject = "Password Reset";
                string body = $@"DO NOT SHARE WITH ANYONE
                        Your temporary password is: {newPassword}
                        
                        This password will expire at: {expiryTime.ToString("yyyy-MM-dd HH:mm:ss")}
                        
                        Please login and change your password before it expires.
                        
                        If you don't change your password within 10 minutes, you'll need to request a new password reset.";

                using (var message = new MailMessage(fromAddress, toAddress)
                {
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = false
                })
                using (var smtp = new SmtpClient()
                {
                    Host = "smtp.gmail.com",
                    Port = 587,
                    EnableSsl = true,
                    DeliveryMethod = SmtpDeliveryMethod.Network,
                    UseDefaultCredentials = false,
                    Credentials = new NetworkCredential(fromEmail, emailPassword)
                })
                {
                    smtp.Send(message);
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to send password reset email", ex);
            }
        }
        #endregion

        #region INFO
        //Thong tin ca nhan
        public ActionResult TTCaNhan()
        {
            return View();
        }

        #endregion

        #region NOTIFICATION - REQUEST
        //Load Thong bao 
        public JsonResult GetNotifications()
        {
            if (Session["MemberID"] != null)
            {
                string memberId = Session["MemberID"].ToString();
                var notifications = data.Notifications
                .Where(n => n.MemberID == memberId)
                .OrderByDescending(n => n.NotificationDate)
                .Select(n => new
                {
                    n.NotificationID,
                    n.Content,
                    NotificationDate = n.NotificationDate.ToString(), 
                    IsRead = n.IsRead.HasValue ? n.IsRead.Value : false, 
                    n.NotificationType,
                    ShowAcceptReject = n.NotificationType == "JoinRequest"
                })
                .ToList();
                if (!notifications.Any())
                {
                    return Json(new { success = true, message = "No notifications" }, JsonRequestBehavior.AllowGet);
                }

                return Json(new { success = true, notifications }, JsonRequestBehavior.AllowGet);
            }
            return Json(new { success = false, message = "User not logged in" }, JsonRequestBehavior.AllowGet);
        }
        //Cap nhat trang thai read - unread
        [HttpPost]
        public JsonResult ToggleNotificationStatus(int notificationId, bool currentIsRead)
        {
            try
            {
                var notification = data.Notifications.FirstOrDefault(n => n.NotificationID == notificationId);
                if (notification != null)
                {
                    notification.IsRead = !currentIsRead;
                    data.SubmitChanges();

                    return Json(new { success = true });
                }
                return Json(new { success = false, message = "Notification not found" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
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

                var notification = data.Notifications.FirstOrDefault(n => n.NotificationID.ToString() == notificationId);
                if (notification == null)
                {
                    return Json(new { success = false, message = "Notification not found" });
                }

                var extraData = JsonConvert.DeserializeObject<Dictionary<string, string>>(notification.ExtraData);
                string requestMemberId = extraData["RequestMemberID"];
                string projectId = extraData["ProjectID"];

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

                var notificationsToDelete = data.Notifications
                    .Where(n => n.ExtraData == notification.ExtraData)
                    .ToList();

                foreach (var notif in notificationsToDelete)
                {
                    data.Notifications.DeleteOnSubmit(notif);
                }
                data.SubmitChanges();

                var project = data.Projects.FirstOrDefault(p => p.ProjectID == projectId);
                var newMember = data.Members.FirstOrDefault(m => m.MemberID == requestMemberId);
                if (project == null || newMember == null)
                {
                    return Json(new { success = false, message = "Error: Project or member not found." });
                }

                string projectName = project.ProjectName;
                string fullName = newMember.FullName;

                var projectMembers = data.ProjectMembers
                    .Where(pm => pm.ProjectID == projectId && pm.Status == "Accepted")
                    .Select(pm => pm.MemberID)
                    .ToList();

                data.Notifications.InsertOnSubmit(new Notification
                {
                    MemberID = requestMemberId,
                    Content = $"Bạn đã được thêm vào project '{projectName}'.",
                    NotificationDate = DateTime.Now,
                    IsRead = false,
                    NotificationType = "JoinAccepted"
                });

                foreach (var member in projectMembers)
                {
                    if (member != requestMemberId) 
                    {
                        data.Notifications.InsertOnSubmit(new Notification
                        {
                            MemberID = member,
                            Content = $"Dự án '{projectName}' có thành viên mới: {fullName}.",
                            NotificationDate = DateTime.Now,
                            IsRead = false,
                            NotificationType = "JoinAccepted"
                        });
                    }
                }

                var adminAndManagers = data.Members
                    .Where(m => m.Role == "Admin" || m.Role == "Manager")
                    .Select(m => m.MemberID)
                    .ToList();

                foreach (var admin in adminAndManagers)
                {
                    data.Notifications.InsertOnSubmit(new Notification
                    {
                        MemberID = admin,
                        Content = $"Thành viên mới: '{fullName}' đã tham gia vào dự án '{projectName}'.",
                        NotificationDate = DateTime.Now,
                        IsRead = false,
                        NotificationType = "JoinAccepted"
                    });
                }

                data.SubmitChanges();

                return Json(new { success = true, message = "Request accepted successfully, notifications sent." });
            }
            catch (Exception ex)
            { 
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

                var notification = data.Notifications.FirstOrDefault(n => n.NotificationID == notificationId);
                if (notification == null)
                {
                    return Json(new { success = false, message = "Notification not found." });
                }

                var extraData = JsonConvert.DeserializeObject<Dictionary<string, string>>(notification.ExtraData);
                string requestMemberId = extraData["RequestMemberID"];
                string projectId = extraData["ProjectID"];

                var projectMember = data.ProjectMembers
                    .FirstOrDefault(pm => pm.MemberID == requestMemberId && pm.ProjectID == projectId && pm.Status == "Pending");
                if (projectMember != null)
                {
                    data.ProjectMembers.DeleteOnSubmit(projectMember);
                }

                var notificationsToDelete = data.Notifications
                    .Where(n => n.ExtraData == notification.ExtraData)
                    .ToList();

                foreach (var notif in notificationsToDelete)
                {
                    data.Notifications.DeleteOnSubmit(notif);
                }

                data.Notifications.InsertOnSubmit(new Notification
                {
                    MemberID = requestMemberId,
                    Content = $"Yêu cầu tham gia dự án có mã: '{projectId}' đã bị từ chối vì: {reason}.",
                    NotificationDate = DateTime.Now,
                    IsRead = false,
                    NotificationType = "JoinRejected"
                });

                data.SubmitChanges();

                return Json(new { success = true, message = "Request rejected successfully, notifications updated." });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = "Error: " + ex.Message });
            }
        }
        #endregion

        #region PROJECT
        //Danh sach project
        [RoleAuthorization("Admin", "Manager", "Developer")]
        public ActionResult DSProject(string statusFilter = "All")
        {
            var role = Session["Role"]?.ToString();
            List<ProjectExtended> projects;
            if (role == "Admin")
            {
                projects = data.Projects
                               .Where(p => statusFilter == "All" || p.Status == statusFilter)
                               .Select(p => new ProjectExtended
                               {
                                   ProjectID = p.ProjectID,
                                   ProjectName = p.ProjectName,
                                   Description = p.Description,
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
                                   Description = p.Description,
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
        //Tao ProjectID
        public string GenerateUniqueProjectID()
        {
            string prefix = "PRJ";
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var random = new Random();
            var randomString = new string(Enumerable.Repeat(chars, 6)
                .Select(s => s[random.Next(s.Length)]).ToArray());
            return prefix + randomString;
        }
        //Lay ProjectID
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
        public ActionResult AddProject(string ProjectName, string Description, DateTime StartDate, DateTime EndDate, int Priority, string Status, HttpPostedFileBase ImageFile)
        {
            try
            {
                string imageFileName = null;

                if (ImageFile != null && ImageFile.ContentLength > 0)
                {
                    // Kiểm tra định dạng file
                    var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif" };
                    var extension = Path.GetExtension(ImageFile.FileName).ToLower();
                    if (!allowedExtensions.Contains(extension))
                    {
                        return RedirectToAction("DSProject", new { notificationMessage = "Chỉ chấp nhận file ảnh có định dạng: .jpg, .jpeg, .png, .gif!", notificationType = "error" });
                    }
                    imageFileName = $"project_{Guid.NewGuid()}{extension}";
                    string path = Server.MapPath("~/Content/images/project-img/");
                    Directory.CreateDirectory(path);
                    string fullPath = Path.Combine(path, imageFileName);
                    ImageFile.SaveAs(fullPath);
                }

                var project = new Project
                {
                    ProjectID = GetUniqueProjectID(),
                    ProjectName = ProjectName?.Trim(),
                    Description = Description?.Trim(),
                    StartDate = StartDate,
                    EndDate = EndDate,
                    Priority = Priority,
                    Status = Status,
                    ImageProject = imageFileName,
                    deleteTime = null,
                    createBy = Session["MemberID"].ToString(),
                };

                if (string.IsNullOrEmpty(project.ProjectName))
                {
                    return RedirectToAction("DSProject", new { notificationMessage = "Tên dự án không được để trống!", notificationType = "error" });
                }

                if (project.EndDate <= project.StartDate)
                {
                    return RedirectToAction("DSProject", new { notificationMessage = "Ngày kết thúc phải sau ngày bắt đầu!", notificationType = "error" });
                }

                data.Projects.InsertOnSubmit(project);
                 var projectMember = new ProjectMember
                {
                    ProjectID = project.ProjectID,
                    MemberID = Session["MemberID"].ToString(),
                     Status = "Accepted",
                    JoinDate = DateTime.Now
                };

        data.ProjectMembers.InsertOnSubmit(projectMember);
                data.SubmitChanges();

                return RedirectToAction("DSProject", new { notificationMessage = "Thêm dự án mới thành công!", notificationType = "success" });
            }
            catch (Exception ex)
            {
               
                System.Diagnostics.Debug.WriteLine($"Error adding project: {ex.Message}");
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
                    return RedirectToAction("DSProject", new { notificationMessage = "Không tìm thấy dự án!", notificationType = "error" });
                }
                if (string.IsNullOrEmpty(ProjectName?.Trim()))
                {
                    return RedirectToAction("DSProject", new { notificationMessage = "Tên dự án không được để trống!", notificationType = "error" });
                }

                if (EndDate <= StartDate)
                {
                    return RedirectToAction("DSProject", new { notificationMessage = "Ngày kết thúc phải sau ngày bắt đầu!", notificationType = "error" });
                }

                if (ImageFile != null && ImageFile.ContentLength > 0)
                {

                    var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif" };
                    var extension = Path.GetExtension(ImageFile.FileName).ToLower();
                    if (!allowedExtensions.Contains(extension))
                    {
                        return RedirectToAction("DSProject", new { notificationMessage = "Chỉ chấp nhận file ảnh có định dạng: .jpg, .jpeg, .png, .gif!", notificationType = "error" });
                    }

                    if (!string.IsNullOrEmpty(project.ImageProject))
                    {
                        string oldImagePath = Path.Combine(Server.MapPath("~/Content/images/project-img/"), project.ImageProject);
                        if (System.IO.File.Exists(oldImagePath))
                        {
                            System.IO.File.Delete(oldImagePath);
                        }
                    }

                    string newFileName = $"project_{Guid.NewGuid()}{extension}";
                    string path = Server.MapPath("~/Content/images/project-img/");
                    Directory.CreateDirectory(path);
                    string fullPath = Path.Combine(path, newFileName);
                    ImageFile.SaveAs(fullPath);

                    project.ImageProject = newFileName;
                }

                project.ProjectName = ProjectName.Trim();
                project.Description = Description?.Trim();
                project.StartDate = StartDate;
                project.EndDate = EndDate;
                project.Priority = Priority;
                project.Status = Status;

                data.SubmitChanges();

                return RedirectToAction("DSProject", new { notificationMessage = "Cập nhật dự án thành công!", notificationType = "success" });
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error updating project: {ex.Message}");
                return RedirectToAction("DSProject", new { notificationMessage = "Đã xảy ra lỗi khi cập nhật dự án!", notificationType = "error" });
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

                
                List<string> failedProjects = new List<string>();
                List<string> deletedProjects = new List<string>();

                foreach (var projectId in projectIds)
                {
                    var project = data.Projects.FirstOrDefault(p => p.ProjectID == projectId);
                    if (project == null) continue;

                    
                    bool hasTasks = data.Tasks.Any(t => t.ProjectID == projectId);
                    if (hasTasks)
                    {
                        failedProjects.Add(projectId);
                    }
                    else
                    {
                        data.Projects.DeleteOnSubmit(project);
                        deletedProjects.Add(projectId);
                    }
                }
                data.SubmitChanges();

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
        //Tham gia Project by ProjectID
        [HttpPost]
        [ValidateAntiForgeryToken]
        public JsonResult JoinProject(string projectCode)
        {
            var project = data.Projects.FirstOrDefault(p => p.ProjectID == projectCode && p.deleteTime == null);

            if (project == null)
            {
                return Json(new { success = false, error = "Project does not exist or has been deleted." });
            }

            var memberID = Session["MemberID"]?.ToString();
            if (string.IsNullOrEmpty(memberID))
            {
                return Json(new { success = false, error = "You need to log in to join a project." });
            }

            var member = data.Members.FirstOrDefault(m => m.MemberID == memberID);
            if (member == null)
            {
                return Json(new { success = false, error = "Member not found." });
            }

            var isMember = data.ProjectMembers.Any(pm => pm.ProjectID == projectCode && pm.MemberID == memberID && pm.Status == "Accepted");
            if (isMember)
            {
                return Json(new { success = false, error = "You are already a member of this project." });
            }

            var existingRequest = data.ProjectMembers.FirstOrDefault(pm => pm.ProjectID == projectCode && pm.MemberID == memberID);
            if (existingRequest != null)
            {
                return Json(new { success = false, error = "You have already submitted a join request for this project." });
            }

            var newRequest = new ProjectMember
            {
                ProjectID = projectCode,
                MemberID = memberID,
                Status = "Pending",
                JoinDate = DateTime.Now
            };
            data.ProjectMembers.InsertOnSubmit(newRequest);
            data.SubmitChanges();

            var adminOrManagers = data.Members
                .Where(m => m.Role == "Admin" || m.Role == "Manager")
                .Select(m => m.MemberID)
                .ToList();

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
        #endregion

        #region PROJECT'S MEMBER
        //Danh sach Member trong Project
        public ActionResult MembersOfProject(string projectId)
        {
            var project = data.Projects.FirstOrDefault(p => p.ProjectID == projectId);
            if (project != null)
                {
                    var owner = data.Members.FirstOrDefault(m => m.MemberID == project.createBy);
                ViewBag.OwnerImage = owner != null ? owner.ImageMember : "error.png"; 
                    ViewBag.OwnerName = owner != null ? owner.FullName : project.createBy;
                }
    
            var members = data.ProjectMembers
                             .Where(pm => pm.ProjectID == projectId && pm.Status == "Accepted") 

                             .Select(pm => pm.Member)
                             .Distinct()
                             .ToList();
            ViewBag.Project = project;
            ViewBag.ProjectId = projectId;
            return View(members);
        }
        //Lay thong bao yeu cau tham gia
        public ActionResult GetJoinRequests(string projectId)
        {
            var notifications = data.Notifications
                .Where(n => n.NotificationType == "JoinRequest")
                .ToList(); 
            var requestMemberData = notifications
                .Where(n =>
                {
                    try
                    {
                        var extraData = JsonConvert.DeserializeObject<Dictionary<string, string>>(n.ExtraData);
                        return extraData.ContainsKey("ProjectID") && extraData["ProjectID"] == projectId;
                    }
                    catch
                    {
                        return false;
                    }
                })
                .Select(n =>
                {
                    var extraData = JsonConvert.DeserializeObject<Dictionary<string, string>>(n.ExtraData);
                    return new
                    {
                        NotificationID = n.NotificationID,  
                        RequestMemberID = extraData.ContainsKey("RequestMemberID") ? extraData["RequestMemberID"] : null
                    };
                })
                .ToList(); 
            var requestMemberIds = requestMemberData.Select(r => r.RequestMemberID).ToList();
            var members = data.Members
                .Where(m => requestMemberIds.Contains(m.MemberID)) 
                .ToList();
            var result = members.Select(m => new
            {
                m.MemberID,
                m.FullName,
                m.Role,
                m.ImageMember,
                NotificationIDs = requestMemberData
                    .Where(r => r.RequestMemberID == m.MemberID)
                    .Select(r => r.NotificationID)
                    .ToList()
            }).ToList();

            return Json(result, JsonRequestBehavior.AllowGet);
        }
        //DS member khong trong du an
        public JsonResult GetNonProjectMembers(string projectId)
        {
            try
            {
                var nonMembers = data.Members
                    .Where(m => m.MemberID != "0" &&
                    !data.ProjectMembers.Any(pm =>
                              pm.ProjectID == projectId &&
                              pm.MemberID == m.MemberID &&
                              pm.Status == "Accepted"))
                    .Select(m => new
                    {
                        MemberId = m.MemberID,
                        FullName = m.FullName,
                        Role = m.Role,
                        ImageMember = m.ImageMember,
                        Email = m.Email
                    })
                    .ToList();

                return Json(nonMembers, JsonRequestBehavior.AllowGet);
            }
            catch (Exception ex)
            {
                return Json(new { error = ex.Message }, JsonRequestBehavior.AllowGet);
            }
        }
        //DSMember trong du an
        public JsonResult GetProjectMembers(string projectId)
        {
            try
            {
                var projectMembers = data.ProjectMembers
                    .Where(pm => pm.ProjectID == projectId &&
                           pm.Status == "Accepted")
                    .Select(pm => new
                    {
                        MemberId = pm.MemberID,
                        FullName = pm.Member.FullName,
                        Role = pm.Member.Role,
                        ImageMember = pm.Member.ImageMember,
                        Email = pm.Member.Email,
                        JoinDate = pm.JoinDate
                    })
                    .ToList();

                return Json(projectMembers, JsonRequestBehavior.AllowGet);
            }
            catch (Exception ex)
            {
                return Json(new { error = ex.Message }, JsonRequestBehavior.AllowGet);
            }
        }
        //Them member vao du an
        [HttpPost]
        public JsonResult AddMemberToProject(string projectId, string memberId)
        {
            try
            {
                var existingMember = data.ProjectMembers
                    .FirstOrDefault(pm => pm.ProjectID == projectId &&
                                  pm.MemberID == memberId);

                if (existingMember != null)
                {
                    return Json(new { success = false, message = "Member already exists in the project." });
                }
                var projectMember = new ProjectMember
                {
                    ProjectID = projectId,
                    MemberID = memberId,
                    JoinDate = DateTime.Now,
                    Status = "Accepted"
                };

                data.ProjectMembers.InsertOnSubmit(projectMember);
                data.SubmitChanges();
                var project = data.Projects.FirstOrDefault(p => p.ProjectID == projectId);
                var member = data.Members.FirstOrDefault(m => m.MemberID == memberId);
                var notification = new Notification
                {
                    MemberID = memberId,
                    Content = $"You have been added to project '{project.ProjectName}'",
                    NotificationDate = DateTime.Now,
                    NotificationType = "ProjectJoin",
                    IsRead = false
                };

                data.Notifications.InsertOnSubmit(notification);
                data.SubmitChanges();

                return Json(new { success = true });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }
        //Xoa member khoi du an
        [HttpPost]
        public JsonResult RemoveMemberFromProject(string projectId, string memberId)
        {
            try
            {
                var hasActiveTasks = data.TaskAssignments
                    .Any(ta => ta.Task.ProjectID == projectId &&
                         ta.MemberID == memberId &&
                         ta.Status != "Completed");

                if (hasActiveTasks)
                {
                    return Json(new
                    {
                        success = false,
                        message = "Cannot remove member with active tasks."
                    });
                }

                var projectMember = data.ProjectMembers
                    .FirstOrDefault(pm => pm.ProjectID == projectId &&
                                  pm.MemberID == memberId);

                if (projectMember != null)
                {
                    data.ProjectMembers.DeleteOnSubmit(projectMember);
                    data.SubmitChanges();

                    var project = data.Projects.FirstOrDefault(p => p.ProjectID == projectId);
                    var notification = new Notification
                    {
                        MemberID = memberId,
                        Content = $"You have been removed from project '{project.ProjectName}'",
                        NotificationDate = DateTime.Now,
                        NotificationType = "ProjectRemoval",
                        IsRead = false
                    };

                    data.Notifications.InsertOnSubmit(notification);
                    data.SubmitChanges();
                }

                return Json(new { success = true });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }
        #endregion

        #region TASK
        //Danh sach task
        public ActionResult DSTask(string projectId)
        {
            var role = Session["Role"]?.ToString();
            var memberId = Session["MemberID"]?.ToString();
            if (string.IsNullOrEmpty(projectId))
            {
                return RedirectToAction("Error", new { message = "Project ID is missing or invalid." });
            }

            var project = data.Projects.FirstOrDefault(p => p.ProjectID == projectId);
            if (project == null)
            {
                return RedirectToAction("Error", new { message = "Project not found." });
            }


            ViewBag.ProjectStartDate = project.StartDate;
            ViewBag.ProjectEndDate = project.EndDate;
            if (role == "Manager" || role == "Admin")
            {
                var tasks = data.Tasks
                                .Where(t => t.ProjectID == projectId && t.Priority != null && t.ParentTaskID == null)
                                .ToList();
                return View(tasks);
            }
            else
            {
                var tasks = data.Tasks
                                .Where(t => t.ProjectID == projectId
                                            && t.Priority != null
                                            && data.TaskAssignments.Any(ta => ta.TaskID == t.TaskID && ta.MemberID == memberId)
                                            && t.ParentTaskID == null)
                                .ToList();
                return View(tasks);
            }
        }
        //Them Task
        [HttpPost]
        public ActionResult AddTask(string TaskName, string Description, DateTime? StartDate, DateTime? EndDate, int Priority, string Status, string ProjectID, string DriveLink, int? ParentTaskID = null)
        {
            try
            {
                var task = new Task
                {
                    TaskName = TaskName,
                    Description = Description,
                    StartDate = StartDate,
                    EndDate = EndDate,
                    Priority = Priority,
                    Status = Status,
                    ProjectID = ProjectID,
                    DriveLink = DriveLink,
                    ParentTaskID = ParentTaskID,
                    createBy = Session["MemberID"].ToString(),
                };
                data.Tasks.InsertOnSubmit(task);
                data.SubmitChanges();
                var taskAssignment = new TaskAssignment
                {
                    TaskID = task.TaskID,  
                    MemberID = task.createBy,  
                    AssignedBy = task.createBy, 
                    AssignedDate = DateTime.Now, 
                    Status = "Pending"  
                };

                
                data.TaskAssignments.InsertOnSubmit(taskAssignment);
                data.SubmitChanges();
                
                return RedirectToAction("DSTask", new { projectId = ProjectID, notificationMessage = "Task added successfully!", notificationType = "success" });
            }
            catch (Exception)
            {
                
                return RedirectToAction("DSTask", new { projectId = ProjectID, notificationMessage = "An error occurred while adding the task!", notificationType = "error" });

            }
        }
        //Edit task 
        [HttpPost]
        public ActionResult EditTask(int TaskID, string TaskName, string Description, DateTime? StartDate, DateTime? EndDate, int Priority, string Status, string DriveLink, int? ParentTaskID = null)
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
                task.ParentTaskID = ParentTaskID;
                task.DriveLink = DriveLink;
                data.SubmitChanges();

                return RedirectToAction("DSTask", new { projectId = task.ProjectID, notificationMessage = "Task updated successfully!", notificationType = "success" });
            }
            catch (Exception)
            {
                return RedirectToAction("DSTask", new { notificationMessage = "An error occurred while updating the task!", notificationType = "error" });

            }
        }
        //Cap nhat trang thai
        [HttpPost]
        public ActionResult UpdateStatus(int taskId, string status, int taskId_Main)
        {
            using (var context = new QLCVDataContext())
            {
                var task = context.Tasks.FirstOrDefault(t => t.TaskID == taskId);
                if (task == null)
                {
                    return Json(new { success = false, message = "Task not found." });
                }
                task.Status = status;
                context.SubmitChanges();

                var subTasks = context.Tasks.Where(t => t.ParentTaskID == taskId_Main).ToList();
                var a = "Pending";
                if (subTasks == null || subTasks.Count == 0)
                {
                    a = "Pending";
                }
                else
                {
                    int doneCount = subTasks.Count(st => st.Status == "Completed");
                    int totalCount = subTasks.Count;

                    if (doneCount == totalCount)
                    {
                        a = "Completed";
                    }
                    else if (doneCount > 0)
                    {
                        a = "In Progress";
                    }
                    else
                    {
                        a = "Pending";
                    }                                                                                                                                                                                                                                                                                                             
                }

                var taskmain = context.Tasks.FirstOrDefault(t => t.TaskID == taskId_Main);
                if (task == null)
                {
                    return Json(new { success = false, message = "Task not found." });
                }
                if (taskmain.Status != a)
                {
                    var taskLog = new TaskLog
                    {
                        TaskID = taskId_Main,
                        Status = a,
                        LogDate = DateTime.Now,
                        Note = "Change Process"
                    };
                    context.TaskLogs.InsertOnSubmit(taskLog);
                }
                // Cập nhật trạng thái
                taskmain.Status = a;
                context.SubmitChanges();


                return Json(new { success = true });
            }
        }
        //Them nhan vien vao task
        [HttpPost]
        public ActionResult UpdateAssignedMember(int taskAssignmentId, string memberId)
        {
            var assignmentfind = data.TaskAssignments.FirstOrDefault(t => t.TaskAssignmentID  == taskAssignmentId);


            var MemberAssigned = data.Members.FirstOrDefault(t => t.MemberID == assignmentfind.AssignedBy);

            var taskfind = data.Tasks.FirstOrDefault(t => t.TaskID == assignmentfind.TaskID);

            var Project = data.Projects.FirstOrDefault(t => t.ProjectID == taskfind.ProjectID);

            data.Notifications.InsertOnSubmit(new Notification
            {
                MemberID = memberId,
                Content = $"Bạn đã được phân công tham gia vào SubTask '{taskfind.Description}' trong dự án '{Project.ProjectName}' bởi '{MemberAssigned.FullName}' là '{MemberAssigned.Role}' ",
                NotificationDate = DateTime.Now,
                IsRead = false,
                NotificationType = "JoinSubTaskAccepted"
            });
            data.SubmitChanges();
            using (var context = new QLCVDataContext())
            {
                var taskAssignment = context.TaskAssignments.FirstOrDefault(ta => ta.TaskAssignmentID == taskAssignmentId);
                if (taskAssignment != null)
                {
                    taskAssignment.MemberID = memberId;  // Cập nhật MemberID
                    context.SubmitChanges();  // Lưu thay đổi vào cơ sở dữ liệu
                    return Json(new { success = true });
                }
                return Json(new { success = false });
            }
        }
        #endregion

        #region SUBTASK
        //Chi tiet task
        public ActionResult DetailTask(string taskId)
        {
            ViewBag.MemberID = Session["MemberID"];
            ViewBag.Role = Session["Role"];

            if (taskId == null)
                return HttpNotFound();  

            using (var context = new QLCVDataContext())
            {
                if (!int.TryParse(taskId, out int taskIdInt))
                {
                    return HttpNotFound();
                }

                var task = context.Tasks
                                  .Include(t => t.Project)
                                  .Include(t => t.TaskAssignments.Select(ta => ta.Member))
                                  .FirstOrDefault(t => t.TaskID == taskIdInt); 

                if (task == null)
                    return HttpNotFound(); 
                var subTaskAssignments = context.TaskAssignments
                                       .Where(ta => context.Tasks.Any(t => t.ParentTaskID == taskIdInt && t.TaskID == ta.TaskID))
                                       .Select(ta => new TaskAssignmentViewModel
                                       {
                                           TaskAssignmentID = ta.TaskAssignmentID,
                                           TaskID = ta.TaskID,
                                           MemberID = ta.MemberID,
                                           AssignedBy = ta.AssignedBy,
                                           AssignedDate = ta.AssignedDate,
                                           Status = ta.Status,
                                           Note = ta.Note
                                       }).ToList();
                var creator = task.TaskAssignments
                        .Where(ta => ta.AssignedBy != null)
                        .Join(context.Members,
                              ta => ta.AssignedBy, 
                              m => m.MemberID,      
                              (ta, m) => new MemberViewModel
                              {
                                  MemberID = ta.AssignedBy,
                                  FullName = m.FullName,   
                                  Role = m.Role,          
                                  ImageMember = m.ImageMember 
                              })
                        .FirstOrDefault();  

                var listTasks = context.Tasks
                      .AsNoTracking()
                      .Where(t => t.ParentTaskID == int.Parse(taskId))
                      .Select(t => new TaskViewModel
                      {
                          ProjectID = t.ProjectID,
                          TaskID = t.TaskID,
                          TaskName = t.TaskName,
                          Description = t.Description,
                          StartDate = t.StartDate,
                          EndDate = t.EndDate,
                          Status = t.Status,
                          Priority = t.Priority,
                          ParentTaskID = t.ParentTaskID
                      })
                      .ToList();

                var viewModel = new TaskViewModel
                {
                    ParentTaskID = task.ParentTaskID,
                    ProjectID = task.ProjectID,
                    TaskID = task.TaskID,
                    TaskName = task.TaskName,
                    Description = task.Description,
                    DriveLink = task.DriveLink,
                    StartDate = task.StartDate ?? DateTime.MinValue,
                    EndDate = task.EndDate ?? DateTime.MinValue,
                    Priority = task.Priority ?? 0,
                    Status = task.Status,
                    TaskAssignment = subTaskAssignments, 
                    AssignedMembers = (from ta in task.TaskAssignments
                                       join member in context.Members on ta.MemberID equals member.MemberID
                                       select new MemberViewModel
                                       {
                                           MemberID = ta.MemberID,
                                           FullName = member.FullName,
                                           Role = member.Role,
                                           ImageMember = member.ImageMember

                                       }).ToList(),
                    ProjectMembers = (from pm in data.ProjectMembers
                                      join m in data.Members on pm.MemberID equals m.MemberID
                                      where pm.ProjectID == task.ProjectID && pm.Status == "Accepted"
                                      select new MemberViewModel
                                      {
                                          MemberID = m.MemberID,        
                                          FullName = m.FullName,       
                                          Role = m.Role,                
                                          ImageMember = m.ImageMember 
                                      }).ToList(),
                    Creator = creator,  
                    ListTasks = listTasks  
                };


                return View(viewModel);
            }
        }
        //Xoa task
        [HttpPost]
        public ActionResult DeleteTaskByMember(int taskId)
        {
            var assignmentfind = data.TaskAssignments.FirstOrDefault(t => t.TaskID == taskId);

            var MemberAssigned = data.Members.FirstOrDefault(t => t.MemberID == assignmentfind.AssignedBy);

            var taskfind = data.Tasks.FirstOrDefault(t => t.TaskID == assignmentfind.TaskID);

            var Project = data.Projects.FirstOrDefault(t => t.ProjectID == taskfind.ProjectID);

            data.Notifications.InsertOnSubmit(new Notification
            {
                MemberID = MemberAssigned.MemberID,
                Content = $"Bạn xóa khỏi  SubTask '{taskfind.Description}' trong dự án '{Project.ProjectName}' bởi '{MemberAssigned.FullName}'  '{MemberAssigned.Role}' ",
                NotificationDate = DateTime.Now,
                IsRead = false,
                NotificationType = "DeleteTask"
            });
            data.SubmitChanges();
            using (var context = new QLCVDataContext())
            {
                
                var task = context.Tasks.FirstOrDefault(t => t.TaskID == taskId);
                if (task == null)
                {
                    return HttpNotFound("Task not found.");
                }

                var subTasks = context.Tasks.Where(t => t.ParentTaskID == taskId).ToList();
                if (subTasks.Any())
                {
                   
                    return Json(new { success = false, message = "Cannot delete task because it has sub-tasks." }, JsonRequestBehavior.AllowGet);
                }

                var taskAssignments = context.TaskAssignments
                    .Where(ta => ta.TaskID == taskId)
                    .ToList();

                foreach (var assignment in taskAssignments)
                {
                    context.TaskAssignments.DeleteOnSubmit(assignment);
                }

                var taskLogs = context.TaskLogs
                    .Where(tl => tl.TaskID == taskId)
                    .ToList();

                foreach (var log in taskLogs)
                {
                    context.TaskLogs.DeleteOnSubmit(log);
                }

                context.Tasks.DeleteOnSubmit(task);

                context.SubmitChanges();

                return RedirectToAction("DSTask", new { projectId = task.ProjectID, notificationMessage = "Task deleted successfully!", notificationType = "success" });
            }
        }
        //Them Subtask
        [HttpPost]
        public ActionResult CreateSubTask(SubTask subTask)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    subTask.Status = subTask.Status ?? "Pending";

                    var newTask = new Task
                    {
                        TaskName = subTask.TaskName,
                        Status = subTask.Status,
                        Description = subTask.Description,
                        ProjectID = subTask.ProjectID,
                        ParentTaskID = subTask.ParentTaskID, 
                        createBy = subTask.createBy,
                        StartDate = subTask.StartDate,
                        EndDate = subTask.EndDate                        
                    };

                    data.Tasks.InsertOnSubmit(newTask);
                    data.SubmitChanges();

                    int newTaskId = newTask.TaskID;

                    var taskAssignment = new TaskAssignment
                    {
                        TaskID = newTaskId, 
                        MemberID = subTask.MemberID, 
                        AssignedBy = subTask.createBy,
                        AssignedDate = DateTime.Now,
                        Status = subTask.Status
                    };
                    data.TaskAssignments.InsertOnSubmit(taskAssignment);
                    data.SubmitChanges();

                    return Json(new { success = true, taskId = newTask.TaskID });
                }
                return Json(new { success = false, message = "Invalid data provided." });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }
        //Xoa SubTask
        [HttpPost]
        public ActionResult DeleteSubTask(int taskId)
        {
            try
            {
                var task = data.Tasks.FirstOrDefault(t => t.TaskID == taskId);
                if (task == null)
                {
                    return Json(new { success = false, message = "Task not found." });
                }
                var taskAssignments = data.TaskAssignments.Where(ta => ta.TaskID == taskId).ToList();

                if (taskAssignments.Any(ta => ta.MemberID != "0"))
                {
                    return Json(new { success = false, message = "Cannot delete Có member trong Task Assignment." });
                }

                if (taskAssignments.Any())
                {
                    data.TaskAssignments.DeleteAllOnSubmit(taskAssignments);
                }

                data.Tasks.DeleteOnSubmit(task);
                data.SubmitChanges();

                return Json(new { success = true, message = "Task and related assignments deleted successfully." });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }
        //Addmember to task
        public ActionResult AssignEmployee(string memberId, int taskId, string assignedByID)
        {
            try
            {
                var task = data.Tasks.FirstOrDefault(t => t.TaskID == taskId);
                if (task == null)
                {
                    return Json(new { success = false, message = "Task not found." });
                }

                var member = data.Members.FirstOrDefault(m => m.MemberID == memberId);
                if (member == null)
                {
                    return Json(new { success = false, message = "Member not found." });
                }

                var existingAssignment = data.TaskAssignments
                    .FirstOrDefault(ta => ta.TaskID == taskId && ta.MemberID == memberId);

                if (existingAssignment != null)
                {

                    return Json(new { success = false, message = "This member is already assigned to the task." });
                }

                var taskAssignment = new TaskAssignment
                {
                    TaskID = taskId,
                    MemberID = memberId,
                    AssignedBy = assignedByID,  
                    AssignedDate = DateTime.Now,
                    Status = "Assigned"  
                };
                data.TaskAssignments.InsertOnSubmit(taskAssignment);
               

                var MemberAssigned  = data.Members.FirstOrDefault(t => t.MemberID== assignedByID);
                var Project = data.Projects.FirstOrDefault(t => t.ProjectID == task.ProjectID);

                data.Notifications.InsertOnSubmit(new Notification
                {
                    MemberID = memberId,
                    Content = $"Bạn đã được phân công tham gia vào Task '{task.TaskName}' trong dự án '{Project.ProjectName}' bởi '{MemberAssigned.FullName}'  '{MemberAssigned.Role}' ",
                    NotificationDate = DateTime.Now,
                    IsRead = false,
                    NotificationType = "JoinTaskAccepted"
                });
                data.SubmitChanges();

                return Json(new { success = true });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }
        // delete member in task
        [HttpPost]
        public ActionResult DeleteTaskAssignment(int taskId, string memberId)
        {
            try
            {
                var taskAssignment = data.TaskAssignments
                    .FirstOrDefault(ta => ta.TaskID == taskId && ta.MemberID == memberId);

                if (taskAssignment == null)
                {
                    return Json(new { success = false, message = "Task assignment not found." });
                }
                data.TaskAssignments.DeleteOnSubmit(taskAssignment);
                data.SubmitChanges();
                return Json(new { success = true });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }
        #endregion

        #region CHAT
        //Load Chat
        public ActionResult GroupChat(string projectId, int page = 1)
        {
            int pageSize = 6;
            var interactions = data.Interactions
                .Where(i => i.ProjectID == projectId)
                .OrderByDescending(i => i.IsPinned) 
                .ThenByDescending(i => i.InteractionDate) 
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToList();

            var project = data.Projects.FirstOrDefault(p => p.ProjectID == projectId);
            if (project == null)
            {
                return HttpNotFound("Project not found.");
            }

            int totalChatCount = data.Interactions.Count(i => i.ProjectID == projectId);
            int totalPages = (int)Math.Ceiling((double)totalChatCount / pageSize);

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
            string memberID = Session["MemberID"]?.ToString();
            if (!string.IsNullOrEmpty(Message) && !string.IsNullOrEmpty(memberID) && !string.IsNullOrEmpty(ProjectID))
            {         
                var interaction = new Interaction
                {
                    ProjectID = ProjectID,
                    MemberID = memberID,
                    InteractionDate = DateTime.Now,
                    Message = Message,
                    IsPinned = false
                };
                data.Interactions.InsertOnSubmit(interaction);
                data.SubmitChanges();
            }
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
                message.IsPinned = true;
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
                interaction.IsPinned = !(interaction.IsPinned ?? false);
                data.SubmitChanges();
                return Json(new { success = true });
            }
            return Json(new { success = false });
        }
        #endregion

        #region MEMBER
        //Load DS member
        [RoleAuthorization("Admin", "HR")]
        public ActionResult DSMember(string searchQuery, string role, string status, int page = 1, int pageSize = 3)
        {
            var members = data.Members.Where(m => m.MemberID != "0").AsQueryable();
            if (!string.IsNullOrEmpty(searchQuery))
            {
                members = members.Where(m => m.FullName.Contains(searchQuery) || m.Email.Contains(searchQuery));
            }
            if (!string.IsNullOrEmpty(role))
            {
                members = members.Where(m => m.Role == role);
            }
            if (!string.IsNullOrEmpty(status))
            {
                bool isActive = status == "true";
                members = members.Where(m => m.Status == "Active");
            }
            int totalRecords = members.Count();

            var pagedMembers = members
                .OrderBy(m => m.MemberID)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToList();

            ViewBag.SearchQuery = searchQuery;
            ViewBag.Role = role;
            ViewBag.Status = status;
            ViewBag.TotalRecords = totalRecords;
            ViewBag.PageSize = pageSize;
            ViewBag.CurrentPage = page;

            return View(pagedMembers);
        }
        // Ham tao ID thanh vien 
        public string GenerateMemberID()
        {
           
            DateTime now = DateTime.Now;
            string formattedTime = now.ToString("HHmmssddMMyy");
            return formattedTime;
        }
        //Kiem tra trung MemberID
        public string GetUniqueMemberID()
        {
            string memberIDnew;
            bool isUnique;

            do
            {
                memberIDnew = GenerateMemberID();
                isUnique = !data.Members.Any(m => m.MemberID == memberIDnew); 
            }
            while (!isUnique); 

            return memberIDnew;
        }
        //Add Member
        [HttpPost]
        public ActionResult AddMember(string FullName, string Email, string Phone, string Role, string Password, string ImageMember, string HireDate, HttpPostedFileBase ImageFile)
        {
            try
            {
                string imagePath = null;
                if (ImageFile != null && ImageFile.ContentLength > 0)
                {
                    string fileName = Path.GetFileNameWithoutExtension(ImageFile.FileName);
                    string extension = Path.GetExtension(ImageFile.FileName);
                    string uniqueFileName = fileName + "_" + Guid.NewGuid() + extension;
                    string path = Server.MapPath("~/Content/images/member-img/");
                    Directory.CreateDirectory(path); 
                    imagePath = Path.Combine(path, uniqueFileName);
                    ImageFile.SaveAs(imagePath);
                    ImageMember = uniqueFileName;
                }

                string encryptedPassword = EncryptPassword(Password, "mysecretkey");

                DateTime hireDate = DateTime.Parse(HireDate);

                string newMemberId = GetUniqueMemberID();

                var member = new Member
                {
                    MemberID = newMemberId,
                    FullName = FullName,
                    Email = Email,
                    Phone = Phone,
                    Role = Role,
                    HireDate = hireDate,
                    Status = "Offline",
                    Password = encryptedPassword,
                    ImageMember = ImageMember,
                    ExpiryTime = null
                };

                data.Members.InsertOnSubmit(member);

                var welcomeNotification = new Notification
                {
                    MemberID = newMemberId,
                    Content = "Chào mừng bạn đến với công ty. Chúc bạn có một hành trình tuyệt vời cùng với chúng tôi",
                    NotificationDate = DateTime.Now,
                    IsRead = false,
                    NotificationType = "Welcome"
                };

                data.Notifications.InsertOnSubmit(welcomeNotification);

                data.SubmitChanges();

                return RedirectToAction("DSMember", "Home");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return RedirectToAction("DSMember", new { notificationMessage = "Đã xảy ra lỗi khi thêm thành viên!", notificationType = "error" });
            }
        }
        //Edit Member
        [HttpPost]
        public ActionResult EditMember(string MemberID, string FullName, string Email, string Phone, string Role, string Password, string ImageMember, string HireDate, HttpPostedFileBase ImageFile)
        {
            if (!ModelState.IsValid)
            {
                return RedirectToAction("DSMember", new { notificationMessage = "Dữ liệu không hợp lệ", notificationType = "error" });
            }
            try
            {
                var member = data.Members.FirstOrDefault(m => m.MemberID == MemberID);
                if (member == null)
                {
                    throw new Exception("Không tìm thấy thành viên với ID này.");
                }

                if (ImageFile != null && ImageFile.ContentLength > 0)
                {
                    string fileName = Path.GetFileNameWithoutExtension(ImageFile.FileName);
                    string extension = Path.GetExtension(ImageFile.FileName);
                    string uniqueFileName = fileName + "_" + Guid.NewGuid() + extension;
                    string path = Server.MapPath("~/Content/images/member-img/");
                    Directory.CreateDirectory(path); 
                    string imagePath = Path.Combine(path, uniqueFileName);
                    ImageFile.SaveAs(imagePath);

                    member.ImageMember = uniqueFileName;
                }
  
                member.FullName = FullName;
                member.Email = Email;
                member.Phone = Phone;
                member.Role = Role;

             
                if (!string.IsNullOrEmpty(Password))
                {
                    member.Password = EncryptPassword(Password, "your-secret-key"); 
                }

                member.HireDate = DateTime.Parse(HireDate);

                data.SubmitChanges();

                return RedirectToAction("DSMember", "Home", new { notificationMessage = "Cập nhật thành viên thành công!", notificationType = "success" });
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return RedirectToAction("DSMember", new { notificationMessage = "Đã xảy ra lỗi khi sửa thành viên!", notificationType = "error" });
            }
        }
        //Xoa member
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
        [HttpPost]
        public JsonResult EditProfile(string FullName, DateTime? BirthDate, string Email, string Phone, string Address, HttpPostedFileBase ImageFile)
        {
            try
            {
                var memberId = Session["MemberID"]?.ToString();
                if (string.IsNullOrEmpty(memberId))
                {
                    return Json(new { success = false, message = "Không tìm thấy thông tin phiên đăng nhập" });
                }

                var member = data.Members.FirstOrDefault(m => m.MemberID == memberId);
                if (member == null)
                {
                    return Json(new { success = false, message = "Không tìm thấy thông tin thành viên" });
                }

                member.FullName = FullName;
                member.DateOfBirth = BirthDate;
                member.Email = Email;
                member.Phone = Phone;
                member.Address = Address;

                if (ImageFile != null && ImageFile.ContentLength > 0)
                {
                    if (ImageFile.ContentLength > 1048576)
                    {
                        return Json(new { success = false, message = "Kích thước file không được vượt quá 1MB" });
                    }

                    var allowedExtensions = new[] { ".jpg", ".jpeg", ".png" };
                    var fileExtension = Path.GetExtension(ImageFile.FileName).ToLower();
                    if (!allowedExtensions.Contains(fileExtension))
                    {
                        return Json(new { success = false, message = "Chỉ chấp nhận file định dạng .JPG, .PNG" });
                    }

                    if (!string.IsNullOrEmpty(member.ImageMember))
                    {
                        var oldImagePath = Path.Combine(Server.MapPath("~/Content/images/member-img"), member.ImageMember);
                        if (System.IO.File.Exists(oldImagePath))
                        {
                            System.IO.File.Delete(oldImagePath);
                        }
                    }

                    var fileName = $"member_{Guid.NewGuid()}{fileExtension}";
                    var path = Path.Combine(Server.MapPath("~/Content/images/member-img"), fileName);
                    ImageFile.SaveAs(path);

                    member.ImageMember = fileName;
                }

                data.SubmitChanges();

                Session["FullName"] = member.FullName;
                Session["DateOfBirth"] = member.DateOfBirth;
                Session["Email"] = member.Email;
                Session["Phone"] = member.Phone;
                Session["Address"] = member.Address;
                if (ImageFile != null && ImageFile.ContentLength > 0)
                {
                    Session["ImageMember"] = member.ImageMember;
                }

                return Json(new { success = true, message = "Cập nhật thông tin thành công" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = "Lỗi khi cập nhật: " + ex.Message });
            }
        }
        #endregion

        #region TIENDO
        public ActionResult TienDoTask(string projectID)
        {
            var taskLogs = data.TaskLogs
                .Join(data.Tasks,
                      tl => tl.TaskID,
                      t => t.TaskID,
                      (tl, t) => new { tl, t })
                .Where(joined => joined.t.ProjectID == projectID) 
                .Select(joined => new TaskLogViewModel
                {
                    LogID = joined.tl.LogID,
                    TaskID = joined.tl.TaskID,
                    TaskName = joined.t.TaskName, 
                    Status = joined.tl.Status,
                    LogDate = joined.tl.LogDate,
                    Note = joined.tl.Note,
                })
                .ToList();

            return View(taskLogs);
        }

        #endregion

        #region REPORT
        //Load view 
        [RoleAuthorization("Admin", "Manager", "HR")]
        public ActionResult BaoCaoThongKe()
        {
            return View();
        }
        //Lay du lieu Filter
        [HttpGet]
        public JsonResult GetFilterOptions()
        {
            try
            {
                var projects = data.Projects
                    .Where(p => p.deleteTime == null)
                    .Select(p => new
                    {
                        ProjectID = p.ProjectID,
                        ProjectName = p.ProjectName
                    })
                    .ToList();

                var members = data.Members
                    .Select(m => new
                    {
                        MemberID = m.MemberID,
                        FullName = m.FullName
                    })
                    .ToList();

                return Json(new
                {
                    success = true,
                    projects = projects,
                    members = members
                }, JsonRequestBehavior.AllowGet);
            }
            catch (Exception ex)
            {
                return Json(new
                {
                    success = false,
                    message = ex.Message
                }, JsonRequestBehavior.AllowGet);
            }
        }
        //Lay du lieu report
        [HttpGet]
        public JsonResult GetReportData(string projectId, string memberId, DateTime? startDate, DateTime? endDate)
        {
            try
            {
                var tasksQuery = data.Tasks.AsQueryable();
                if (!string.IsNullOrEmpty(projectId))
                {
                    tasksQuery = tasksQuery.Where(t => t.ProjectID == projectId);
                }
                if (!string.IsNullOrEmpty(memberId))
                {
                    tasksQuery = tasksQuery.Where(t => t.TaskAssignments.Any(ta => ta.MemberID == memberId));
                }
                if (startDate.HasValue)
                {
                    tasksQuery = tasksQuery.Where(t => t.StartDate >= startDate);
                }
                if (endDate.HasValue)
                {
                    tasksQuery = tasksQuery.Where(t => t.EndDate <= endDate);
                }
                var totalProjects = data.Projects.Count(p => p.deleteTime == null);
                var completedTasks = tasksQuery.Count(t => t.Status == "Completed" && t.ParentTaskID != null);
                var inProgressTasks = tasksQuery.Count(t => t.Status == "Pending" && t.ParentTaskID != null);
                var overdueTasks = tasksQuery.Count(t => t.EndDate < DateTime.Now && t.Status != "Completed" && t.ParentTaskID != null);

                var projectProgress = data.Projects
                    .Where(p => p.deleteTime == null)
                    .Select(p => new
                    {
                        projectName = p.ProjectName,
                        totalTasks = p.Tasks.Count(t => t.ParentTaskID != null),
                        completedTasks = p.Tasks.Count(t => t.ParentTaskID != null && t.Status == "Completed")
                    })
                    .ToList();


                var taskDistribution = data.TaskAssignments
                .Where(ta => ta.Status != "Assigned"
                            && ta.MemberID != "0"
                            && ta.MemberID != ta.AssignedBy
                            && (string.IsNullOrEmpty(projectId) || ta.Task.ProjectID == projectId))
                .GroupBy(ta => ta.MemberID) 
                .Select(g => new
                {
                    memberId = g.Key, 
                    memberName = data.Members 
                                 .Where(m => m.MemberID == g.Key)
                                 .Select(m => m.FullName)
                                 .FirstOrDefault(),
                    taskCount = g.Count()
                })
                .ToList();

                
                var taskDistributionByAssigner = data.TaskAssignments
                .Where(ta => ta.AssignedBy != null && ta.Status != "Assigned" && ta.Task.ParentTaskID != null &&
                            (string.IsNullOrEmpty(projectId) || ta.Task.ProjectID == projectId))
                .GroupBy(ta => new
                {
                    AssignerId = ta.AssignedBy,
                    AssignerName = data.Members
                                        .Where(m => m.MemberID == ta.AssignedBy)
                                        .Select(m => m.FullName)
                                        .FirstOrDefault()
                })
                .Select(g => new
                {
                    memberName = g.Key.AssignerName,
                    memberId = g.Key.AssignerId,
                    taskCount = g.Count()
                })
                .ToList();


                
                var detailedReport = tasksQuery
                .Select(t => new
                {
                    projectId = t.Project.ProjectID,
                    projectName = t.Project.ProjectName,
                    parentTaskId = t.ParentTaskID,
                    taskId = t.TaskID,
                    taskName = t.ParentTaskID == null
                        ? t.TaskName
                        : t.Description, 
                    assignedTo = t.ParentTaskID == null
                        ? "Task chính" 
                        : (from ta in t.TaskAssignments
                           join m in data.Members on ta.MemberID equals m.MemberID 
                           where ta.MemberID != null && ta.MemberID != "0"
                           orderby ta.MemberID 
                           select m.FullName) 
                            .FirstOrDefault() ?? "Chưa phân công", 
                    status = t.Status,
                    startDate = t.StartDate,
                    endDate = t.EndDate,
                    progress = t.ParentTaskID != null 
                        ? (t.Status == "Completed" ? 100 : 0) 
                        : (tasksQuery.Where(st => st.ParentTaskID == t.TaskID).Any() 
                            ? (tasksQuery.Where(st => st.ParentTaskID == t.TaskID && st.Status == "Completed").Count() * 100.0 /
                               tasksQuery.Where(st => st.ParentTaskID == t.TaskID).Count()) 
                            : 0), 
                    subTaskIds = t.ParentTaskID == null 
                        ? tasksQuery.Where(st => st.ParentTaskID == t.TaskID)
                                    .Select(st => st.TaskID)
                                    .ToList() 
                        : null 
                })
                .OrderBy(t => t.projectId) 
                .ThenBy(t => t.parentTaskId == null ? t.taskId : t.parentTaskId)
                .ThenBy(t => t.taskId) 
                .ToList();






                return Json(new
                {
                    success = true,
                    totalProjects,
                    completedTasks,
                    inProgressTasks,
                    overdueTasks,
                    projectProgress,
                    taskDistribution,
                    taskDistributionByAssigner,  
                    detailedReport
                }, JsonRequestBehavior.AllowGet);
            }
            catch (Exception ex)
            {
                return Json(new
                {
                    success = false,
                    message = ex.Message
                }, JsonRequestBehavior.AllowGet);
            }
        }
        //Tao report
        [HttpPost]
        public JsonResult CreateReport(string projectId, string generatedBy, string summary)
        {
            try
            {
                // Kiểm tra generatedBy
                if (string.IsNullOrEmpty(generatedBy))
                {
                    return Json(new { success = false, message = "Member ID is required" });
                }

                var report = new Report
                {
                    ProjectID = projectId,  
                    GeneratedBy = generatedBy,
                    ReportDate = DateTime.Now,
                    Summary = summary
                };

                data.Reports.InsertOnSubmit(report);
                data.SubmitChanges();

                return Json(new { success = true });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }
        #endregion

        #region TRANSFER
        //Chuyen subtask
        [HttpPost]
        public JsonResult TransferTask(string fromMemberId, string toMemberId, int[] taskIds)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"Received transfer request: From={fromMemberId}, To={toMemberId}, Tasks={string.Join(",", taskIds ?? new int[0])}");
                if (string.IsNullOrEmpty(fromMemberId) || string.IsNullOrEmpty(toMemberId))
                {
                    return Json(new { success = false, message = "Member IDs cannot be empty." });
                }

                if (taskIds == null || taskIds.Length == 0)
                {
                    return Json(new { success = false, message = "No tasks selected for transfer." });
                }

                var fromMember = data.Members.FirstOrDefault(m => m.MemberID == fromMemberId);
                var toMember = data.Members.FirstOrDefault(m => m.MemberID == toMemberId);

                if (fromMember == null || toMember == null)
                {
                    return Json(new { success = false, message = "Invalid members." });
                }

                var transferredTasks = new List<string>();
                var notifications = new List<Notification>();

                foreach (var taskId in taskIds)
                {
                    var task = data.Tasks.FirstOrDefault(t => t.TaskID == taskId);
                    if (task == null) continue;

                    var currentAssignment = data.TaskAssignments
                        .FirstOrDefault(ta => ta.TaskID == taskId && ta.MemberID == fromMemberId);

                    if (currentAssignment == null) continue;

                    var newAssignment = new TaskAssignment
                    {
                        TaskID = taskId,
                        MemberID = toMemberId,
                        AssignedBy = Session["MemberID"]?.ToString(),
                        AssignedDate = DateTime.Now,
                        Status = "Pending",
                        Note = $"Transferred from {fromMember.FullName}"
                    };
                    notifications.Add(new Notification
                    {
                        MemberID = fromMemberId,
                        Content = $"Task '{task.Description ?? $"Task {taskId}"}' has been transferred to {toMember.FullName}",
                        NotificationDate = DateTime.Now,
                        IsRead = false,
                        NotificationType = "TaskTransferred"
                    });
                    notifications.Add(new Notification
                    {
                        MemberID = toMemberId,
                        Content = $"You have been assigned task '{task.Description ?? $"Task {taskId}"}' transferred from {fromMember.FullName}",
                        NotificationDate = DateTime.Now,
                        IsRead = false,
                        NotificationType = "TaskReceived"
                    });

                    transferredTasks.Add(task.Description ?? $"Task {taskId}");
                    data.TaskAssignments.InsertOnSubmit(newAssignment);
                    data.TaskAssignments.DeleteOnSubmit(currentAssignment);
                }

                if (transferredTasks.Count == 0)
                {
                    return Json(new { success = false, message = "No tasks were eligible for transfer." });
                }
                data.Notifications.InsertAllOnSubmit(notifications);

                data.SubmitChanges();

                var tasksMessage = string.Join(", ", transferredTasks);
                return Json(new
                {
                    success = true,
                    message = $"Successfully transferred tasks ({tasksMessage}) from {fromMember.FullName} to {toMember.FullName}"
                });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = $"Error during transfer: {ex.Message}" });
            }
        }
        //Lay member subtask
        [HttpGet]
        public JsonResult GetMemberSubtasks(int parentTaskId, string memberId)
        {
            try
            {
                var tasks = data.Tasks
                    .Where(t => t.ParentTaskID == parentTaskId)
                    .Where(t => t.TaskAssignments.Any(ta => ta.MemberID == memberId))
                    .Select(t => new
                    {
                        t.TaskID,
                        t.Description,
                        t.Status
                    })
                    .ToList();

                return Json(new { success = true, tasks = tasks }, JsonRequestBehavior.AllowGet);
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message }, JsonRequestBehavior.AllowGet);
            }
        }

        [HttpGet]
        public JsonResult GetOverdueTasks()
        {
            try
            {
                var today = DateTime.Now;
                var overdueTasks = data.Tasks
                    .Where(t => t.EndDate < today && t.Status != "Completed" && t.ParentTaskID != null)
                    .Join(data.Projects, // Thực hiện phép nối với bảng Projects
                        task => task.ProjectID, // Khóa ngoại từ bảng Tasks
                        project => project.ProjectID, // Khóa chính từ bảng Projects
                        (task, project) => new // Tạo đối tượng mới với thông tin cần thiết
                        {
                            taskDes = task.Description,
                            dueDate = task.EndDate,
                            projectName = project.ProjectName // Lấy tên dự án
                        })
                    .ToList();

                return Json(new { success = true, tasks = overdueTasks }, JsonRequestBehavior.AllowGet);
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message }, JsonRequestBehavior.AllowGet);
            }
        }
        #endregion

       
    }
}

    