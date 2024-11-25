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
using System.Net;
using System.Configuration;
using Newtonsoft.Json.Linq;

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

        #region MA-HOA
        //Ma hoa
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
        //Giai ma
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

            var member = data.Members.FirstOrDefault(m => m.MemberID == username && m.deleteTime == null);

            if (member == null)
            {
                ViewBag.ErrorMessage = "*Tên đăng nhập hoặc mật khẩu không đúng.";
                return View();
            }

            // Giải mã mật khẩu
            string decryptedPassword = DecryptPassword(member.Password, "mysecretkey");

            // Kiểm tra mật khẩu và thời gian hết hạn
            if (decryptedPassword != password)
            {
                ViewBag.ErrorMessage = "*Tên đăng nhập hoặc mật khẩu không đúng.";
                return View();
            }

            // Kiểm tra thời gian hết hạn nếu có
            if (member.ExpiryTime.HasValue && DateTime.Now > member.ExpiryTime.Value)
            {
                ViewBag.ErrorMessage = "*Mật khẩu tạm thời đã hết hạn. Vui lòng yêu cầu mật khẩu mới.";
                return View();
            }

            member.Status = "Active";
            data.SubmitChanges();

            // Nếu đăng nhập thành công, lưu thông tin vào session
            Session["Password"] = decryptedPassword;
            Session["MemberID"] = member.MemberID;
            Session["FullName"] = member.FullName;
            Session["Role"] = member.Role;
            Session["Email"] = member.Email;
            Session["Phone"] = member.Phone;
            Session["ImageMember"] = member.ImageMember;

                if (member.ExpiryTime.HasValue)
                {
                    return RedirectToAction("ChangePassword");
                }
            // Chuyển hướng về trang chủ sau khi đăng nhập thành công
            return RedirectToAction("TrangChu");
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

            // Kiểm tra mật khẩu cũ với database
            if (EncryptPassword(oldPassword, "mysecretkey") != currentMember.Password)
            {
                ViewBag.ErrorMessage = "Old password is incorrect.";
                return View();
            }

            // Kiểm tra quy tắc mật khẩu mạnh
            if (!IsStrongPassword(newPassword))
            {
                ViewBag.ErrorMessage = "Password must be at least 8 characters long and contain: uppercase letter, lowercase letter, number, and special character.";
                return View();
            }

            currentMember.Password = EncryptPassword(newPassword, "mysecretkey");
            currentMember.ExpiryTime = null; // Xóa giá trị ExpiryTime
            data.SubmitChanges();

            return View("TrangChu");
        }

        private bool IsStrongPassword(string password)
        {
            // Kiểm tra độ dài tối thiểu
            if (password.Length < 8) return false;

            // Kiểm tra các yêu cầu về ký tự
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
                //// Verify reCAPTCHA
                //var response = Request["g-recaptcha-response"];
                //string secretKey = ConfigurationManager.AppSettings["reCaptcha:SecretKey"];
                //var client = new WebClient();

                //var result = client.DownloadString(string.Format(
                //    "https://www.google.com/recaptcha/api/siteverify?secret={0}&response={1}",
                //    secretKey, response));

                //var obj = JObject.Parse(result);
                //var status = (bool)obj.SelectToken("success");

                //if (!status)
                //{
                //    ViewBag.Message = "Please verify that you are not a robot.";
                //    ViewBag.IsError = true;
                //    return View();
                //}

                var member = data.Members.FirstOrDefault(m =>
                    m.MemberID == memberID &&
                    m.Email == email &&
                    m.deleteTime == null);

                if (member == null)
                {
                    ViewBag.IsError = true;
                    ViewBag.Message = "Invalid Member ID or Email";
                    return View();
                }

                // Tạo mật khẩu mới ngẫu nhiên
                string newPassword = GenerateRandomPasswordForgot();

                // Đặt thời gian hết hạn (10 phút từ hiện tại)
                DateTime expiryTime = DateTime.Now.AddMinutes(10);

                // Cập nhật mật khẩu và thời gian hết hạn trong database
                member.Password = EncryptPassword(newPassword, "mysecretkey");
                member.ExpiryTime = expiryTime;
                data.SubmitChanges();

                // Gửi email với thông tin về thời gian hết hạn
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
                string body = $@"Your temporary password is: {newPassword}
                        
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
        //Cap nhat trang thai read - unread
        [HttpPost]
        public JsonResult ToggleNotificationStatus(int notificationId, bool currentIsRead)
        {
            try
            {
                // Lấy notification từ database
                var notification = data.Notifications.FirstOrDefault(n => n.NotificationID == notificationId);
                if (notification != null)
                {
                    // Toggle trạng thái Read
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

                // Tạo thng báo cho người bị từ chối
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
        #endregion

        #region PROJECT
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
                                   Description =p.Description,
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
        public ActionResult AddProject(string ProjectName, string Description, DateTime StartDate, DateTime EndDate, int Priority, string Status, HttpPostedFileBase ImageFile)
        {
            try
            {
                string imageFileName = null;

                // Xử lý file ảnh nếu có
                if (ImageFile != null && ImageFile.ContentLength > 0)
                {
                    // Kiểm tra định dạng file
                    var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif" };
                    var extension = Path.GetExtension(ImageFile.FileName).ToLower();
                    if (!allowedExtensions.Contains(extension))
                    {
                        return RedirectToAction("DSProject", new { notificationMessage = "Chỉ chấp nhận file ảnh có định dạng: .jpg, .jpeg, .png, .gif!", notificationType = "error" });
                    }

                    // Tạo tên file duy nhất
                    imageFileName = $"project_{Guid.NewGuid()}{extension}";
                    
                    // Lưu file
                    string path = Server.MapPath("~/Content/images/project-img/");
                    Directory.CreateDirectory(path);
                    string fullPath = Path.Combine(path, imageFileName);
                    ImageFile.SaveAs(fullPath);
                }

                // Tạo project mới
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
                    deleteTime = null
                };

                // Validate dữ liệu
                if (string.IsNullOrEmpty(project.ProjectName))
                {
                    return RedirectToAction("DSProject", new { notificationMessage = "Tên dự án không được để trống!", notificationType = "error" });
                }

                if (project.EndDate <= project.StartDate)
                {
                    return RedirectToAction("DSProject", new { notificationMessage = "Ngày kết thúc phải sau ngày bắt đầu!", notificationType = "error" });
                }

                // Lưu vào database
                data.Projects.InsertOnSubmit(project);
                data.SubmitChanges();

                return RedirectToAction("DSProject", new { notificationMessage = "Thêm dự án mới thành công!", notificationType = "success" });
            }
            catch (Exception ex)
            {
                // Log error
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

                // Validate dữ liệu
                if (string.IsNullOrEmpty(ProjectName?.Trim()))
                {
                    return RedirectToAction("DSProject", new { notificationMessage = "Tên dự án không được để trống!", notificationType = "error" });
                }

                if (EndDate <= StartDate)
                {
                    return RedirectToAction("DSProject", new { notificationMessage = "Ngày kết thúc phải sau ngày bắt đầu!", notificationType = "error" });
                }

                // Xử lý file ảnh mới nếu có
                if (ImageFile != null && ImageFile.ContentLength > 0)
                {
                    // Kiểm tra định dạng file
                    var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif" };
                    var extension = Path.GetExtension(ImageFile.FileName).ToLower();
                    if (!allowedExtensions.Contains(extension))
                    {
                        return RedirectToAction("DSProject", new { notificationMessage = "Chỉ chấp nhận file ảnh có định dạng: .jpg, .jpeg, .png, .gif!", notificationType = "error" });
                    }

                    // Xóa ảnh cũ nếu có
                    if (!string.IsNullOrEmpty(project.ImageProject))
                    {
                        string oldImagePath = Path.Combine(Server.MapPath("~/Content/images/project-img/"), project.ImageProject);
                        if (System.IO.File.Exists(oldImagePath))
                        {
                            System.IO.File.Delete(oldImagePath);
                        }
                    }

                    // Lưu ảnh mới
                    string newFileName = $"project_{Guid.NewGuid()}{extension}";
                    string path = Server.MapPath("~/Content/images/project-img/");
                    Directory.CreateDirectory(path);
                    string fullPath = Path.Combine(path, newFileName);
                    ImageFile.SaveAs(fullPath);

                    project.ImageProject = newFileName;
                }

                // Cập nhật thông tin project
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
                // Log error
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
        #endregion

        #region PROJECT'S MEMBER
        //Danh sach Member trong Project
        public ActionResult MembersOfProject(string projectId)
        {

            // Lấy thông tin dự án
            var project = data.Projects.FirstOrDefault(p => p.ProjectID == projectId);

            var members = data.ProjectMembers
                             .Where(pm => pm.ProjectID == projectId && pm.Status == "Accepted") // Lọc theo Status

                             .Select(pm => pm.Member)
                             .Distinct()
                             .ToList();
            ViewBag.Project = project;
            ViewBag.ProjectId = projectId;
            return View(members);
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
        //DS member khong trong du an
        public JsonResult GetNonProjectMembers(string projectId)
        {
            try
            {
                // Lấy danh sách thành viên chưa tham gia project
                var nonMembers = data.Members
                    .Where(m => m.deleteTime == null &&
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
                // Lấy danh sách thành viên đang trong project
                var projectMembers = data.ProjectMembers
                    .Where(pm => pm.ProjectID == projectId &&
                           pm.Status == "Accepted" &&
                           pm.Member.deleteTime == null)
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
        //Them member bao du an
        [HttpPost]
        public JsonResult AddMemberToProject(string projectId, string memberId)
        {
            try
            {
                // Kiểm tra xem member đã tồn tại trong project chưa
                var existingMember = data.ProjectMembers
                    .FirstOrDefault(pm => pm.ProjectID == projectId &&
                                  pm.MemberID == memberId);

                if (existingMember != null)
                {
                    return Json(new { success = false, message = "Member already exists in the project." });
                }

                // Thêm member vào project
                var projectMember = new ProjectMember
                {
                    ProjectID = projectId,
                    MemberID = memberId,
                    JoinDate = DateTime.Now,
                    Status = "Accepted"
                };

                data.ProjectMembers.InsertOnSubmit(projectMember);
                data.SubmitChanges();

                // Lấy thông tin project và member để tạo thông báo
                var project = data.Projects.FirstOrDefault(p => p.ProjectID == projectId);
                var member = data.Members.FirstOrDefault(m => m.MemberID == memberId);

                // Tạo thông báo cho member được thêm vào
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
                // Kiểm tra xem member có đang làm task nào không
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

                // Tìm và xóa member khỏi project
                var projectMember = data.ProjectMembers
                    .FirstOrDefault(pm => pm.ProjectID == projectId &&
                                  pm.MemberID == memberId);

                if (projectMember != null)
                {
                    data.ProjectMembers.DeleteOnSubmit(projectMember);
                    data.SubmitChanges();

                    // Tạo thông báo cho member bị xóa
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
            var project = data.Projects.FirstOrDefault(p=>p.ProjectID == projectId);
                
                ViewBag.ProjectStartDate = project.StartDate;
                ViewBag.ProjectEndDate = project.EndDate;
            // Kiểm tra nếu là Manager hoặc Admin, lấy tất cả task
            if (role == "Manager" || role == "Admin")
            {
                // Lấy tất cả task của dự án nhưng loại bỏ task có Priority == null
                var tasks = data.Tasks
                                .Where(t => t.ProjectID == projectId && t.Priority != null && t.ParentTaskID == null)
                                .ToList();
                return View(tasks);
            }
            else
            {
                // Chỉ lấy task mà người dùng tham gia, và loại bỏ task có Priority == null
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
        //Toggle status
        [HttpPost]
        public ActionResult ToggleStatus(int taskId, string status)
        {
            try
            {
                var task = data.Tasks.FirstOrDefault(t => t.TaskID == taskId);
                if (task == null)
                {
                    return Json(new { success = false, message = "Task not found." });
                }

                // Kiểm tra và thay đổi trạng thái
                string newStatus = status == "Done" ? "Pending" : "Done"; // Chuyển trạng thái
                task.Status = newStatus;

                // Lưu thay đổi vào cơ sở dữ liệu
                data.SubmitChanges();

                // Trả về kết quả cùng với trạng thái mới
                return Json(new { success = true, newStatus = newStatus });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        #endregion

        #region SUBTASK
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

                // Lấy danh sách các task từ cơ sở dữ liệu (có thể là các task cùng dự án hoặc các task khác có cùng ParentID, tùy yêu cầu của bạn)
                var listTasks = context.Tasks
                      .AsNoTracking()
                      .Where(t => t.ProjectID == task.ProjectID || t.ParentTaskID == task.ParentTaskID)
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
                    StartDate = task.StartDate ?? DateTime.MinValue,
                    EndDate = task.EndDate ?? DateTime.MinValue,
                    Priority = task.Priority ?? 0,
                    Status = task.Status,
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
                                          MemberID = m.MemberID,        // Correct reference to 'm'
                                          FullName = m.FullName,        // Correct reference to 'm'
                                          Role = m.Role,                // Correct reference to 'm'
                                          ImageMember = m.ImageMember  // Correct reference to 'm'
                                      }).ToList(),
                    Creator = creator,  // Assign the creator here
                    ListTasks = listTasks  // Assign the list of tasks here
                };


                return View(viewModel);
            }
        }
        //Xoa task
        [HttpPost]
        public ActionResult DeleteTaskByMember(string memberId, int taskId)
        {
            using (var context = new QLCVDataContext())
            {
                // Kiểm tra Task có tồn tại hay không
                var task = context.Tasks.FirstOrDefault(t => t.TaskID == taskId);
                if (task == null)
                {
                    return HttpNotFound("Task not found.");
                }

                // Kiểm tra nếu có MemberID tồn tại trong TaskAssignments hoặc TaskLogs
                var hasAssignmentsWithMember = context.TaskAssignments
                    .Any(ta => ta.TaskID == taskId && ta.MemberID == memberId);

                var hasLogsWithMember = context.TaskLogs
                    .Any(tl => tl.TaskID == taskId && tl.MemberID == memberId);

                if (hasAssignmentsWithMember || hasLogsWithMember)
                {
                    return Content("Cannot delete the task because there are members assigned or logs exist for this task.");
                }

                // Xóa tất cả TaskAssignments liên quan đến TaskID
                var taskAssignments = context.TaskAssignments
                    .Where(ta => ta.TaskID == taskId)
                    .ToList();

                foreach (var assignment in taskAssignments)
                {
                    context.TaskAssignments.DeleteOnSubmit(assignment);
                }

                // Xóa tất cả TaskLogs liên quan đến TaskID
                var taskLogs = context.TaskLogs
                    .Where(tl => tl.TaskID == taskId)
                    .ToList();

                foreach (var log in taskLogs)
                {
                    context.TaskLogs.DeleteOnSubmit(log);
                }

                // Xóa Task
                context.Tasks.DeleteOnSubmit(task);

                // Lưu thay đổi
                context.SubmitChanges();

                return RedirectToAction("DSTask", new { notificationMessage = "task delete successfully!", notificationType = "success" }); // Điều hướng về danh sách Task
            }
        }

        // Them Subtask
        [HttpPost]
        public ActionResult CreateSubTask(SubTask subTask)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    // Đảm bảo trạng thái mặc định
                    subTask.Status = subTask.Status ?? "Pending";

                    // Tạo Task mới
                    var newTask = new Task
                    {
                        TaskName = subTask.TaskName,
                        Status = subTask.Status,
                        Description = subTask.Description,
                        ProjectID = subTask.ProjectID,
                        ParentTaskID = subTask.ParentTaskID, // Gán ID Task cha (nếu có)
                        StartDate = DateTime.Now
                    };

                    // Lưu vào cơ sở dữ liệu
                    data.Tasks.InsertOnSubmit(newTask);
                    data.SubmitChanges();

                    return Json(new { success = true, taskId = newTask.TaskID });
                }

                // Nếu dữ liệu không hợp lệ
                return Json(new { success = false, message = "Invalid data provided." });
            }
            catch (Exception ex)
            {
                // Xử lý ngoại lệ
                return Json(new { success = false, message = ex.Message });
            }
        }
        // xóa  SubTask
        [HttpPost]
        public ActionResult DeleteSubTask(int taskId)
        {
            try
            {
                // Tìm Task trong cơ sở dữ liệu
                var task = data.Tasks.FirstOrDefault(t => t.TaskID == taskId);
                if (task == null)
                {
                    return Json(new { success = false, message = "Task not found." });
                }

                // Xóa Task khỏi cơ sở dữ liệu
                data.Tasks.DeleteOnSubmit(task);
                data.SubmitChanges();

                return Json(new { success = true, message = "Task deleted successfully." });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        // Addmember to task
        public ActionResult AssignEmployee(string memberId, int taskId, string assignedByID)
        {
            try
            {
                // Check if the task exists
                var task = data.Tasks.FirstOrDefault(t => t.TaskID == taskId);
                if (task == null)
                {
                    return Json(new { success = false, message = "Task not found." });
                }

                // Check if the member exists
                var member = data.Members.FirstOrDefault(m => m.MemberID == memberId);
                if (member == null)
                {
                    return Json(new { success = false, message = "Member not found." });
                }
                // Check if the assignment already exists in TaskAssignments table
                var existingAssignment = data.TaskAssignments
                    .FirstOrDefault(ta => ta.TaskID == taskId && ta.MemberID == memberId);

                if (existingAssignment != null)
                {
                    // If assignment already exists, return a message indicating so
                    return Json(new { success = false, message = "This member is already assigned to the task." });
                }
                // Add new Task Assignment entry
                var taskAssignment = new TaskAssignment
                {
                    TaskID = taskId,
                    MemberID = memberId,
                    AssignedBy = assignedByID,  // Assuming the current user assigns
                    AssignedDate = DateTime.Now,
                    Status = "Assigned"  // You can customize the status
                };

                // Insert new Task Assignment record into the database
                data.TaskAssignments.InsertOnSubmit(taskAssignment);
                data.SubmitChanges();

                // Return success response
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
                // Check if the task assignment exists
                var taskAssignment = data.TaskAssignments
                    .FirstOrDefault(ta => ta.TaskID == taskId && ta.MemberID == memberId);

                if (taskAssignment == null)
                {
                    return Json(new { success = false, message = "Task assignment not found." });
                }

                // Remove the task assignment
                data.TaskAssignments.DeleteOnSubmit(taskAssignment);
                data.SubmitChanges();

                // Return success response
                return Json(new { success = true });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        #endregion

        #region CHAT
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
                    Message = Message,
                    IsPinned = false
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
        //CHAT - END
        #endregion

        #region MEMBER
        //MEMBER - START
        //Load DS member
        public ActionResult DSMember(string searchQuery, string role, string status)
        {
            var roleSession = Session["Role"]?.ToString();
            var memberId = Session["MemberID"]?.ToString();
            List<Members> members;

            // Lọc ban đầu
            var query = data.Members.Where(m => m.deleteTime == null);

            // Tìm kiếm theo tên hoặc email
            if (!string.IsNullOrEmpty(searchQuery))
            {
                query = query.Where(m => m.FullName.Contains(searchQuery) || m.Email.Contains(searchQuery));
            }

            // Lọc theo vai trò
            if (!string.IsNullOrEmpty(role))
            {
                query = query.Where(m => m.Role == role);
            }

            // Lọc theo trạng thái
            if (!string.IsNullOrEmpty(status))
            {
                bool isActive = status == "true";
                query = query.Where(m => m.Status == (isActive ? "Active" : "Offline"));
            }

            // Kiểm tra quyền truy cập
            if (roleSession == "Manager" || roleSession == "Admin")
            {
                members = query
                    .Select(m => new Members
                    {
                        MemberID = m.MemberID,
                        FullName = m.FullName,
                        Email = m.Email,
                        Phone = m.Phone,
                        Role = m.Role,
                        HireDate = m.HireDate,
                        ImageMember = m.ImageMember,
                        Status = m.Status,
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
                        ImageMember = m.ImageMember,
                        Status = m.Status,
                        MemberCount = data.TaskAssignments
                            .Where(a => a.MemberID == m.MemberID)
                            .Select(a => a.TaskID)
                            .Distinct()
                            .Count()
                    })
                    .ToList();
            }

            ViewBag.SearchQuery = searchQuery;
            ViewBag.Role = role;
            ViewBag.Status = status;

            return View(members);
        }
        // Hàm tạo ID thành viên duy nhất
        public string GenerateMemberID()
        {
            // Lấy thời gian hiện tại
            DateTime now = DateTime.Now;

            // Định dạng thành chuỗi: HHmmssddMMyyyy
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
                memberIDnew = GenerateMemberID(); // Tạo ID dựa trên thời gian hiện tại
                isUnique = !data.Members.Any(m => m.MemberID == memberIDnew); // Kiểm tra xem ID đã tồn tại chưa
            }
            while (!isUnique); // Nếu trùng, tiếp tục kiểm tra

            return memberIDnew;
        }
        // Action AddMember
        [HttpPost]
        public ActionResult AddMember(string FullName, string Email, string Phone, string Role, string Password, string ImageMember, string HireDate, HttpPostedFileBase ImageFile)
        {
            try
            {
                string imagePath = null;

                // Xử lý ảnh nếu người dùng tải lên
                if (ImageFile != null && ImageFile.ContentLength > 0)
                {
                    string fileName = Path.GetFileNameWithoutExtension(ImageFile.FileName);
                    string extension = Path.GetExtension(ImageFile.FileName);
                    string uniqueFileName = fileName + "_" + Guid.NewGuid() + extension; // Tạo tên ảnh duy nhất
                    string path = Server.MapPath("~/Content/images/member-img/");
                    Directory.CreateDirectory(path); // Tạo thư mục nếu chưa có
                    imagePath = Path.Combine(path, uniqueFileName);
                    ImageFile.SaveAs(imagePath);
                    ImageMember = uniqueFileName;
                }

                // Mã hóa mật khẩu trước khi lưu vào cơ sở dữ liệu
                string encryptedPassword = EncryptPassword(Password, "mysecretkey");

                // Chuyển đổi HireDate từ string sang DateTime
                DateTime hireDate = DateTime.Parse(HireDate);

                // Tạo đối tượng Member mới và lưu thông tin
                var member = new Member
                {
                    MemberID = GetUniqueMemberID(), // Tạo ID duy nhất
                    FullName = FullName,
                    Email = Email,
                    Phone = Phone,
                    Role = Role,
                    HireDate = hireDate, // Lưu HireDate
                    Status = "Offline",
                    Password = encryptedPassword, // Lưu mật khẩu đã mã hóa
                    ImageMember = ImageMember, // Lưu tên file ảnh
                    deleteTime = null
                };

                // Thêm member vào database
                data.Members.InsertOnSubmit(member);
                data.SubmitChanges();

                // Chuyển hướng về trang DSMember sau khi thêm thành viên
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
                // Tìm thành viên cần chỉnh sửa theo MemberID
                var member = data.Members.FirstOrDefault(m => m.MemberID == MemberID);
                if (member == null)
                {
                    throw new Exception("Không tìm thấy thành viên với ID này.");
                }

                // Xử lý ảnh nếu người dùng tải lên ảnh mới
                if (ImageFile != null && ImageFile.ContentLength > 0)
                {
                    string fileName = Path.GetFileNameWithoutExtension(ImageFile.FileName);
                    string extension = Path.GetExtension(ImageFile.FileName);
                    string uniqueFileName = fileName + "_" + Guid.NewGuid() + extension;
                    string path = Server.MapPath("~/Content/images/member-img/");
                    Directory.CreateDirectory(path); // Tạo thư mục nếu chưa có
                    string imagePath = Path.Combine(path, uniqueFileName);
                    ImageFile.SaveAs(imagePath);

                    member.ImageMember = uniqueFileName;
                }

                // Cập nhật thông tin thành viên
                member.FullName = FullName;
                member.Email = Email;
                member.Phone = Phone;
                member.Role = Role;

                // Nếu có thay đổi mật khẩu, mã hóa và lưu mật khẩu mới
                if (!string.IsNullOrEmpty(Password))
                {
                    member.Password = EncryptPassword(Password, "your-secret-key"); // Mã hóa mật khẩu
                }

                // Chuyển đổi HireDate từ string sang DateTime
                member.HireDate = DateTime.Parse(HireDate);

                // Lưu thay đổi
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
        #endregion

        public ActionResult TienDoTask()
        {
            return View();
        }

        #region REPORT
        //Load view 
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
                    .Select(p => new { 
                        ProjectID = p.ProjectID, 
                        ProjectName = p.ProjectName 
                    })
                    .ToList();

                var members = data.Members
                    .Select(m => new { 
                        MemberID = m.MemberID, 
                        FullName = m.FullName 
                    })
                    .ToList();

                return Json(new { 
                    success = true, 
                    projects = projects, 
                    members = members 
                }, JsonRequestBehavior.AllowGet);
            }
            catch (Exception ex)
            {
                return Json(new { 
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
                // Query cơ bản cho tasks
                var tasksQuery = data.Tasks.AsQueryable();
                
                // Áp dụng các bộ lọc
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

                // Tính toán số liệu thống kê
                var totalProjects = data.Projects.Count(p => p.deleteTime == null);
                var completedTasks = tasksQuery.Count(t => t.Status == "Done");
                var inProgressTasks = tasksQuery.Count(t => t.Status == "In Progress");
                var overdueTasks = tasksQuery.Count(t => t.EndDate < DateTime.Now && t.Status != "Done");

                // Dữ liệu cho biểu đồ
                var projectProgress = data.Projects
                    .Where(p => p.deleteTime == null)
                    .Select(p => new {
                        projectName = p.ProjectName,
                        totalTasks = p.Tasks.Count(),
                        completedTasks = p.Tasks.Count(t => t.Status == "Done")
                    })
                    .ToList();

                var taskDistribution = data.TaskAssignments
                    .GroupBy(ta => ta.Member.FullName)
                    .Select(g => new {
                        memberName = g.Key,
                        taskCount = g.Count()
                    })
                    .ToList();

                // Chi tiết báo cáo
                var detailedReport = tasksQuery
                    .Select(t => new {
                        projectName = t.Project.ProjectName,
                        taskName = t.TaskName,
                        assignedTo = t.TaskAssignments.Select(ta => ta.Member.FullName).FirstOrDefault(),
                        status = t.Status,
                        startDate = t.StartDate,
                        endDate = t.EndDate,
                        progress = t.Status == "Done" ? 100 : 
                                  t.Status == "In Progress" ? 50 : 0
                    })
                    .ToList();

                return Json(new {
                    success = true,
                    totalProjects,
                    completedTasks,
                    inProgressTasks,
                    overdueTasks,
                    projectProgress,
                    taskDistribution,
                    detailedReport
                }, JsonRequestBehavior.AllowGet);
            }
            catch (Exception ex)
            {
                return Json(new { 
                    success = false, 
                    message = ex.Message 
                }, JsonRequestBehavior.AllowGet);
            }
        }

        #endregion
    }
}

