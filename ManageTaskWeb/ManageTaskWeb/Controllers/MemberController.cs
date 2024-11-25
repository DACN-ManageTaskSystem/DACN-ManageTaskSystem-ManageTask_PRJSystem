using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using ManageTaskWeb.Models;
using System.IO;

namespace ManageTaskWeb.Controllers
{
    public class MemberController : Controller
    {
        QLCVDataContext data = new QLCVDataContext();

        public string GenerateUniqueMemberID()
        {
            string prefix = "MEM"; // Tiền tố cho ID thành viên
            const string chars = "0123456789"; // Các ký tự ngẫu nhiên
            var random = new Random();
            var randomString = new string(Enumerable.Repeat(chars, 6) // 6 ký tự ngẫu nhiên
                .Select(s => s[random.Next(s.Length)]).ToArray());
            return randomString;
        }

        public string GetUniqueMemberID()
        {
            string memberIDnew;
            bool isUnique;

            do
            {
                memberIDnew = GenerateUniqueMemberID();  // Tạo ID ngẫu nhiên mới
                isUnique = !data.Members.Any(m => m.MemberID == memberIDnew);  // Kiểm tra xem ID đã tồn tại trong cơ sở dữ liệu chưa
            }
            while (!isUnique);  // Tiếp tục tạo ID mới nếu ID trùng lặp

            return memberIDnew;
        }

        [HttpPost]
        public ActionResult AddMember(string FullName, string Email, string Phone, string Role, string Password, string ImageMember, HttpPostedFileBase ImageFile)
        {
            try
            {

                string imagePath = null;
                if (ImageFile != null && ImageFile.ContentLength > 0)
                {
                    // Lưu ảnh vào thư mục
                    string path = Server.MapPath("~/Content/images/member-img/");
                    Directory.CreateDirectory(path); // Tạo thư mục nếu chưa có
                    imagePath = Path.Combine(path, ImageMember);
                    ImageFile.SaveAs(imagePath);
                }

                // Tạo đối tượng Member mới và lưu thông tin
                var member = new Member
                {
                    MemberID = GetUniqueMemberID(), // Tạo ID duy nhất (có thể dùng hàm tự tạo như MemberID định dạng HHmmssddMMyy)
                    FullName = FullName,
                    Email = Email,
                    Phone = Phone,
                    Role = Role,
                    HireDate = System.DateTime.Now,
                    Status = "Offline",
                    Password = Password, // Lưu mật khẩu
                    ImageMember = ImageMember, // Lưu tên file ảnh
                };

                // Thêm member vào database
                data.Members.InsertOnSubmit(member);
                data.SubmitChanges();
                return RedirectToAction("DSMember", "Home");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return RedirectToAction("DSMember", new { notificationMessage = "Đã xảy ra lỗi khi thêm thành viên!", notificationType = "error" });
            }
        }

    }
}
