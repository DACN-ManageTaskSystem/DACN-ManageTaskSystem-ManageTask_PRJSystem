CREATE DATABASE [DBTM]
GO
USE [DBTM]
GO
/****** Object:  Table [dbo].[Interactions]    Script Date: 12/9/2024 9:01:37 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Interactions](
	[InteractionID] [int] IDENTITY(1,1) NOT NULL,
	[ProjectID] [nvarchar](14) NULL,
	[MemberID] [nvarchar](14) NULL,
	[InteractionDate] [datetime] NULL,
	[Message] [nvarchar](max) NULL,
	[IsPinned] [bit] NULL,
PRIMARY KEY CLUSTERED 
(
	[InteractionID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Members]    Script Date: 12/9/2024 9:01:37 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Members](
	[MemberID] [nvarchar](14) NOT NULL,
	[FullName] [nvarchar](255) NOT NULL,
	[Email] [nvarchar](255) NOT NULL,
	[Phone] [nvarchar](20) NULL,
	[Role] [nvarchar](100) NULL,
	[HireDate] [date] NULL,
	[Status] [nvarchar](50) NULL,
	[Password] [nvarchar](255) NOT NULL,
	[ImageMember] [nvarchar](255) NULL,
	[ExpiryTime] [datetime] NULL,
	[DateOfBirth] [date] NULL,
	[Address] [nvarchar](255) NULL,
PRIMARY KEY CLUSTERED 
(
	[MemberID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Notifications]    Script Date: 12/9/2024 9:01:37 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Notifications](
	[NotificationID] [int] IDENTITY(1,1) NOT NULL,
	[MemberID] [nvarchar](14) NULL,
	[Content] [nvarchar](max) NOT NULL,
	[NotificationDate] [datetime] NULL,
	[IsRead] [bit] NULL,
	[NotificationType] [nvarchar](50) NULL,
	[ExtraData] [nvarchar](max) NULL,
PRIMARY KEY CLUSTERED 
(
	[NotificationID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ProjectMembers]    Script Date: 12/9/2024 9:01:37 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ProjectMembers](
	[ProjectMemberID] [int] IDENTITY(1,1) NOT NULL,
	[ProjectID] [nvarchar](14) NULL,
	[MemberID] [nvarchar](14) NULL,
	[JoinDate] [datetime] NULL,
	[Status] [nvarchar](50) NULL,
PRIMARY KEY CLUSTERED 
(
	[ProjectMemberID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Projects]    Script Date: 12/9/2024 9:01:37 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Projects](
	[ProjectID] [nvarchar](14) NOT NULL,
	[ProjectName] [nvarchar](255) NOT NULL,
	[Description] [nvarchar](max) NULL,
	[StartDate] [date] NULL,
	[EndDate] [date] NULL,
	[Status] [nvarchar](50) NULL,
	[deleteTime] [datetime] NULL,
	[ImageProject] [nvarchar](255) NULL,
	[Priority] [int] NULL,
	[createBy] [nvarchar](255) NULL,
PRIMARY KEY CLUSTERED 
(
	[ProjectID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Reports]    Script Date: 12/9/2024 9:01:37 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Reports](
	[ReportID] [int] IDENTITY(1,1) NOT NULL,
	[ProjectID] [nvarchar](14) NULL,
	[GeneratedBy] [nvarchar](14) NULL,
	[ReportDate] [datetime] NULL,
	[Summary] [nvarchar](max) NULL,
PRIMARY KEY CLUSTERED 
(
	[ReportID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TaskAssignments]    Script Date: 12/9/2024 9:01:37 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TaskAssignments](
	[TaskAssignmentID] [int] IDENTITY(1,1) NOT NULL,
	[TaskID] [int] NOT NULL,
	[MemberID] [nvarchar](14) NOT NULL,
	[AssignedBy] [nvarchar](14) NULL,
	[AssignedDate] [datetime] NULL,
	[Status] [nvarchar](50) NULL,
	[Note] [nvarchar](max) NULL,
PRIMARY KEY CLUSTERED 
(
	[TaskAssignmentID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TaskLogs]    Script Date: 12/9/2024 9:01:37 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TaskLogs](
	[LogID] [int] IDENTITY(1,1) NOT NULL,
	[TaskID] [int] NULL,
	[Status] [nvarchar](50) NULL,
	[LogDate] [datetime] NULL,
	[Note] [nvarchar](max) NULL,
PRIMARY KEY CLUSTERED 
(
	[LogID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Tasks]    Script Date: 12/9/2024 9:01:37 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Tasks](
	[TaskID] [int] IDENTITY(1,1) NOT NULL,
	[TaskName] [nvarchar](255) NOT NULL,
	[Description] [nvarchar](max) NULL,
	[ProjectID] [nvarchar](14) NULL,
	[ParentTaskID] [int] NULL,
	[DriveLink] [nvarchar](max) NULL,
	[StartDate] [date] NULL,
	[EndDate] [date] NULL,
	[Priority] [int] NULL,
	[Status] [nvarchar](50) NULL,
	[createBy] [nvarchar](255) NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[TaskID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
SET IDENTITY_INSERT [dbo].[Interactions] ON 

INSERT [dbo].[Interactions] ([InteractionID], [ProjectID], [MemberID], [InteractionDate], [Message], [IsPinned]) VALUES (2, N'PRJ202301', N'123462010124', CAST(N'2024-12-07T11:22:50.720' AS DateTime), N'Xin chào mọi người
', 0)
INSERT [dbo].[Interactions] ([InteractionID], [ProjectID], [MemberID], [InteractionDate], [Message], [IsPinned]) VALUES (3, N'PRJ202301', N'123457010124', CAST(N'2024-12-07T11:26:55.130' AS DateTime), N'Đây là sự án mới sẽ bắt đầu vào tháng 10 năm 2024 và dự kiến sẽ kết thúc vào tháng 6 năm 2025
Mong mọi người hãy cùng nhau hợp tác và hỗ trợ nhau để dự án có thể thành công.
Xin cảm ơn !', 1)
INSERT [dbo].[Interactions] ([InteractionID], [ProjectID], [MemberID], [InteractionDate], [Message], [IsPinned]) VALUES (4, N'PRJ202301', N'123457010124', CAST(N'2024-12-07T11:27:22.193' AS DateTime), N'Thật tuyệt!', 0)
INSERT [dbo].[Interactions] ([InteractionID], [ProjectID], [MemberID], [InteractionDate], [Message], [IsPinned]) VALUES (5, N'PRJ202301', N'123462010124', CAST(N'2024-12-07T11:47:30.050' AS DateTime), N'Tôi xong việc rồi', 0)
INSERT [dbo].[Interactions] ([InteractionID], [ProjectID], [MemberID], [InteractionDate], [Message], [IsPinned]) VALUES (6, N'PRJ202301', N'123471010124', CAST(N'2024-12-07T12:57:05.210' AS DateTime), N'rất tốt hãy tiếp tục', 0)
INSERT [dbo].[Interactions] ([InteractionID], [ProjectID], [MemberID], [InteractionDate], [Message], [IsPinned]) VALUES (7, N'PRJ202301', N'123471010124', CAST(N'2024-12-07T12:57:16.723' AS DateTime), N'tôi cũng đang làm công việc của mình ', 0)
INSERT [dbo].[Interactions] ([InteractionID], [ProjectID], [MemberID], [InteractionDate], [Message], [IsPinned]) VALUES (8, N'PRJ202301', N'123471010124', CAST(N'2024-12-07T12:57:34.010' AS DateTime), N'Mọi sự thay đổi tôi đã up lên google drive rồi nhé', 0)
SET IDENTITY_INSERT [dbo].[Interactions] OFF
GO
INSERT [dbo].[Members] ([MemberID], [FullName], [Email], [Phone], [Role], [HireDate], [Status], [Password], [ImageMember], [ExpiryTime], [DateOfBirth], [Address]) VALUES (N'0', N'Anonymos', N'Anonymos.an@company.com', N'0901123456', N'Anonymos', CAST(N'2023-01-15' AS Date), N'Offline', N'WzuuRzC2bOWMEZ2gg/aBjw==', N'Anonymos.jpg', NULL, CAST(N'1990-05-15' AS Date), N'123 Đường Lê Lợi, TP.HCM')
INSERT [dbo].[Members] ([MemberID], [FullName], [Email], [Phone], [Role], [HireDate], [Status], [Password], [ImageMember], [ExpiryTime], [DateOfBirth], [Address]) VALUES (N'123456010124', N'Nguyễn Văn An', N'admin.an@company.com', N'0901123456', N'Admin', CAST(N'2023-01-15' AS Date), N'Offline', N'WzuuRzC2bOWMEZ2gg/aBjw==', N'admin1.jpg', NULL, CAST(N'1990-05-15' AS Date), N'123 Đường Lê Lợi, TP.HCM')
INSERT [dbo].[Members] ([MemberID], [FullName], [Email], [Phone], [Role], [HireDate], [Status], [Password], [ImageMember], [ExpiryTime], [DateOfBirth], [Address]) VALUES (N'123457010124', N'Trần Thị Bình', N'manager.binh@company.com', N'0902123456', N'Manager', CAST(N'2022-03-10' AS Date), N'Offline', N'WzuuRzC2bOWMEZ2gg/aBjw==', N'manager1.jpg', NULL, CAST(N'1985-07-20' AS Date), N'456 Đường Hoàng Hoa Thám, Hà Nội')
INSERT [dbo].[Members] ([MemberID], [FullName], [Email], [Phone], [Role], [HireDate], [Status], [Password], [ImageMember], [ExpiryTime], [DateOfBirth], [Address]) VALUES (N'123458010124', N'Lê Minh Quân', N'manager.quan@company.com', N'0903123456', N'Manager', CAST(N'2021-09-12' AS Date), N'Offline', N'WzuuRzC2bOWMEZ2gg/aBjw==', N'manager2.jpg', NULL, CAST(N'1988-10-10' AS Date), N'789 Đường Phan Đăng Lưu, Đà Nẵng')
INSERT [dbo].[Members] ([MemberID], [FullName], [Email], [Phone], [Role], [HireDate], [Status], [Password], [ImageMember], [ExpiryTime], [DateOfBirth], [Address]) VALUES (N'123459010124', N'Ngô Thị Hạnh', N'manager.hanh@company.com', N'0904123456', N'Manager', CAST(N'2020-06-15' AS Date), N'Offline', N'WzuuRzC2bOWMEZ2gg/aBjw==', N'manager3.jpg', NULL, CAST(N'1992-12-22' AS Date), N'12 Đường Lý Thường Kiệt, Cần Thơ')
INSERT [dbo].[Members] ([MemberID], [FullName], [Email], [Phone], [Role], [HireDate], [Status], [Password], [ImageMember], [ExpiryTime], [DateOfBirth], [Address]) VALUES (N'123460010124', N'Phạm Văn Tâm', N'manager.tam@company.com', N'0905123456', N'Manager', CAST(N'2022-12-01' AS Date), N'Offline', N'WzuuRzC2bOWMEZ2gg/aBjw==', N'manager4.jpg', NULL, CAST(N'1991-03-05' AS Date), N'34 Đường Lê Duẩn, Bình Dương')
INSERT [dbo].[Members] ([MemberID], [FullName], [Email], [Phone], [Role], [HireDate], [Status], [Password], [ImageMember], [ExpiryTime], [DateOfBirth], [Address]) VALUES (N'123461010124', N'Đỗ Thị Ngọc', N'manager.ngoc@company.com', N'0906123456', N'Manager', CAST(N'2021-08-20' AS Date), N'Offline', N'WzuuRzC2bOWMEZ2gg/aBjw==', N'manager5.jpg', NULL, CAST(N'1989-09-15' AS Date), N'67 Đường Trần Hưng Đạo, Hải Phòng')
INSERT [dbo].[Members] ([MemberID], [FullName], [Email], [Phone], [Role], [HireDate], [Status], [Password], [ImageMember], [ExpiryTime], [DateOfBirth], [Address]) VALUES (N'123462010124', N'Nguyễn Văn Khánh', N'dev.khanh@company.com', N'0907123456', N'Developer', CAST(N'2023-01-05' AS Date), N'Active', N'WzuuRzC2bOWMEZ2gg/aBjw==', N'dev1.jpg', NULL, CAST(N'1995-11-30' AS Date), N'12 Đường Nguyễn Huệ, TP.HCM')
INSERT [dbo].[Members] ([MemberID], [FullName], [Email], [Phone], [Role], [HireDate], [Status], [Password], [ImageMember], [ExpiryTime], [DateOfBirth], [Address]) VALUES (N'123463010124', N'Trần Thị Mai', N'dev.mai@company.com', N'0908123456', N'Developer', CAST(N'2023-02-10' AS Date), N'Offline', N'WzuuRzC2bOWMEZ2gg/aBjw==', N'dev2.jpg', NULL, CAST(N'1996-07-25' AS Date), N'34 Đường Pasteur, Hà Nội')
INSERT [dbo].[Members] ([MemberID], [FullName], [Email], [Phone], [Role], [HireDate], [Status], [Password], [ImageMember], [ExpiryTime], [DateOfBirth], [Address]) VALUES (N'123464010124', N'Phạm Văn Hoàng', N'dev.hoang@company.com', N'0909123456', N'Developer', CAST(N'2023-03-15' AS Date), N'Offline', N'WzuuRzC2bOWMEZ2gg/aBjw==', N'dev3.jpg', NULL, CAST(N'1994-10-05' AS Date), N'56 Đường Tô Hiến Thành, Đà Nẵng')
INSERT [dbo].[Members] ([MemberID], [FullName], [Email], [Phone], [Role], [HireDate], [Status], [Password], [ImageMember], [ExpiryTime], [DateOfBirth], [Address]) VALUES (N'123465010124', N'Đỗ Thị Thanh', N'dev.thanh@company.com', N'0910123456', N'Developer', CAST(N'2023-04-20' AS Date), N'Offline', N'WzuuRzC2bOWMEZ2gg/aBjw==', N'dev4.jpg', NULL, CAST(N'1993-05-22' AS Date), N'78 Đường Nguyễn Trãi, Cần Thơ')
INSERT [dbo].[Members] ([MemberID], [FullName], [Email], [Phone], [Role], [HireDate], [Status], [Password], [ImageMember], [ExpiryTime], [DateOfBirth], [Address]) VALUES (N'123466010124', N'Nguyễn Văn Tùng', N'dev.tung@company.com', N'0911123456', N'Developer', CAST(N'2023-05-25' AS Date), N'Offline', N'WzuuRzC2bOWMEZ2gg/aBjw==', N'dev5.jpg', NULL, CAST(N'1992-01-18' AS Date), N'90 Đường Võ Thị Sáu, Bình Dương')
INSERT [dbo].[Members] ([MemberID], [FullName], [Email], [Phone], [Role], [HireDate], [Status], [Password], [ImageMember], [ExpiryTime], [DateOfBirth], [Address]) VALUES (N'123467010124', N'Trần Thị Duyên', N'dev.duyen@company.com', N'0912123456', N'Developer', CAST(N'2023-06-30' AS Date), N'Offline', N'WzuuRzC2bOWMEZ2gg/aBjw==', N'dev6.jpg', NULL, CAST(N'1997-03-12' AS Date), N'123 Đường Nguyễn Văn Linh, Hải Phòng')
INSERT [dbo].[Members] ([MemberID], [FullName], [Email], [Phone], [Role], [HireDate], [Status], [Password], [ImageMember], [ExpiryTime], [DateOfBirth], [Address]) VALUES (N'123468010124', N'Phạm Văn Lộc', N'dev.loc@company.com', N'0913123456', N'Developer', CAST(N'2023-07-15' AS Date), N'Offline', N'WzuuRzC2bOWMEZ2gg/aBjw==', N'dev7.jpg', NULL, CAST(N'1990-09-07' AS Date), N'345 Đường Lý Tự Trọng, TP.HCM')
INSERT [dbo].[Members] ([MemberID], [FullName], [Email], [Phone], [Role], [HireDate], [Status], [Password], [ImageMember], [ExpiryTime], [DateOfBirth], [Address]) VALUES (N'123469010124', N'Nguyễn Thị Hồng', N'dev.hong@company.com', N'0914123456', N'Developer', CAST(N'2023-08-10' AS Date), N'Offline', N'WzuuRzC2bOWMEZ2gg/aBjw==', N'dev8.jpg', NULL, CAST(N'1998-12-20' AS Date), N'567 Đường Lê Quý Đôn, Hà Nội')
INSERT [dbo].[Members] ([MemberID], [FullName], [Email], [Phone], [Role], [HireDate], [Status], [Password], [ImageMember], [ExpiryTime], [DateOfBirth], [Address]) VALUES (N'123470010124', N'Trần Văn Hùng', N'dev.hung@company.com', N'0915123456', N'Developer', CAST(N'2023-09-15' AS Date), N'Offline', N'WzuuRzC2bOWMEZ2gg/aBjw==', N'dev9.jpg', NULL, CAST(N'1995-02-08' AS Date), N'789 Đường Nguyễn Đình Chiểu, Đà Nẵng')
INSERT [dbo].[Members] ([MemberID], [FullName], [Email], [Phone], [Role], [HireDate], [Status], [Password], [ImageMember], [ExpiryTime], [DateOfBirth], [Address]) VALUES (N'123471010124', N'Phạm Thị Thu', N'dev.thu@company.com', N'0916123456', N'Developer', CAST(N'2023-10-10' AS Date), N'Offline', N'WzuuRzC2bOWMEZ2gg/aBjw==', N'dev10.jpg', NULL, CAST(N'1999-04-25' AS Date), N'901 Đường Trần Phú, Cần Thơ')
INSERT [dbo].[Members] ([MemberID], [FullName], [Email], [Phone], [Role], [HireDate], [Status], [Password], [ImageMember], [ExpiryTime], [DateOfBirth], [Address]) VALUES (N'123472010124', N'Nguyễn Văn Hiệp', N'hr.hiep@company.com', N'0917123456', N'HR', CAST(N'2022-11-01' AS Date), N'Offline', N'WzuuRzC2bOWMEZ2gg/aBjw==', N'hr1.jpg', NULL, CAST(N'1987-06-19' AS Date), N'234 Đường Phạm Ngũ Lão, TP.HCM')
INSERT [dbo].[Members] ([MemberID], [FullName], [Email], [Phone], [Role], [HireDate], [Status], [Password], [ImageMember], [ExpiryTime], [DateOfBirth], [Address]) VALUES (N'123473010124', N'Trần Thị Thảo', N'hr.thao@company.com', N'0918123456', N'HR', CAST(N'2021-05-15' AS Date), N'Offline', N'WzuuRzC2bOWMEZ2gg/aBjw==', N'hr2.jpg', NULL, CAST(N'1990-08-08' AS Date), N'456 Đường Đinh Tiên Hoàng, Hà Nội')
INSERT [dbo].[Members] ([MemberID], [FullName], [Email], [Phone], [Role], [HireDate], [Status], [Password], [ImageMember], [ExpiryTime], [DateOfBirth], [Address]) VALUES (N'123474010124', N'Phạm Văn Hòa', N'hr.hoa@company.com', N'0919123456', N'HR', CAST(N'2020-02-20' AS Date), N'Offline', N'WzuuRzC2bOWMEZ2gg/aBjw==', N'hr3.jpg', NULL, CAST(N'1985-11-30' AS Date), N'678 Đường Nguyễn Văn Cừ, Đà Nẵng')
INSERT [dbo].[Members] ([MemberID], [FullName], [Email], [Phone], [Role], [HireDate], [Status], [Password], [ImageMember], [ExpiryTime], [DateOfBirth], [Address]) VALUES (N'123475010124', N'Đỗ Thị Cúc', N'hr.cuc@company.com', N'0920123456', N'HR', CAST(N'2023-03-01' AS Date), N'Offline', N'WzuuRzC2bOWMEZ2gg/aBjw==', N'hr4.jpg', NULL, CAST(N'1993-07-15' AS Date), N'890 Đường Cách Mạng Tháng 8, Cần Thơ')
GO
SET IDENTITY_INSERT [dbo].[Notifications] ON 

INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (2, N'123462010124', N'You have been added to project ''REAL_Thiết kế lại Website Công ty''', CAST(N'2024-12-07T11:14:02.707' AS DateTime), 0, N'ProjectJoin', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (3, N'123463010124', N'You have been added to project ''REAL_Thiết kế lại Website Công ty''', CAST(N'2024-12-07T11:14:33.593' AS DateTime), 0, N'ProjectJoin', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (4, N'123467010124', N'You have been added to project ''REAL_Thiết kế lại Website Công ty''', CAST(N'2024-12-07T11:14:38.433' AS DateTime), 0, N'ProjectJoin', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (5, N'123471010124', N'You have been added to project ''REAL_Thiết kế lại Website Công ty''', CAST(N'2024-12-07T11:14:41.817' AS DateTime), 0, N'ProjectJoin', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (6, N'123463010124', N'Bạn đã được phân công tham gia vào Task '' Xây dựng cơ sở dữ liệu cho dự án'' trong dự án ''REAL_Thiết kế lại Website Công ty'' bởi ''Trần Thị Bình''  ''Manager'' ', CAST(N'2024-12-07T11:15:34.347' AS DateTime), 0, N'JoinTaskAccepted', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (7, N'123462010124', N'Bạn đã được phân công tham gia vào Task '' Xây dựng cơ sở dữ liệu cho dự án'' trong dự án ''REAL_Thiết kế lại Website Công ty'' bởi ''Trần Thị Bình''  ''Manager'' ', CAST(N'2024-12-07T11:15:38.720' AS DateTime), 0, N'JoinTaskAccepted', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (8, N'123467010124', N'Bạn đã được phân công tham gia vào Task ''Xây dựng chức năng quản lý dự án'' trong dự án ''REAL_Thiết kế lại Website Công ty'' bởi ''Trần Thị Bình''  ''Manager'' ', CAST(N'2024-12-07T11:15:50.953' AS DateTime), 0, N'JoinTaskAccepted', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (9, N'123471010124', N'Bạn đã được phân công tham gia vào Task ''Xây dựng chức năng quản lý dự án'' trong dự án ''REAL_Thiết kế lại Website Công ty'' bởi ''Trần Thị Bình''  ''Manager'' ', CAST(N'2024-12-07T11:15:55.840' AS DateTime), 0, N'JoinTaskAccepted', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (10, N'123462010124', N'Bạn đã được phân công tham gia vào Task ''Xây dựng chức năng quản lý dự án'' trong dự án ''REAL_Thiết kế lại Website Công ty'' bởi ''Trần Thị Bình''  ''Manager'' ', CAST(N'2024-12-07T11:16:00.953' AS DateTime), 0, N'JoinTaskAccepted', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (11, N'123471010124', N'Bạn đã được phân công tham gia vào Task '' Xây dựng cơ sở dữ liệu cho dự án'' trong dự án ''REAL_Thiết kế lại Website Công ty'' bởi ''Trần Thị Bình''  ''Manager'' ', CAST(N'2024-12-07T11:16:27.087' AS DateTime), 0, N'JoinTaskAccepted', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (12, N'123462010124', N'Bạn đã được phân công tham gia vào SubTask ''Thiết kế sơ đồ ERD cho cơ sở dữ liệu.'' trong dự án ''REAL_Thiết kế lại Website Công ty'' bởi ''Trần Thị Bình'' là ''Manager'' ', CAST(N'2024-12-07T11:16:31.113' AS DateTime), 0, N'JoinSubTaskAccepted', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (13, N'123471010124', N'Bạn đã được phân công tham gia vào SubTask ''Tạo bảng Users và cấu hình các thuộc tính cơ bản.'' trong dự án ''REAL_Thiết kế lại Website Công ty'' bởi ''Trần Thị Bình'' là ''Manager'' ', CAST(N'2024-12-07T11:16:34.697' AS DateTime), 0, N'JoinSubTaskAccepted', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (14, N'123463010124', N'Bạn đã được phân công tham gia vào SubTask ''Tạo bảng Projects và thiết lập quan hệ với Users.'' trong dự án ''REAL_Thiết kế lại Website Công ty'' bởi ''Trần Thị Bình'' là ''Manager'' ', CAST(N'2024-12-07T11:16:39.757' AS DateTime), 0, N'JoinSubTaskAccepted', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (15, N'123462010124', N'Bạn đã được phân công tham gia vào SubTask ''Tạo bảng Tasks và liên kết với Projects.'' trong dự án ''REAL_Thiết kế lại Website Công ty'' bởi ''Trần Thị Bình'' là ''Manager'' ', CAST(N'2024-12-07T11:16:43.380' AS DateTime), 0, N'JoinSubTaskAccepted', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (16, N'123462010124', N'Bạn đã được phân công tham gia vào SubTask ''Tạo bảng Comments và liên kết với Tasks.'' trong dự án ''REAL_Thiết kế lại Website Công ty'' bởi ''Trần Thị Bình'' là ''Manager'' ', CAST(N'2024-12-07T11:16:55.223' AS DateTime), 0, N'JoinSubTaskAccepted', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (17, N'123471010124', N'Bạn đã được phân công tham gia vào SubTask ''Thêm bảng TransactionHistory để lưu lịch sử giao dịch.'' trong dự án ''REAL_Thiết kế lại Website Công ty'' bởi ''Trần Thị Bình'' là ''Manager'' ', CAST(N'2024-12-07T11:16:59.590' AS DateTime), 0, N'JoinSubTaskAccepted', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (18, N'123471010124', N'Bạn đã được phân công tham gia vào SubTask ''Viết script để seed dữ liệu mẫu.'' trong dự án ''REAL_Thiết kế lại Website Công ty'' bởi ''Trần Thị Bình'' là ''Manager'' ', CAST(N'2024-12-07T11:17:02.833' AS DateTime), 0, N'JoinSubTaskAccepted', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (19, N'123456010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project REAL_Thiết kế lại Website Công ty (ID: PRJ202301).', CAST(N'2024-12-07T11:21:11.260' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202301"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (20, N'123457010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project REAL_Thiết kế lại Website Công ty (ID: PRJ202301).', CAST(N'2024-12-07T11:21:11.260' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202301"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (21, N'123458010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project REAL_Thiết kế lại Website Công ty (ID: PRJ202301).', CAST(N'2024-12-07T11:21:11.260' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202301"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (22, N'123459010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project REAL_Thiết kế lại Website Công ty (ID: PRJ202301).', CAST(N'2024-12-07T11:21:11.260' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202301"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (23, N'123460010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project REAL_Thiết kế lại Website Công ty (ID: PRJ202301).', CAST(N'2024-12-07T11:21:11.260' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202301"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (24, N'123461010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project REAL_Thiết kế lại Website Công ty (ID: PRJ202301).', CAST(N'2024-12-07T11:21:11.260' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202301"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (25, N'123456010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project Phát triển Ứng dụng Di động (ID: PRJ202302).', CAST(N'2024-12-07T13:00:23.063' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202302"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (26, N'123457010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project Phát triển Ứng dụng Di động (ID: PRJ202302).', CAST(N'2024-12-07T13:00:23.063' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202302"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (27, N'123458010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project Phát triển Ứng dụng Di động (ID: PRJ202302).', CAST(N'2024-12-07T13:00:23.063' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202302"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (28, N'123459010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project Phát triển Ứng dụng Di động (ID: PRJ202302).', CAST(N'2024-12-07T13:00:23.063' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202302"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (29, N'123460010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project Phát triển Ứng dụng Di động (ID: PRJ202302).', CAST(N'2024-12-07T13:00:23.063' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202302"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (30, N'123461010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project Phát triển Ứng dụng Di động (ID: PRJ202302).', CAST(N'2024-12-07T13:00:23.063' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202302"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (31, N'123456010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project Nâng cấp Hệ thống ERP (ID: PRJ202303).', CAST(N'2024-12-07T13:00:27.937' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202303"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (32, N'123457010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project Nâng cấp Hệ thống ERP (ID: PRJ202303).', CAST(N'2024-12-07T13:00:27.937' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202303"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (33, N'123458010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project Nâng cấp Hệ thống ERP (ID: PRJ202303).', CAST(N'2024-12-07T13:00:27.937' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202303"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (34, N'123459010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project Nâng cấp Hệ thống ERP (ID: PRJ202303).', CAST(N'2024-12-07T13:00:27.937' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202303"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (35, N'123460010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project Nâng cấp Hệ thống ERP (ID: PRJ202303).', CAST(N'2024-12-07T13:00:27.937' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202303"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (36, N'123461010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project Nâng cấp Hệ thống ERP (ID: PRJ202303).', CAST(N'2024-12-07T13:00:27.937' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202303"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (37, N'123456010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project Di chuyển Hạ tầng lên Cloud (ID: PRJ202304).', CAST(N'2024-12-07T13:00:36.237' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202304"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (38, N'123457010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project Di chuyển Hạ tầng lên Cloud (ID: PRJ202304).', CAST(N'2024-12-07T13:00:36.237' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202304"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (39, N'123458010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project Di chuyển Hạ tầng lên Cloud (ID: PRJ202304).', CAST(N'2024-12-07T13:00:36.237' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202304"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (40, N'123459010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project Di chuyển Hạ tầng lên Cloud (ID: PRJ202304).', CAST(N'2024-12-07T13:00:36.237' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202304"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (41, N'123460010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project Di chuyển Hạ tầng lên Cloud (ID: PRJ202304).', CAST(N'2024-12-07T13:00:36.237' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202304"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (42, N'123461010124', N'Trần Văn Hùng (ID: 123470010124) requested to join project Di chuyển Hạ tầng lên Cloud (ID: PRJ202304).', CAST(N'2024-12-07T13:00:36.237' AS DateTime), 0, N'JoinRequest', N'{"RequestMemberID": "123470010124", "ProjectID": "PRJ202304"}')
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (43, N'123471010124', N'You have been added to project ''Nâng cấp Hệ thống ERP''', CAST(N'2024-12-07T13:04:31.220' AS DateTime), 0, N'ProjectJoin', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (44, N'123463010124', N'You have been added to project ''Nâng cấp Hệ thống ERP''', CAST(N'2024-12-07T13:04:35.623' AS DateTime), 0, N'ProjectJoin', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (45, N'123462010124', N'You have been added to project ''Nâng cấp Hệ thống ERP''', CAST(N'2024-12-07T13:04:39.700' AS DateTime), 0, N'ProjectJoin', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (46, N'123467010124', N'Bạn đã được phân công tham gia vào SubTask ''Tạo form thêm mới dự án.'' trong dự án ''REAL_Thiết kế lại Website Công ty'' bởi ''Trần Thị Bình'' là ''Manager'' ', CAST(N'2024-12-07T13:13:38.820' AS DateTime), 0, N'JoinSubTaskAccepted', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (47, N'123471010124', N'Bạn đã được phân công tham gia vào SubTask ''Tạo giao diện danh sách dự án.'' trong dự án ''REAL_Thiết kế lại Website Công ty'' bởi ''Trần Thị Bình'' là ''Manager'' ', CAST(N'2024-12-07T13:13:40.770' AS DateTime), 0, N'JoinSubTaskAccepted', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (48, N'123462010124', N'Bạn đã được phân công tham gia vào SubTask ''Xây dựng API lấy danh sách dự án.'' trong dự án ''REAL_Thiết kế lại Website Công ty'' bởi ''Trần Thị Bình'' là ''Manager'' ', CAST(N'2024-12-07T13:13:42.800' AS DateTime), 0, N'JoinSubTaskAccepted', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (49, N'123462010124', N'Bạn đã được phân công tham gia vào SubTask ''Cấu hình quyền truy cập cho từng loại người dùng.'' trong dự án ''REAL_Thiết kế lại Website Công ty'' bởi ''Trần Thị Bình'' là ''Manager'' ', CAST(N'2024-12-07T13:13:44.973' AS DateTime), 0, N'JoinSubTaskAccepted', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (50, N'123462010124', N'Bạn đã được phân công tham gia vào SubTask ''Thêm chức năng chỉnh sửa thông tin dự án.'' trong dự án ''REAL_Thiết kế lại Website Công ty'' bởi ''Trần Thị Bình'' là ''Manager'' ', CAST(N'2024-12-07T13:13:47.323' AS DateTime), 0, N'JoinSubTaskAccepted', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (51, N'123471010124', N'Bạn đã được phân công tham gia vào SubTask ''Xóa dự án và xử lý các ràng buộc liên quan.'' trong dự án ''REAL_Thiết kế lại Website Công ty'' bởi ''Trần Thị Bình'' là ''Manager'' ', CAST(N'2024-12-07T13:13:50.403' AS DateTime), 0, N'JoinSubTaskAccepted', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (52, N'123467010124', N'Bạn đã được phân công tham gia vào SubTask ''Hiển thị chi tiết dự án theo ID.'' trong dự án ''REAL_Thiết kế lại Website Công ty'' bởi ''Trần Thị Bình'' là ''Manager'' ', CAST(N'2024-12-07T13:13:55.500' AS DateTime), 0, N'JoinSubTaskAccepted', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (53, N'123471010124', N'Bạn đã được phân công tham gia vào SubTask ''Thêm bộ lọc tìm kiếm và phân trang danh sách dự án.'' trong dự án ''REAL_Thiết kế lại Website Công ty'' bởi ''Trần Thị Bình'' là ''Manager'' ', CAST(N'2024-12-07T13:14:30.273' AS DateTime), 0, N'JoinSubTaskAccepted', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (54, N'123467010124', N'Bạn đã được phân công tham gia vào SubTask ''Viết test case cho các API quản lý dự án.'' trong dự án ''REAL_Thiết kế lại Website Công ty'' bởi ''Trần Thị Bình'' là ''Manager'' ', CAST(N'2024-12-07T13:14:41.997' AS DateTime), 0, N'JoinSubTaskAccepted', NULL)
INSERT [dbo].[Notifications] ([NotificationID], [MemberID], [Content], [NotificationDate], [IsRead], [NotificationType], [ExtraData]) VALUES (55, N'123471010124', N'Bạn đã được phân công tham gia vào SubTask ''Kiểm tra và fix bug liên quan đến chức năng này.'' trong dự án ''REAL_Thiết kế lại Website Công ty'' bởi ''Trần Thị Bình'' là ''Manager'' ', CAST(N'2024-12-07T13:14:44.947' AS DateTime), 0, N'JoinSubTaskAccepted', NULL)
SET IDENTITY_INSERT [dbo].[Notifications] OFF
GO
SET IDENTITY_INSERT [dbo].[ProjectMembers] ON 

INSERT [dbo].[ProjectMembers] ([ProjectMemberID], [ProjectID], [MemberID], [JoinDate], [Status]) VALUES (2, N'PRJUC5H1H', N'123457010124', CAST(N'2024-12-07T10:50:42.287' AS DateTime), N'Accepted')
INSERT [dbo].[ProjectMembers] ([ProjectMemberID], [ProjectID], [MemberID], [JoinDate], [Status]) VALUES (3, N'PRJ202302', N'123457010124', CAST(N'2024-12-07T10:54:07.017' AS DateTime), N'Accepted')
INSERT [dbo].[ProjectMembers] ([ProjectMemberID], [ProjectID], [MemberID], [JoinDate], [Status]) VALUES (4, N'PRJ202301', N'123457010124', CAST(N'2024-12-07T10:56:20.343' AS DateTime), N'Accepted')
INSERT [dbo].[ProjectMembers] ([ProjectMemberID], [ProjectID], [MemberID], [JoinDate], [Status]) VALUES (5, N'PRJ202303', N'123458010124', CAST(N'2024-12-07T10:56:35.773' AS DateTime), N'Accepted')
INSERT [dbo].[ProjectMembers] ([ProjectMemberID], [ProjectID], [MemberID], [JoinDate], [Status]) VALUES (6, N'PRJ202304', N'123458010124', CAST(N'2024-12-07T10:56:59.190' AS DateTime), N'Accepted')
INSERT [dbo].[ProjectMembers] ([ProjectMemberID], [ProjectID], [MemberID], [JoinDate], [Status]) VALUES (7, N'PRJ202305', N'123459010124', CAST(N'2024-12-07T10:57:10.567' AS DateTime), N'Accepted')
INSERT [dbo].[ProjectMembers] ([ProjectMemberID], [ProjectID], [MemberID], [JoinDate], [Status]) VALUES (8, N'PRJ202306', N'123459010124', CAST(N'2024-12-07T10:57:14.473' AS DateTime), N'Accepted')
INSERT [dbo].[ProjectMembers] ([ProjectMemberID], [ProjectID], [MemberID], [JoinDate], [Status]) VALUES (9, N'PRJ202307', N'123459010124', CAST(N'2024-12-07T10:57:32.373' AS DateTime), N'Accepted')
INSERT [dbo].[ProjectMembers] ([ProjectMemberID], [ProjectID], [MemberID], [JoinDate], [Status]) VALUES (10, N'PRJ202301', N'123462010124', CAST(N'2024-12-07T11:14:02.487' AS DateTime), N'Accepted')
INSERT [dbo].[ProjectMembers] ([ProjectMemberID], [ProjectID], [MemberID], [JoinDate], [Status]) VALUES (11, N'PRJ202301', N'123463010124', CAST(N'2024-12-07T11:14:33.573' AS DateTime), N'Accepted')
INSERT [dbo].[ProjectMembers] ([ProjectMemberID], [ProjectID], [MemberID], [JoinDate], [Status]) VALUES (12, N'PRJ202301', N'123467010124', CAST(N'2024-12-07T11:14:38.410' AS DateTime), N'Accepted')
INSERT [dbo].[ProjectMembers] ([ProjectMemberID], [ProjectID], [MemberID], [JoinDate], [Status]) VALUES (13, N'PRJ202301', N'123471010124', CAST(N'2024-12-07T11:14:41.790' AS DateTime), N'Accepted')
INSERT [dbo].[ProjectMembers] ([ProjectMemberID], [ProjectID], [MemberID], [JoinDate], [Status]) VALUES (14, N'PRJ202301', N'123470010124', CAST(N'2024-12-07T11:21:11.237' AS DateTime), N'Pending')
INSERT [dbo].[ProjectMembers] ([ProjectMemberID], [ProjectID], [MemberID], [JoinDate], [Status]) VALUES (15, N'PRJ202302', N'123470010124', CAST(N'2024-12-07T13:00:23.050' AS DateTime), N'Pending')
INSERT [dbo].[ProjectMembers] ([ProjectMemberID], [ProjectID], [MemberID], [JoinDate], [Status]) VALUES (16, N'PRJ202303', N'123470010124', CAST(N'2024-12-07T13:00:27.933' AS DateTime), N'Pending')
INSERT [dbo].[ProjectMembers] ([ProjectMemberID], [ProjectID], [MemberID], [JoinDate], [Status]) VALUES (17, N'PRJ202304', N'123470010124', CAST(N'2024-12-07T13:00:36.233' AS DateTime), N'Pending')
INSERT [dbo].[ProjectMembers] ([ProjectMemberID], [ProjectID], [MemberID], [JoinDate], [Status]) VALUES (18, N'PRJ202303', N'123471010124', CAST(N'2024-12-07T13:04:31.217' AS DateTime), N'Accepted')
INSERT [dbo].[ProjectMembers] ([ProjectMemberID], [ProjectID], [MemberID], [JoinDate], [Status]) VALUES (19, N'PRJ202303', N'123463010124', CAST(N'2024-12-07T13:04:35.613' AS DateTime), N'Accepted')
INSERT [dbo].[ProjectMembers] ([ProjectMemberID], [ProjectID], [MemberID], [JoinDate], [Status]) VALUES (20, N'PRJ202303', N'123462010124', CAST(N'2024-12-07T13:04:39.690' AS DateTime), N'Accepted')
SET IDENTITY_INSERT [dbo].[ProjectMembers] OFF
GO
INSERT [dbo].[Projects] ([ProjectID], [ProjectName], [Description], [StartDate], [EndDate], [Status], [deleteTime], [ImageProject], [Priority], [createBy]) VALUES (N'PRJ202301', N'REAL_Thiết kế lại Website Công ty', N'- Thiết kế lại giao diện website công ty.
- Tăng trải nghiệm người dùng.
- Tối ưu hóa SEO để tăng lượt truy cập.', CAST(N'2024-01-10' AS Date), CAST(N'2025-05-30' AS Date), N'Pending', NULL, N'website_redesign.jpg', 5, N'123457010124')
INSERT [dbo].[Projects] ([ProjectID], [ProjectName], [Description], [StartDate], [EndDate], [Status], [deleteTime], [ImageProject], [Priority], [createBy]) VALUES (N'PRJ202302', N'Phát triển Ứng dụng Di động', N'- Xây dựng ứng dụng di động hỗ trợ bán hàng trực tuyến. - Hỗ trợ đa nền tảng (iOS, Android). - Tích hợp thanh toán trực tuyến.', CAST(N'2024-02-15' AS Date), CAST(N'2025-07-15' AS Date), N'Pending', NULL, N'mobile_app_dev.jpg', 4, N'123457010124')
INSERT [dbo].[Projects] ([ProjectID], [ProjectName], [Description], [StartDate], [EndDate], [Status], [deleteTime], [ImageProject], [Priority], [createBy]) VALUES (N'PRJ202303', N'Nâng cấp Hệ thống ERP', N'- Cập nhật phiên bản mới nhất của ERP. 
- Tích hợp các module mới như Kế toán và Quản lý Nhân sự. 
- Đảm bảo hiệu suất và bảo mật hệ thống.', CAST(N'2024-03-01' AS Date), CAST(N'2025-06-30' AS Date), N'Pending', NULL, N'erp_upgrade.jpg', 1, N'123458010124')
INSERT [dbo].[Projects] ([ProjectID], [ProjectName], [Description], [StartDate], [EndDate], [Status], [deleteTime], [ImageProject], [Priority], [createBy]) VALUES (N'PRJ202304', N'Di chuyển Hạ tầng lên Cloud', N'- Di chuyển toàn bộ hạ tầng hiện tại lên nền tảng Cloud. - Tăng tính linh hoạt và giảm chi phí vận hành. - Đảm bảo an toàn dữ liệu trong quá trình chuyển đổi.', CAST(N'2024-04-01' AS Date), CAST(N'2025-08-31' AS Date), N'Pending', NULL, N'cloud_migration.jpg', 5, N'123458010124')
INSERT [dbo].[Projects] ([ProjectID], [ProjectName], [Description], [StartDate], [EndDate], [Status], [deleteTime], [ImageProject], [Priority], [createBy]) VALUES (N'PRJ202305', N'TEST_Kiểm toán An ninh mạng', N'- Kiểm tra hệ thống mạng nội bộ. - Đánh giá lỗ hổng bảo mật. - Đảm bảo tuân thủ các tiêu chuẩn bảo mật hiện hành.', CAST(N'2024-01-15' AS Date), CAST(N'2025-03-15' AS Date), N'On Hold', NULL, N'cybersecurity_audit.jpg', 4, N'123459010124')
INSERT [dbo].[Projects] ([ProjectID], [ProjectName], [Description], [StartDate], [EndDate], [Status], [deleteTime], [ImageProject], [Priority], [createBy]) VALUES (N'PRJ202306', N'TEST_Chiến dịch Marketing Quý 2', N'- Thực hiện chiến dịch marketing trên mạng xã hội. - Gửi email tiếp thị hàng tuần. - Phân tích hiệu quả và tối ưu chiến lược.', CAST(N'2024-03-20' AS Date), CAST(N'2025-06-30' AS Date), N'In Progress', NULL, N'marketing_campaign_q2.jpg', 3, N'123459010124')
INSERT [dbo].[Projects] ([ProjectID], [ProjectName], [Description], [StartDate], [EndDate], [Status], [deleteTime], [ImageProject], [Priority], [createBy]) VALUES (N'PRJ202307', N'TEST_Hệ thống Phản hồi Khách hàng', N'- Xây dựng hệ thống phản hồi tự động. - Tích hợp chatbot hỗ trợ khách hàng. - Phân tích dữ liệu phản hồi để cải thiện dịch vụ.', CAST(N'2024-05-05' AS Date), CAST(N'2025-09-15' AS Date), N'Completed', NULL, N'feedback_system.jpg', 5, N'123459010124')
INSERT [dbo].[Projects] ([ProjectID], [ProjectName], [Description], [StartDate], [EndDate], [Status], [deleteTime], [ImageProject], [Priority], [createBy]) VALUES (N'PRJUC5H1H', N'ZThiết kế lại Website Công ty', N'ZThiết kế lại Website Công ty', CAST(N'2024-12-07' AS Date), CAST(N'2025-01-11' AS Date), N'Pending', NULL, N'project_64d5f234-d984-463c-923f-18044eb45b0f.jpg', 3, N'123457010124')
GO
SET IDENTITY_INSERT [dbo].[TaskAssignments] ON 

INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (2, 13, N'123457010124', N'123457010124', CAST(N'2024-12-07T11:06:56.147' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (3, 14, N'123457010124', N'123457010124', CAST(N'2024-12-07T11:07:29.710' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (4, 15, N'123462010124', N'123457010124', CAST(N'2024-12-07T11:07:41.790' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (5, 16, N'123471010124', N'123457010124', CAST(N'2024-12-07T11:07:48.563' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (6, 17, N'123463010124', N'123457010124', CAST(N'2024-12-07T11:07:55.780' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (7, 18, N'123462010124', N'123457010124', CAST(N'2024-12-07T11:08:03.117' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (8, 19, N'123462010124', N'123457010124', CAST(N'2024-12-07T11:08:11.367' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (9, 20, N'123471010124', N'123457010124', CAST(N'2024-12-07T11:08:17.923' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (10, 21, N'123471010124', N'123457010124', CAST(N'2024-12-07T11:08:24.730' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (11, 22, N'0', N'123457010124', CAST(N'2024-12-07T11:08:31.840' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (12, 23, N'0', N'123457010124', CAST(N'2024-12-07T11:08:40.157' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (13, 24, N'0', N'123457010124', CAST(N'2024-12-07T11:08:47.153' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (14, 13, N'123463010124', N'123457010124', CAST(N'2024-12-07T11:15:34.323' AS DateTime), N'Assigned', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (15, 13, N'123462010124', N'123457010124', CAST(N'2024-12-07T11:15:38.707' AS DateTime), N'Assigned', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (16, 14, N'123467010124', N'123457010124', CAST(N'2024-12-07T11:15:50.930' AS DateTime), N'Assigned', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (17, 14, N'123471010124', N'123457010124', CAST(N'2024-12-07T11:15:55.830' AS DateTime), N'Assigned', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (18, 14, N'123462010124', N'123457010124', CAST(N'2024-12-07T11:16:00.930' AS DateTime), N'Assigned', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (19, 13, N'123471010124', N'123457010124', CAST(N'2024-12-07T11:16:27.070' AS DateTime), N'Assigned', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (20, 25, N'123458010124', N'123458010124', CAST(N'2024-12-07T13:02:59.763' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (21, 26, N'0', N'123458010124', CAST(N'2024-12-07T13:03:15.677' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (22, 27, N'0', N'123458010124', CAST(N'2024-12-07T13:03:23.643' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (23, 28, N'0', N'123458010124', CAST(N'2024-12-07T13:03:29.367' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (24, 29, N'0', N'123458010124', CAST(N'2024-12-07T13:03:34.703' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (25, 30, N'0', N'123458010124', CAST(N'2024-12-07T13:03:39.760' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (26, 31, N'0', N'123458010124', CAST(N'2024-12-07T13:03:45.863' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (27, 32, N'0', N'123458010124', CAST(N'2024-12-07T13:03:51.840' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (28, 33, N'0', N'123458010124', CAST(N'2024-12-07T13:03:58.063' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (29, 34, N'0', N'123458010124', CAST(N'2024-12-07T13:04:04.473' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (30, 35, N'0', N'123458010124', CAST(N'2024-12-07T13:04:11.177' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (31, 36, N'123467010124', N'123457010124', CAST(N'2024-12-07T13:09:06.487' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (32, 37, N'123471010124', N'123457010124', CAST(N'2024-12-07T13:09:13.923' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (33, 38, N'123462010124', N'123457010124', CAST(N'2024-12-07T13:09:19.277' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (34, 39, N'123462010124', N'123457010124', CAST(N'2024-12-07T13:09:28.040' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (35, 40, N'123462010124', N'123457010124', CAST(N'2024-12-07T13:09:33.987' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (36, 41, N'123471010124', N'123457010124', CAST(N'2024-12-07T13:09:57.197' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (37, 42, N'123467010124', N'123457010124', CAST(N'2024-12-07T13:10:04.447' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (38, 43, N'123471010124', N'123457010124', CAST(N'2024-12-07T13:13:20.643' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (39, 44, N'123467010124', N'123457010124', CAST(N'2024-12-07T13:13:27.007' AS DateTime), N'Pending', NULL)
INSERT [dbo].[TaskAssignments] ([TaskAssignmentID], [TaskID], [MemberID], [AssignedBy], [AssignedDate], [Status], [Note]) VALUES (40, 45, N'123471010124', N'123457010124', CAST(N'2024-12-07T13:13:32.853' AS DateTime), N'Pending', NULL)
SET IDENTITY_INSERT [dbo].[TaskAssignments] OFF
GO
SET IDENTITY_INSERT [dbo].[TaskLogs] ON 

INSERT [dbo].[TaskLogs] ([LogID], [TaskID], [Status], [LogDate], [Note]) VALUES (14, 14, N'In Progress', CAST(N'2024-12-07T13:15:18.340' AS DateTime), N'Change Process')
SET IDENTITY_INSERT [dbo].[TaskLogs] OFF
GO
SET IDENTITY_INSERT [dbo].[Tasks] ON 

INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (13, N' Xây dựng cơ sở dữ liệu cho dự án', N' Xây dựng cơ sở dữ liệu cho dự án', N'PRJ202301', NULL, N'https://drive.google.com/drive/folders/1U5df60E6qlyfhlvloaJ7Mkvvc9YTgi5Z?usp=sharing', CAST(N'2024-10-03' AS Date), CAST(N'2024-10-31' AS Date), 1, N'Pending', N'123457010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (14, N'Xây dựng chức năng quản lý dự án', N'Xây dựng chức năng quản lý dự án', N'PRJ202301', NULL, N'https://drive.google.com/drive/folders/1U5df60E6qlyfhlvloaJ7Mkvvc9YTgi5Z?usp=sharing', CAST(N'2024-09-12' AS Date), CAST(N'2025-01-16' AS Date), 4, N'In Progress', N'123457010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (15, N' Xây dựng cơ sở dữ liệu cho dự án', N'Thiết kế sơ đồ ERD cho cơ sở dữ liệu.', N'PRJ202301', 13, NULL, CAST(N'2024-10-03' AS Date), CAST(N'2024-10-31' AS Date), NULL, N'Pending', N'123457010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (16, N' Xây dựng cơ sở dữ liệu cho dự án', N'Tạo bảng Users và cấu hình các thuộc tính cơ bản.', N'PRJ202301', 13, NULL, CAST(N'2024-10-03' AS Date), CAST(N'2024-10-31' AS Date), NULL, N'Pending', N'123457010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (17, N' Xây dựng cơ sở dữ liệu cho dự án', N'Tạo bảng Projects và thiết lập quan hệ với Users.', N'PRJ202301', 13, NULL, CAST(N'2024-10-03' AS Date), CAST(N'2024-10-31' AS Date), NULL, N'Pending', N'123457010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (18, N' Xây dựng cơ sở dữ liệu cho dự án', N'Tạo bảng Tasks và liên kết với Projects.', N'PRJ202301', 13, NULL, CAST(N'2024-10-03' AS Date), CAST(N'2024-10-31' AS Date), NULL, N'Pending', N'123457010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (19, N' Xây dựng cơ sở dữ liệu cho dự án', N'Tạo bảng Comments và liên kết với Tasks.', N'PRJ202301', 13, NULL, CAST(N'2024-10-03' AS Date), CAST(N'2024-10-31' AS Date), NULL, N'Pending', N'123457010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (20, N' Xây dựng cơ sở dữ liệu cho dự án', N'Thêm bảng TransactionHistory để lưu lịch sử giao dịch.', N'PRJ202301', 13, NULL, CAST(N'2024-10-03' AS Date), CAST(N'2024-10-31' AS Date), NULL, N'Pending', N'123457010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (21, N' Xây dựng cơ sở dữ liệu cho dự án', N'Viết script để seed dữ liệu mẫu.', N'PRJ202301', 13, NULL, CAST(N'2024-10-03' AS Date), CAST(N'2024-10-31' AS Date), NULL, N'Pending', N'123457010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (22, N' Xây dựng cơ sở dữ liệu cho dự án', N'Cấu hình kết nối cơ sở dữ liệu trong ứng dụng.', N'PRJ202301', 13, NULL, CAST(N'2024-10-03' AS Date), CAST(N'2024-10-31' AS Date), NULL, N'Pending', N'123457010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (23, N' Xây dựng cơ sở dữ liệu cho dự án', N'Kiểm tra tính toàn vẹn dữ liệu với các ràng buộc.', N'PRJ202301', 13, NULL, CAST(N'2024-10-03' AS Date), CAST(N'2024-10-31' AS Date), NULL, N'Pending', N'123457010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (24, N' Xây dựng cơ sở dữ liệu cho dự án', N'Tối ưu hóa chỉ mục và truy vấn', N'PRJ202301', 13, NULL, CAST(N'2024-10-03' AS Date), CAST(N'2024-10-31' AS Date), NULL, N'Pending', N'123457010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (25, N'Viết tài liệu và kiểm thử dự án', N'Viết tài liệu và kiểm thử dự án', N'PRJ202303', NULL, N'https://drive.google.com/drive/folders/1U5df60E6qlyfhlvloaJ7Mkvvc9YTgi5Z?usp=sharing', CAST(N'2024-12-05' AS Date), CAST(N'2025-01-04' AS Date), 2, N'Pending', N'123458010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (26, N'Viết tài liệu và kiểm thử dự án', N'Viết tài liệu hướng dẫn sử dụng phần mềm.', N'PRJ202303', 25, NULL, CAST(N'2024-12-05' AS Date), CAST(N'2025-01-04' AS Date), NULL, N'Pending', N'123458010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (27, N'Viết tài liệu và kiểm thử dự án', N'Tạo checklist kiểm thử tính năng.', N'PRJ202303', 25, NULL, CAST(N'2024-12-05' AS Date), CAST(N'2025-01-04' AS Date), NULL, N'Pending', N'123458010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (28, N'Viết tài liệu và kiểm thử dự án', N'Viết test case chi tiết cho từng API.', N'PRJ202303', 25, NULL, CAST(N'2024-12-05' AS Date), CAST(N'2025-01-04' AS Date), NULL, N'Pending', N'123458010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (29, N'Viết tài liệu và kiểm thử dự án', N'Thực hiện kiểm thử chức năng.', N'PRJ202303', 25, NULL, CAST(N'2024-12-05' AS Date), CAST(N'2025-01-04' AS Date), NULL, N'Pending', N'123458010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (30, N'Viết tài liệu và kiểm thử dự án', N'Ghi nhận và xử lý bug phát hiện.', N'PRJ202303', 25, NULL, CAST(N'2024-12-05' AS Date), CAST(N'2025-01-04' AS Date), NULL, N'Pending', N'123458010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (31, N'Viết tài liệu và kiểm thử dự án', N'Viết tài liệu triển khai hệ thống.', N'PRJ202303', 25, NULL, CAST(N'2024-12-05' AS Date), CAST(N'2025-01-04' AS Date), NULL, N'Pending', N'123458010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (32, N'Viết tài liệu và kiểm thử dự án', N'Thêm tài liệu mô tả cấu trúc dự án.', N'PRJ202303', 25, NULL, CAST(N'2024-12-05' AS Date), CAST(N'2025-01-04' AS Date), NULL, N'Pending', N'123458010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (33, N'Viết tài liệu và kiểm thử dự án', N'Hướng dẫn đội nhóm sử dụng SignalR.', N'PRJ202303', 25, NULL, CAST(N'2024-12-05' AS Date), CAST(N'2025-01-04' AS Date), NULL, N'Pending', N'123458010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (34, N'Viết tài liệu và kiểm thử dự án', N'Chuẩn bị tài liệu demo dự án.', N'PRJ202303', 25, NULL, CAST(N'2024-12-05' AS Date), CAST(N'2025-01-04' AS Date), NULL, N'Pending', N'123458010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (35, N'Viết tài liệu và kiểm thử dự án', N'Viết báo cáo tổng kết quá trình phát triển.', N'PRJ202303', 25, NULL, CAST(N'2024-12-05' AS Date), CAST(N'2025-01-04' AS Date), NULL, N'Pending', N'123458010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (36, N'Xây dựng chức năng quản lý dự án', N'Tạo form thêm mới dự án.', N'PRJ202301', 14, NULL, CAST(N'2024-09-12' AS Date), CAST(N'2025-01-16' AS Date), NULL, N'Completed', N'123457010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (37, N'Xây dựng chức năng quản lý dự án', N'Tạo giao diện danh sách dự án.', N'PRJ202301', 14, NULL, CAST(N'2024-09-12' AS Date), CAST(N'2025-01-16' AS Date), NULL, N'Pending', N'123457010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (38, N'Xây dựng chức năng quản lý dự án', N'Xây dựng API lấy danh sách dự án.', N'PRJ202301', 14, NULL, CAST(N'2024-09-12' AS Date), CAST(N'2025-01-16' AS Date), NULL, N'Pending', N'123457010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (39, N'Xây dựng chức năng quản lý dự án', N'Cấu hình quyền truy cập cho từng loại người dùng.', N'PRJ202301', 14, NULL, CAST(N'2024-09-12' AS Date), CAST(N'2025-01-16' AS Date), NULL, N'Pending', N'123457010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (40, N'Xây dựng chức năng quản lý dự án', N'Thêm chức năng chỉnh sửa thông tin dự án.', N'PRJ202301', 14, NULL, CAST(N'2024-09-12' AS Date), CAST(N'2025-01-16' AS Date), NULL, N'Pending', N'123457010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (41, N'Xây dựng chức năng quản lý dự án', N'Xóa dự án và xử lý các ràng buộc liên quan.', N'PRJ202301', 14, NULL, CAST(N'2024-09-12' AS Date), CAST(N'2025-01-16' AS Date), NULL, N'Pending', N'123457010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (42, N'Xây dựng chức năng quản lý dự án', N'Hiển thị chi tiết dự án theo ID.', N'PRJ202301', 14, NULL, CAST(N'2024-09-12' AS Date), CAST(N'2025-01-16' AS Date), NULL, N'Completed', N'123457010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (43, N'Xây dựng chức năng quản lý dự án', N'Thêm bộ lọc tìm kiếm và phân trang danh sách dự án.', N'PRJ202301', 14, NULL, CAST(N'2024-09-12' AS Date), CAST(N'2025-01-16' AS Date), NULL, N'Pending', N'123457010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (44, N'Xây dựng chức năng quản lý dự án', N'Viết test case cho các API quản lý dự án.', N'PRJ202301', 14, NULL, CAST(N'2024-09-12' AS Date), CAST(N'2025-01-16' AS Date), NULL, N'Pending', N'123457010124')
INSERT [dbo].[Tasks] ([TaskID], [TaskName], [Description], [ProjectID], [ParentTaskID], [DriveLink], [StartDate], [EndDate], [Priority], [Status], [createBy]) VALUES (45, N'Xây dựng chức năng quản lý dự án', N'Kiểm tra và fix bug liên quan đến chức năng này.', N'PRJ202301', 14, NULL, CAST(N'2024-09-12' AS Date), CAST(N'2025-01-16' AS Date), NULL, N'Pending', N'123457010124')
SET IDENTITY_INSERT [dbo].[Tasks] OFF
GO
SET ANSI_PADDING ON
GO
/****** Object:  Index [UQ__Members__A9D1053454EA0FEE]    Script Date: 12/9/2024 9:01:37 PM ******/
ALTER TABLE [dbo].[Members] ADD UNIQUE NONCLUSTERED 
(
	[Email] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
GO
ALTER TABLE [dbo].[Interactions] ADD  DEFAULT (getdate()) FOR [InteractionDate]
GO
ALTER TABLE [dbo].[Interactions] ADD  DEFAULT ((0)) FOR [IsPinned]
GO
ALTER TABLE [dbo].[Notifications] ADD  DEFAULT (getdate()) FOR [NotificationDate]
GO
ALTER TABLE [dbo].[Notifications] ADD  DEFAULT ((0)) FOR [IsRead]
GO
ALTER TABLE [dbo].[ProjectMembers] ADD  DEFAULT (getdate()) FOR [JoinDate]
GO
ALTER TABLE [dbo].[ProjectMembers] ADD  DEFAULT ('Pending') FOR [Status]
GO
ALTER TABLE [dbo].[Reports] ADD  DEFAULT (getdate()) FOR [ReportDate]
GO
ALTER TABLE [dbo].[TaskAssignments] ADD  DEFAULT (getdate()) FOR [AssignedDate]
GO
ALTER TABLE [dbo].[TaskAssignments] ADD  DEFAULT ('Assigned') FOR [Status]
GO
ALTER TABLE [dbo].[TaskLogs] ADD  DEFAULT (getdate()) FOR [LogDate]
GO
ALTER TABLE [dbo].[Interactions]  WITH CHECK ADD FOREIGN KEY([MemberID])
REFERENCES [dbo].[Members] ([MemberID])
GO
ALTER TABLE [dbo].[Interactions]  WITH CHECK ADD FOREIGN KEY([ProjectID])
REFERENCES [dbo].[Projects] ([ProjectID])
GO
ALTER TABLE [dbo].[Notifications]  WITH CHECK ADD FOREIGN KEY([MemberID])
REFERENCES [dbo].[Members] ([MemberID])
GO
ALTER TABLE [dbo].[ProjectMembers]  WITH CHECK ADD FOREIGN KEY([MemberID])
REFERENCES [dbo].[Members] ([MemberID])
GO
ALTER TABLE [dbo].[ProjectMembers]  WITH CHECK ADD FOREIGN KEY([ProjectID])
REFERENCES [dbo].[Projects] ([ProjectID])
GO
ALTER TABLE [dbo].[Reports]  WITH CHECK ADD FOREIGN KEY([GeneratedBy])
REFERENCES [dbo].[Members] ([MemberID])
GO
ALTER TABLE [dbo].[Reports]  WITH CHECK ADD FOREIGN KEY([ProjectID])
REFERENCES [dbo].[Projects] ([ProjectID])
GO
ALTER TABLE [dbo].[TaskAssignments]  WITH CHECK ADD FOREIGN KEY([AssignedBy])
REFERENCES [dbo].[Members] ([MemberID])
GO
ALTER TABLE [dbo].[TaskAssignments]  WITH CHECK ADD FOREIGN KEY([MemberID])
REFERENCES [dbo].[Members] ([MemberID])
GO
ALTER TABLE [dbo].[TaskAssignments]  WITH CHECK ADD FOREIGN KEY([TaskID])
REFERENCES [dbo].[Tasks] ([TaskID])
GO
ALTER TABLE [dbo].[TaskLogs]  WITH CHECK ADD FOREIGN KEY([TaskID])
REFERENCES [dbo].[Tasks] ([TaskID])
GO
ALTER TABLE [dbo].[Tasks]  WITH CHECK ADD FOREIGN KEY([ParentTaskID])
REFERENCES [dbo].[Tasks] ([TaskID])
GO
ALTER TABLE [dbo].[Tasks]  WITH CHECK ADD FOREIGN KEY([ProjectID])
REFERENCES [dbo].[Projects] ([ProjectID])
GO
