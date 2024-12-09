# DACN-ManageTaskSystem-ManageTask_PRJSystem

-----------CONFIGURATION INSTRUCTIONS-----------
1. Run the file Database.sql (Authentication: SQL Server Authentiation, Login: sa, Password: 123)
2. Run the file ManageTaskWeb.sln
3. Run the program
3.1. - If there is an error connecting to the database, go to Model -> QLCV.designer.cs
- Search for "public QLCVDataContext() :
base("Data Source=.;Initial Catalog=DBTM;Persist Security Info=True;Use" +
"r ID=sa;Password=123;Encrypt=True;TrustServerCertificate=True", mappingSource)
{
OnCreated();
}"
- Change the Servername, Databasename, id, password to match the machine information

------------SAMPLE DATA------------
1. Login account:
Admin: (MemberID: 123456010124, Password: Abc123456*)
Manager: (MemberID: 123457010124, Password: Abc123456*)
Developer: (MemberID: 123462010124, Password: Abc123456*)
HR: (MemberID: 123472010124, Password: Abc123456*)
2. To run the forgot password function. Create an employee or update an employee with the real email.

----------- DEMO - GITHUB -----------
Demo:
GitHub:
