# DACN-ManageTaskSystem-ManageTask_PRJSystem

-----------CONFIGURATION INSTRUCTIONS-----------
1. Run the file Database.sql (Authentication: SQL Server Authentiation, Login: sa, Password: 123)<br>
2. Run the file ManageTaskWeb.sln<br>
3. Run the program<br>
3.1. - If there is an error connecting to the database, go to Model -> QLCV.designer.cs<br>
- Search for "public QLCVDataContext() :
base("Data Source=.;Initial Catalog=DBTM;Persist Security Info=True;Use" +
"r ID=sa;Password=123;Encrypt=True;TrustServerCertificate=True", mappingSource)
{
OnCreated();
}"
- Change the Servername, Databasename, id, password to match the machine information<br>
<br>
------------SAMPLE DATA------------<br>
1. Login account:<br>
<br>
Admin: (MemberID: 123456010124, Password: Abc123456*)
<br>
Manager: (MemberID: 123457010124, Password: Abc123456*)
<br>
Developer: (MemberID: 123462010124, Password: Abc123456*)
<br>
HR: (MemberID: 123472010124, Password: Abc123456*)
<br>
3. To run the forgot password function. Create an employee or update an employee with the real email.<br>
<br>
----------- DEMO - GITHUB -----------<br>
Demo:<br>
GitHub:<br>
