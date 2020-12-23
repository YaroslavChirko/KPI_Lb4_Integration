using IIG.CoSFE.DatabaseUtils;
using IIG.FileWorker;
using IIG.PasswordHashingUtils;
using System;
using System.IO;
using System.Linq;
using Xunit;
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace KpiLab4_Integration
{
    public class PasswordHasher_Integration
    {

        AuthDatabaseUtils adu = new AuthDatabaseUtils(@"DESKTOP-GE4243S\MSSQLSERVERDEV", @"IIG.CoSWE.AuthDB", true, @"sa", @"11111111", 15);


        [Theory]
        [InlineData("mycoolpasfhtfmygfmvyjhbygmuhhjygfhjhgyjvhghfyfjiujhiutrdrrerqwerwerwerwerfghfuygkuisdddddddddsfhtfjgvjyfghgvjhgvghvhvhgkfkktftkygvkg", "hamon")]
        [InlineData("hamon", "ImAlsoSaldddddddddddddddddddddddddddddddddddddddddtttttttttttttttttttttttttttttttttttt")]
        public void AuthDbCheckFalse(string pass, string login)
        {
            string hashed = PasswordHasher.GetHash(pass, login);
            adu.AddCredentials(login, hashed);
            Assert.False(adu.CheckCredentials(login, hashed));
        }

        [Theory]
        [InlineData("don't hash", "some")]
        [InlineData("", "notValid")]
        public void AuthDbAddFalse(string pass, string login)
        {

            adu.AddCredentials(login, pass);
            Assert.False(adu.CheckCredentials(login, pass));
        }



        [Theory]
        [InlineData("valid data", "1235")]
        [InlineData("mycoolpass", "ImAlsoSalt")]
        public void AuthDbAddTrue(string pass, string login)
        {
            string hashed = PasswordHasher.GetHash(pass, login);
            adu.AddCredentials(login, hashed);
            Assert.True(adu.CheckCredentials(login, hashed));
        }

        [Fact]
        public void DeleteEntry() {
            string login = "NewUser";
            string pass = "123456";
            string hashed = PasswordHasher.GetHash(pass, login);
            adu.AddCredentials(login, hashed);
            Assert.True(adu.CheckCredentials(login, hashed), "Add check");
            adu.DeleteCredentials(login, hashed);
            Assert.False(adu.CheckCredentials(login, hashed), "Delete check");
        }

        [Fact]
        public void DeleteEntryNonExistant()
        {
            Assert.False(adu.DeleteCredentials("non_existant", "aswell"), "Will fail but logically should be false");
        }

        [Theory]
        [InlineData("pass_noUpdate", "UserBeforeUpdate","UpdatedLogin","updated_pass")]
        public void updateCredentials(string pass,string login, string up_login,string up_pass) {
            string hashed = PasswordHasher.GetHash(pass, login);
            adu.AddCredentials(login, hashed);
            Assert.True(adu.CheckCredentials(login, hashed), "add, should be true");
            string up_hashed = PasswordHasher.GetHash(up_pass, up_login);
            adu.UpdateCredentials(login,hashed,up_login,up_hashed);
            Assert.True(adu.CheckCredentials(up_login, up_hashed),"update check, should be true");
            Assert.False(adu.CheckCredentials(login, hashed), "should be false after update");
        }


        [Fact]
        public void updateNonExistant() {

            string login_updated = "updated";
            string pass_updated = "some_pass";
            string start_login = "some_login";
            string start_hashed = PasswordHasher.GetHash("start_pass", start_login);
            string hashed_upd = PasswordHasher.GetHash(pass_updated, login_updated);
            Assert.False(adu.UpdateCredentials(start_login, start_hashed, login_updated ,hashed_upd));
            Assert.False(adu.CheckCredentials(login_updated, hashed_upd));
        }
    }


    public class Fileworker_Integration {
    StorageDatabaseUtils sdu = new StorageDatabaseUtils(@"DESKTOP-GE4243S\MSSQLSERVERDEV", @"IIG.CoSWE.StorageDB", true, @"sa", @"11111111", 15);

        [Fact]
        public void FileBinaryStore() {

            string filepath = "thisfile.txt";
            string writeSomeLines = "should write some lines to the file";
            BaseFileWorker.Write(writeSomeLines, filepath);
            byte[] byteArr = File.ReadAllBytes(filepath);
            // string binaryStr = System.Text.Encoding.Default.GetString(byteArr);
            sdu.AddFile(filepath,byteArr);
            byte[] returnedArr;
            string returnedFileName;
            int returned = int.Parse(sdu.GetFiles(filepath).Rows[0]["FileID"].ToString());
            sdu.GetFile(returned,out returnedFileName,out returnedArr);
            Assert.Equal(byteArr, returnedArr);
            Assert.Equal(filepath, returnedFileName);

        }

        [Fact]
        public void EmptyFileStore() {
            string filepath = "emptyfile.txt";
            BaseFileWorker.Write("", filepath);
            byte[] byteArr = File.ReadAllBytes(filepath);
            sdu.AddFile(filepath, byteArr);
            byte[] returnedArr;
            string returnedFileName;
            int returned = int.Parse(sdu.GetFiles(filepath).Rows[0]["FileID"].ToString());
            sdu.GetFile(returned, out returnedFileName, out returnedArr);
            Assert.Equal(byteArr, returnedArr);
            Assert.Equal(filepath, returnedFileName);
        }

        [Fact]
        public void DeleteFileCheck() { 
            string filename = "thisfile.txt";
           var returned =  sdu.GetFiles(filename);
            if (returned.Rows.Count > 0) { 
            Assert.True(sdu.DeleteFile(int.Parse(returned.Rows[0]["FileID"].ToString())));
            }
        }

        [Fact]
        public void DeleteFileCheckFail() {
            Assert.False(sdu.DeleteFile(-1), "will be failed, but logically should be false");
        }

        [Fact]
        public void GetFilesEmptyCheck() {
            Assert.True(sdu.GetFiles("no_such_filename.dot").Rows.Count == 0);
        }

        [Fact]
        public void GetFileErrorCheck() {
            byte[] emptyByte;
            string emptyFilename;
            Assert.False(sdu.GetFile(-1,out emptyFilename,out emptyByte));
        }
    }
}
