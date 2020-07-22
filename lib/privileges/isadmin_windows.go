// +build windows

package privileges

import (
	"golang.org/x/sys/windows"
)

//Code concept from https://github.com/BishopFox/sliver/blob/8b617232a64c68fbe256bf2d394d6ee886ce43af/sliver/priv/priv_windows.go#L50

//SePrivEnable will check to see if the process has SeDebugMode set or elevate it if not
func SePrivEnable() {
	var tokenHandle windows.Token
	prcHandle, err := windows.GetCurrentProcess()
	if err != nil {
		//logging.Logger.Println(err)
	}

	windows.OpenProcessToken(
		prcHandle,                       // HANDLE Process Handle
		windows.TOKEN_ADJUST_PRIVILEGES, // DWORD Desired Access
		&tokenHandle,                    // PHANDLE TokenHandle
	)

	/*
		typedef struct _LUID {
		  DWORD LowPart;
		  LONG  HighPart;
		} LUID, *PLUID;

	*/
	var luid windows.LUID // Describes a local identifier for an adapter struct above

	/*
		BOOL LookupPrivilegeValueW(
		  LPCWSTR lpSystemName,
		  LPCWSTR lpName,
		  PLUID   lpLuid
		);
	*/
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeDebugPrivilege"), &luid)
	if err != nil {
		//logging.Logger.Println("LookupPrivilegeValueW Failed: ", err)
	}

	privilege := windows.Tokenprivileges{}
	privilege.PrivilegeCount = 1
	privilege.Privileges[0].Luid = luid
	privilege.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED

	/*
		BOOL AdjustTokenPrivileges(
		  HANDLE            TokenHandle,
		  BOOL              DisableAllPrivileges,
		  PTOKEN_PRIVILEGES NewState,
		  DWORD             BufferLength,
		  PTOKEN_PRIVILEGES PreviousState,
		  PDWORD            ReturnLength
		);
	*/
	err = windows.AdjustTokenPrivileges(tokenHandle, false, &privilege, 0, nil, nil)
	if err != nil {
		//logging.Logger.Println("AdjustTokenPrivileges Failed: ", err)
	}
}

//Original code from https://coolaj86.com/articles/golang-and-windows-and-admins-oh-my/

//AdminOrElevated checks to see if the user is admin and if it is elevated
func AdminOrElevated() (elevated bool, admin bool) {
	var sid *windows.SID

	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		//logging.Logger.Println("SID Error: %s", err)
	}

	token := windows.GetCurrentProcessToken()

	member, err := token.IsMember(sid)
	if err != nil {
		//logging.Logger.Println("Token Membership Error: %s", err)
	}

	if token.IsElevated() == true {
		elevated = true
	} else {
		elevated = false
	}

	if member == true {
		admin = true
	} else {
		admin = false
	}

	return elevated, admin
}
