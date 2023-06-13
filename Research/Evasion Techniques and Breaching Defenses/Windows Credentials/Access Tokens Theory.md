
Created by the kernel upon user authentication

Contains values linked to a specific user through the SID

Stored in the Kernel

## Integrity Levels

- Low
	- Web Browsers
	- Desktop Applications
- Medium
	- Applications run by user
- High
	- Applications run by administrator
- System
	- Only used for system services

Local Admins receive 2 tokens
- 1 -> Default token, operates a medium integrity
- 2 -> Elevated token, runs on high integrity when (Run As Administrator enabled)

Local Admins regulated by UAC are also called `Split Token Administrators`

Within the tokens, privileges are controlled by 2 bit masks:

- First -> Sets privileges from the token
- Second -> Registers if the present privileges are enabled/disabled and may be dynamically updated through the Win32 API - `AdjustTokenPrivileges`
```cpp
BOOL AdjustTokenPrivileges(
  [in]            HANDLE            TokenHandle,
  [in]            BOOL              DisableAllPrivileges,
  [in, optional]  PTOKEN_PRIVILEGES NewState,
  [in]            DWORD             BufferLength,
  [out, optional] PTOKEN_PRIVILEGES PreviousState,
  [out, optional] PDWORD            ReturnLength
);

/*
* Source:
* https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
*/
```

## View available privileges for current user

```
whoami /priv
```

If the user decides to shutdown a computer (a privilege generally disabled), the backend code will enable the privilege with `AdjustTokenPrivileges` API and power off the system.

It is possible to add additional privileges after a user logs out and logs back in.

This can be done with the Win32 API - `LsaAddAccountRights`
```cpp
NTSTATUS LsaAddAccountRights(
  [in] LSA_HANDLE          PolicyHandle,
  [in] PSID                AccountSid,
  [in] PLSA_UNICODE_STRING UserRights,
  [in] ULONG               CountOfRights
);
/*
* Source:
* https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaaddaccountrights
*/
```

More often, it is done through a Group Policy or locally through `secpol.msc`

Each process has a `Primary Access Token`, from the users token, created during authentication

An `Impersonation Token` which allows it to act on behalf of another user, without their credentials

Impersonation Tokens have 4 levels:
- Anonymous
	- Only allow enumeration of information
- Identification
	- Only allow enumeration of information
- Impersonation
	- Impersonation of client identity
- Delegation
	- Makes it possible to perform sequential access control checks on different machines