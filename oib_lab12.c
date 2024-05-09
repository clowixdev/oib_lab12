#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <aclapi.h>
#define PATH_LENGTH 260

void clear(char* arr, int len) {
    for (int i = 0; i < len; i++) {
        arr[i] = '\0';
    }
}

void opening(LPCSTR file_name)
{
	HANDLE file = NULL;
	file = CreateFileA(file_name, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		DWORD error = GetLastError();
		printf("Error %d occurred while creating or opening file\n", error);
		return;
	}

}
void print(LPCSTR file_name)
{
	DWORD error = 0;
	PACL pacl = NULL;//ccccccccc cc cccc cccccccc ccccccc
	PSECURITY_DESCRIPTOR psd = NULL;//cccccccccc cccccccccccPSID p_user_sid;
	PSID p_user_sid;
	SID_NAME_USE siduse;
	
	ACCESS_MASK AccessRights = 0;
	DWORD dwsize = 260;
	char answer = 0;
	LPTSTR domain = (LPTSTR)malloc(512), owner = (LPTSTR)malloc(512);
	LPTSTR  user = (LPTSTR)malloc(260);
	PTRUSTEE pTrustee = (PTRUSTEE)malloc(sizeof(TRUSTEE));
	if (pTrustee) {
		pTrustee->TrusteeForm = TRUSTEE_IS_NAME;
		pTrustee->TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	}

	error = GetNamedSecurityInfoA(file_name, SE_FILE_OBJECT,	DACL_SECURITY_INFORMATION |	
		OWNER_SECURITY_INFORMATION |	GROUP_SECURITY_INFORMATION,	&p_user_sid, NULL, &pacl, NULL, &psd);
	if (error != ERROR_SUCCESS)
	{
		printf("Something went wrong with getting PACL.GetNamedSecurityInfo : %u \n",error);
		return;
	}

	if (!LookupAccountSid(NULL,p_user_sid,	owner,&dwsize,	domain,	&dwsize,&siduse)) 
	{
		error = GetLastError();
		printf("Search by SID was failed. Error code: %d\n", error);
		return;
	}
	answer = 0;
	printf("Owner name: %s\nDo you want to check access rights(y/n)? >>> ", owner);
	fflush(stdin);
	scanf("%c", &answer);
	if (answer == 'y')
	{
		printf("Enter username>>>> ");
		getchar();
		scanf("%s", user);
		if (pTrustee) pTrustee->ptstrName = user;
		if (pTrustee)  
			GetEffectiveRightsFromAcl(pacl,pTrustee,&AccessRights);
		printf("User %s has the following rights:  ", user);
		if (((AccessRights & KEY_ALL_ACCESS) == KEY_ALL_ACCESS))//c AccessRights cccccccc cccccc ccc ccccc c cccccccccccc ccccc, ccccccc cccccccccc cccccc cccccc ccccccccc ccccccccc, c cc cccccc ccccccccc
		{
			printf("All possible access rights to the file\n");
		}
		else if (((AccessRights & KEY_READ) == KEY_READ))
			printf("The right to read the corresponding file data\n");
		else if (((AccessRights & KEY_WRITE) == KEY_WRITE))
			printf("The right to write data to the file.\n");
		else if (((AccessRights & KEY_EVENT) == KEY_EVENT))
			printf("Right to execute file\n");
		else printf("-\n");
	}
	else if (answer == 'n')
	{
		printf("OKK :((\n");
		return;
	}
	else
	{
		printf("error input :((\nTry again.");
		return;
	}
}

void change(LPTSTR file_name)
{
	DWORD error;
	PSECURITY_DESCRIPTOR presecurity_descriptor;
	TCHAR username[260];
	DWORD AccesPermissions[] = { GENERIC_ALL, FILE_READ_DATA, FILE_WRITE_DATA, GENERIC_EXECUTE };
	PACL oldacl = NULL, newacl = NULL;
	EXPLICIT_ACCESS explicit_access;
	char answer1=0,answer2=0;
	printf("Enter username: ");
	scanf("%s", username);
	error = GetNamedSecurityInfoA(file_name, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION |
		OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION, NULL, NULL, &oldacl, NULL, &presecurity_descriptor);
	if (error != ERROR_SUCCESS)
	{
		printf("Something went wrong with getting PACL.GetNamedSecurityInfo : %u \n", error);
		return;
	}
	ZeroMemory(&explicit_access, sizeof(EXPLICIT_ACCESS));
	while (1)
	{
			printf("Enter right to change:\n1)All rights\n2)Reading\n3)Writing\n4)Execution\n>>>>");
			getchar();
			scanf("%d", &answer1);
			if ((answer1 <= 4 && answer1 >= 1))
			{
				explicit_access.grfAccessPermissions = AccesPermissions[answer1 - 1];
				while (1)
				{
					printf("You want to add, remove or exit?(a/r/e) >>> ");
					fflush(stdin);
					scanf("%c", &answer2);
					if (answer2 == 'e') break;
					else if (answer2 == 'a') explicit_access.grfAccessMode = SET_ACCESS;
					else if (answer2 == 'r') explicit_access.grfAccessMode = DENY_ACCESS;
					else { printf("Wrong input :(\n"); continue; }
					explicit_access.grfInheritance = NO_INHERITANCE;
					explicit_access.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
					explicit_access.Trustee.ptstrName = username;
				}
				//oldacl = NULL;
				error = SetEntriesInAcl(1, &explicit_access, oldacl, &newacl);
				if (ERROR_SUCCESS != error)
				{
					printf("SetEntriesInAcl Error %u\n", error);
					return;
				}

				error = SetNamedSecurityInfo(file_name, SE_FILE_OBJECT,
					DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, newacl, NULL);
				if (ERROR_SUCCESS != error) {
					printf("SetNamedSecurityInfo Error %u\n", error);
					return;
				}
				return;
			}
			else
			{
				printf("Wrong input :(\n");
				continue;
			}
		}
}

void read(char* file_name)
{
	FILE* file = fopen(file_name, "r");
	if (file == NULL) printf("The file cannot be read.\n");
	else {
		char data[200] = { 0 };
		fgets(data, 200, file);
		printf("You have enough rights to read this file. First 200 symbols of data:\n %s\n", data);
	}
}

void write(char* file_name)
{
	FILE* file = fopen(file_name, "w");
	if (file == NULL) printf("You have no rights to write in file.\n");
	else {
		char data[200] = { 0 };

		printf("You have enough rights to write in this file. Enter new data:");
		fflush(stdin);
		fgets(data, 200, stdin);//ccccc cc cc ccccc, cccccc c ccc cccc cccc ccc cc ccccc, ccc ccc ccccccccc...
		fputs(data, file);
	}
}

int main(void)
{
	char file_path[PATH_LENGTH] = { 0 };
	int option=123456;
	printf("Enter file path>>>");
	gets(file_path);
	while (1)
	{
		printf("Available options:\n	1)create or open new file\n	2)read file\n	3)write to file\n	4)view rights\n	5)change rights\n        6)exit\nEnter your choice>>>>");
		scanf_s("%d", &option);
		switch (option)
		{
		case 1:
			clear(file_path, PATH_LENGTH);
			printf("Enter file path>>>");
			fflush(stdin);
			gets(file_path);
			opening(file_path);
			break;
		case 2:
			read(file_path);
			break;
		case 3:
			write(file_path);
			break;
		case 4:
			print(file_path);
			break;
		case 5:
			change(file_path);
			break;
		case 6: 
			printf("Shutting down...");
			return 0;
		default: printf("Error input\n Try again\n");
		}
	}
}