/*
 * safeseh_dump.cpp
 *
 * a command line utility for listing the SAFESEH exception handlers in a process
 * sean larsson, idefense labs
 * infamous41md<>gmail<>com
 */

#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>
#include <psapi.h>

#pragma comment(lib, "psapi")
#pragma comment(lib, "dbghelp")

// return values for get_safeseh()
enum {
	NO_SAFESEH, HAS_SAFESEH, MANAGED_CODE, NO_SEH, RET_FAIL
};

enum {
	XP = 0, SERVER_2K3, VISTA_WIN7
};

//these are offsets for the DllCharacteristics flag in the
//optional header structure, indexed by above enum
int dll_chars_offset[] = {
0x5f, 0x5f, 0x5e
};

//same goes for the actual flag bit
int dll_chars_flag[] = {
0x4, 0x4, 0x400
};

char *os_names[] = { "XP", "SERVER 2K3", "VISTA_WIN7" };

//
int os_type = -1;

//////////////////////////////
//////////////////////////////

//
void die(char *message)
{	
	DWORD	err = GetLastError();	
	printf("%s failed with error %u\n", message, err);
	exit(1);
}

// enable debug privs, borrowed from msdn
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if ( !LookupPrivilegeValue( 
			NULL,            // lookup privilege on local system
			lpszPrivilege,   // privilege to lookup 
			&luid ) )        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError() ); 
		return FALSE; 
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.
	if ( !AdjustTokenPrivileges(
		hToken, 
		FALSE, 
		&tp, 
		sizeof(TOKEN_PRIVILEGES), 
		(PTOKEN_PRIVILEGES) NULL, 
		(PDWORD) NULL) )
	{ 
		printf("AdjustTokenPrivileges error: %u\n", GetLastError() ); 
		return FALSE; 
	} 

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		//printf("The token does not have the specified privilege. \n");
		return FALSE;
	} 

	return TRUE;
}


// do the actual parsing of the image config directories to see if
// this module has a safe seh table or not
//
// @param proc - process handle
// @param handle - dll base address
// @param table - output safe seh table
// @param count - output seh count
//
// @return NO_SAFESEH | HAS_SAFESEH | MANAGED_CODE | NO_SEH
//
int parse_config_dirs(HANDLE proc, HMODULE handle, ULONG **table, ULONG *count)
{
	UCHAR	*dentry = NULL;
	ULONG	size = 0,	*safe_table = NULL;
	IMAGE_NT_HEADERS		*nthdr;
	IMAGE_LOAD_CONFIG_DIRECTORY32	*config;
	DWORD	n = 0, i = 0, sz = 0;
	int	ret = 0;
	UCHAR	*tmp = NULL;
	SIZE_T	num = 0;

	//load the NT header
	nthdr = ImageNtHeader(handle);
	if(nthdr == NULL)
		die("ImageNtHeader");

	//dll with no seh handlers at all, this means we can't jump into it.
	//the offset and bit tested differ on vista/7
	tmp = (UCHAR *)nthdr;
	if( ( *(WORD *)(tmp + dll_chars_offset[os_type]) ) & dll_chars_flag[os_type])
		return NO_SEH;

	//load the load config type entry
	config = (IMAGE_LOAD_CONFIG_DIRECTORY32 *)ImageDirectoryEntryToDataEx(handle,
					TRUE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &size, NULL);

	// see if the config structure has valid handler table
	// the version specific tests are crucial as vista + server + xp behave different
	if(config != NULL && 
			(
				( (os_type == SERVER_2K3 || os_type == VISTA_WIN7) && size == 0x40) ||
				( os_type == XP && (size == 0x40 || size == config->Size) )
			) 
			&&
			config->Size >= 0x48 &&
			config->SEHandlerTable != 0 && config->SEHandlerCount != 0){
		
		//create the table
		n = config->SEHandlerCount;
		safe_table = (ULONG *)calloc(n, sizeof(*table));
		if(safe_table == NULL)
			die("calloc");

		sz = n * sizeof(*safe_table);
		num = 0;
		if(ReadProcessMemory(proc, (LPCVOID)config->SEHandlerTable,
							safe_table, sz, &num) == FALSE)
			die("ReadProcessMemory(), parse_config_dirs()");
		if(num != sz)
			die("Didn't read as many bytes from process as needed");
		
		*count = n;
		*table = safe_table;
		ret = HAS_SAFESEH;
	}else{

		//load the COM_DESCRIPTOR type entry, check for managed code
		dentry = (UCHAR *)ImageDirectoryEntryToDataEx(handle, TRUE, 0xe, &size, NULL);
		if(dentry == NULL || !(*((char *)dentry + 0x10) & 1)){
			ret = NO_SAFESEH;
		}else
			ret = MANAGED_CODE;
	}

	return ret;
}

//
// find the safe seh handler table for a dll in a process
// this reads the handler table from a dll in a running process
//
// @param proc - process handle
// @param handle - module handle/base addr
// @param table - dynamically allocated safeseh table
// @param count - number of elements in table
//
// @return NO_SAFESEH | HAS_SAFESEH | MANAGED_CODE | NO_SEH
//
int get_safeseh(HANDLE proc, HMODULE dll_handle, ULONG **table, ULONG *count)
{
	DWORD	n = 0, sz = 0;
	int	ret = 0;
	MODULEINFO	mod;
	UCHAR	*pmem = NULL;

	memset(&mod, 0, sizeof(mod));

	//get the module size
	if(GetModuleInformation(proc, dll_handle, &mod, sizeof(mod)) == FALSE)
		die("GetModuleInformation()");
	sz = mod.SizeOfImage;

	pmem = (UCHAR *)calloc(1, sz);
	if(pmem == NULL)
		die("calloc");

	//read in the entire module
	if(ReadProcessMemory(proc, mod.lpBaseOfDll, pmem, sz, &n) == FALSE){
		
		if(GetLastError() == 299){
			printf("BUG: Congrats, you found that MODULEINFORMATION.SizeOfImage lies about actual size in WOW64 dlls!\n");
		}
		free(pmem);
		return RET_FAIL;
	}
	if(n != sz)
		die("Didn't read as many bytes from process as needed");

	ret = parse_config_dirs(proc, (HMODULE)pmem, table, count);

	free(pmem);
	return ret;
}

//
// find the safe seh handler table for a dll
// this loads a dll in the current process rather than attaching to
// a running one
//
// @param dll - the dll to find table for
// @param table - dynamically allocated safeseh table
// @param count - number of elements in table
//
// @return NO_SAFESEH | HAS_SAFESEH | MANAGED_CODE | NO_SEH
//
int get_safeseh(char *dll, ULONG **table, ULONG *count)
{
	HMODULE	handle;
	int	ret = 0;

	handle = LoadLibraryExA(dll, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if(handle == NULL)
		die("LoadLibraryEx()");

	ret = parse_config_dirs(GetCurrentProcess(), handle, table, count);
	
	FreeLibrary(handle);
	return ret;
}


// print out the safe seh table for a loaded/nonloaded dll
// passing the proc or dll_base parameter as NULL means
// load the dll into this process and find the table
//
// @param proc - process handle, or NULL if looking up a non loaded dll
// @param dll - the name of dll to find table for
// @param dll_base - dll base address or NULL if looking up non loaded dll
//
void phandlers(HANDLE proc, char *dll, HMODULE dll_base)
{
	ULONG	*table = NULL, count = 0, size = 0;
	int	ret = 0;
	MODULEINFO	info;

	if(proc)
	{
		memset(&info, 0, sizeof(info));
		if (GetModuleInformation(proc, dll_base, &info, sizeof(info)) == FALSE)
			die("GetModuleInformation()");
		printf("\n[*] Getting table for %s [ %#lx - %#lx ]\n", dll, dll_base, (ULONG)dll_base + info.SizeOfImage);
	}
	else
		printf("\n[*] Getting table for %s\n", dll);
	
	if(proc == NULL || dll_base == NULL)
		ret = get_safeseh(dll, &table, &count);
	else
		ret = get_safeseh(proc, dll_base, &table, &count);

	switch(ret){
		case HAS_SAFESEH:
			printf("    [*] %s has safe seh\n", dll);
			break;
		case NO_SAFESEH:
			printf("    [*] %s DOES NOT HAVE safe seh (KAPWWN!)\n", dll);
			return;
		case NO_SEH:
			printf("    [*] %s has no seh at all (can't use it)\n", dll);
			return;
		case MANAGED_CODE:
			printf("    [*] %s is managed code (can't use it)\n", dll);
			return;
		case RET_FAIL:
			return;
	}

	printf("    [*] %s has %d safe handlers\n", dll, count);
	for(DWORD i = 0; i < count; i++){
		
		if(dll_base != NULL)
			printf("    [**] handler @address %#x\n", table[i] + dll_base);
		else
			printf("    [**] handler @offset %#x\n", table[i]);
	}

	free(table);
}

void enable_debug()
{
	HANDLE	tok;

	//enable debugging
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &tok);
	SetPrivilege(tok, L"SeDebugPrivilege", TRUE);
	CloseHandle(tok);
}

//
void enum_proc_safeseh(DWORD pid)
{
	HANDLE	proc;
	HMODULE	mods[0x1000];
	DWORD	modsz = 0,	*table = NULL, count = 0;
	char	name[0x1000];

	printf("[!] Dumping safeseh for process id %d\n\n", pid);

	//get a process handle
	proc  = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if(proc == NULL)
		die("OpenProcess");

	//get a list of all loaded modules
	if(EnumProcessModulesEx(proc, mods, 0x1000*sizeof(HMODULE), &modsz, LIST_MODULES_ALL) == FALSE){
		
		//occurs on WOW64 when trying to list a 64bit processes modules
		if(GetLastError() == 299){
			printf("ERROR: Are you in WOW64 trying to enumerate a 64bit processes modules?\nNot possible, use 64bit version.\n");
			exit(1);
		}else
			die("EnumProcessModulesEx");
	}

	//get handler table for any dll/exe in process
	for(DWORD i = 0; i < modsz / sizeof(mods[0]); i++){
		
		if(GetModuleBaseNameA(proc, mods[i], name, sizeof(name)) == 0)
			die("GetModuleBaseName");

		phandlers(proc, name, mods[i]);
	}

	CloseHandle(proc);
}

//
void get_os_type()
{
	OSVERSIONINFO	vers;

	memset(&vers, 0, sizeof(vers));
	vers.dwOSVersionInfoSize = sizeof(vers);
	
	if(GetVersionEx(&vers) == FALSE)
		die("GetVersionEx()");
	
	//limited checks, assumes xp sp2 if it finds xp
	if(vers.dwMajorVersion == 5){
		if(vers.dwMinorVersion == 1)
			os_type = XP;
		else if(vers.dwMinorVersion == 2)
			os_type = SERVER_2K3;
	}else if(vers.dwMajorVersion == 6)
		if(vers.dwMinorVersion == 0 || vers.dwMinorVersion == 1)
			os_type = VISTA_WIN7;
	
	if(os_type == -1){
		printf("Major %d, minor %d\n", vers.dwMajorVersion, vers.dwMinorVersion);
		die("Can't determine OS type");
	}
}

//get the pid of a process by name
//will return the first match if there are multiple matches
DWORD get_pid_by_name(char *name)
{
	HANDLE	hproc;
	char	pname[0x500],	*exename = NULL;
	DWORD	pids[0x1000],	nb = 0,	found_pid = -1;

	if(EnumProcesses(pids, sizeof(pids), &nb) == FALSE)
		die("EnumProcesses()");

	for(DWORD i = 0; i < nb / sizeof(DWORD) && found_pid == -1; i++){

		//not sure if there is an easier way to do this, MSDN uses this method
		hproc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pids[i]);
		if(hproc != NULL){
			if(GetProcessImageFileNameA(hproc, pname, sizeof(pname)) == 0){
				CloseHandle(hproc);
				continue;
			}
			
			//find the last slash to get the actual .exe name
			exename = strrchr(pname, '\\');
			if(exename == NULL)
				exename = pname;
			else
				exename++;

			//see if it matches
			if(strncmp(name, exename, strlen(name)) == 0){
				found_pid = pids[i];
			}
			
			//free handle
			CloseHandle(hproc);
		}
	}

	return found_pid;
}

/*
*/
int main(int argc, char *argv[])
{
	DWORD	pid = -1;

	//
	if(argc < 2){
		printf("Usage: %s [ -p process id ] [ -c prcess name ] or [ list of dll names ]\n", argv[0]);
		return 1;
	}

	//will silently fail for unpriv user
	enable_debug();

	get_os_type();

	//dump the handlers for a given process id
	if(argc == 3 && (argv[1][1] == 'p' || argv[1][1] == 'c') ){
		
		if(argv[1][1] == 'p')
			pid = atoi(argv[2]);
		else{
			pid = get_pid_by_name(argv[2]);
			if(pid == -1)
				die("Can't resolve process name to pid");
		}

		enum_proc_safeseh(pid);
	}else{
		
		//dump handlers for dlls listed on command line
		for(int i = 1; i < argc; i++){
			phandlers(NULL, argv[i], NULL);
		}
	}

	return 0;
}

