/*
This file is a part of the NVDA project.
URL: http://www.nvda-project.org/
Copyright 2006-2010 NVDA contributers.
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2.0, as published by
    the Free Software Foundation.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
This license can be found at:
http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
*/

#include <cstdio>
#include <cwchar>
#include <string>
#include <locale>
#include <codecvt>
#include <vector>
#define WIN32_LEAN_AND_MEAN 
#define CINTERFACE
#include <windows.h>
#include <objbase.h>
#include <rpcproxy.h>
#include <common/log.h>
#include "COMProxyRegistration.h"

using namespace std;

typedef void(RPC_ENTRY *LPFNGETPROXYDLLINFO)(ProxyFileInfo***, CLSID**);

COMProxyRegistration_t* registerCOMProxy(wchar_t* dllPath) {
	int res;
	// load the proxy dll
	HMODULE dllHandle=LoadLibrary(dllPath);
	if(dllHandle==NULL) {
		LOG_ERROR(L"LoadLibrary failed for "<<dllPath);
		return nullptr;
	}
	// look up the GetProxyDllInfo function on the proxy dll 
	LPFNGETPROXYDLLINFO Dll_GetProxyDllInfo=(LPFNGETPROXYDLLINFO)GetProcAddress(dllHandle,"GetProxyDllInfo");
	if(Dll_GetProxyDllInfo==NULL) {
		LOG_ERROR(L"GetProxyDllInfo function not found in "<<dllPath);
		FreeLibrary(dllHandle);
		return nullptr;
	}
	// Fetch the proxy information from the dll (interface IIDs and the proxy stub CLSID)
	CLSID* pProxyClsid=NULL;
	ProxyFileInfo** pProxyInfo=NULL;
	Dll_GetProxyDllInfo(&pProxyInfo,&pProxyClsid);
	if(!pProxyClsid||!pProxyInfo) {
		LOG_ERROR(L"Could not fetch proxy information from "<<dllPath);
		FreeLibrary(dllHandle);
		return nullptr;
	}
	// Create and activate an activation context using the manifest in the proxy dll 
	// to temporarily register the proxy dll's class object
	ACTCTX actCtx={0};
	actCtx.cbSize=sizeof(actCtx);
	actCtx.dwFlags=ACTCTX_FLAG_HMODULE_VALID|ACTCTX_FLAG_RESOURCE_NAME_VALID;
	actCtx.lpResourceName=MAKEINTRESOURCE(2);
	actCtx.hModule=dllHandle;
	HANDLE hActCtx=CreateActCtx(&actCtx);
	if(hActCtx==NULL) {
		LOG_ERROR(L"Could not create activation context for "<<dllPath);
		FreeLibrary(dllHandle);
		return nullptr;
	}
	ULONG_PTR actCtxCookie;
	if(!ActivateActCtx(hActCtx,&actCtxCookie)) {
		LOG_ERROR(L"Error activating activation context for "<<dllPath);
		ReleaseActCtx(hActCtx);
		FreeLibrary(dllHandle);
		return nullptr;
	}
	// Fetch the class object (which will come from the proxy dll)
	IUnknown* ClassObjPunk=NULL;
	res=CoGetClassObject(*pProxyClsid,CLSCTX_INPROC_SERVER,nullptr,IID_IUnknown,(void**)&ClassObjPunk);
	// From here we no longer need the activation context
	DeactivateActCtx(0,actCtxCookie);
	ReleaseActCtx(hActCtx);
	if(res!=S_OK) {
		LOG_ERROR(L"Error fetching class object for "<<dllPath<<L", code "<<res);
		FreeLibrary(dllHandle);
		return nullptr;
	}
	// Re-register the class object with COM now that the activation context is gone.
	// Keeping the class object available to COM, with COM also handling the life time of the proxy dll now
	DWORD dwCookie;
	res=CoRegisterClassObject(*pProxyClsid,ClassObjPunk,CLSCTX_INPROC_SERVER,REGCLS_MULTIPLEUSE,&dwCookie);
	ClassObjPunk->lpVtbl->Release(ClassObjPunk);
	if(res!=S_OK) {
		LOG_ERROR(L"Error registering class object for "<<dllPath<<L", code "<<res);
		FreeLibrary(dllHandle);
		return nullptr;
	}
	COMProxyRegistration_t* reg= new COMProxyRegistration_t();
	reg->dllPath=dllPath;
	reg->classObjectRegistrationCookie=dwCookie;
	// For all interfaces the proxy dll supports, register its CLSID as their proxy stub CLSID
	ProxyFileInfo** tempInfoPtr=pProxyInfo;
	while(*tempInfoPtr) {
		ProxyFileInfo& fileInfo=**tempInfoPtr;
		for(unsigned short idx=0;idx<fileInfo.TableSize;++idx) {
			IID iid=*(fileInfo.pStubVtblList[idx]->header.piid);
			CLSID clsidBackup={0};
			wstring_convert<codecvt_utf8_utf16<wchar_t>> converter;
			wstring name=converter.from_bytes(fileInfo.pNamesArray[idx]);
			if((res=CoGetPSClsid(iid,&clsidBackup))!=S_OK) {
				LOG_INFO(L"No previous PS clsid set for interface "<<name<<L" in "<<dllPath<<L", code "<<res);
			}
			if((res=CoRegisterPSClsid(iid,*pProxyClsid))!=S_OK) {
				LOG_ERROR(L"Unable to register interface "<<name<<L" with proxy stub "<<dllPath<<L", code "<<res);
				continue;
			}
		reg->psClsidBackups.push_back({name,iid,clsidBackup});
		}
		++tempInfoPtr;
	}
	// We can now safely free the proxy dll. COM will keep it loaded or re-load it if needed
	FreeLibrary(dllHandle);
	return reg;
}

bool unregisterCOMProxy(COMProxyRegistration_t* reg) {
	if(!reg) return false;
	HRESULT res;
	for(auto& backup: reg->psClsidBackups) {
			if((res=CoRegisterPSClsid(backup.iid,backup.clsid))!=S_OK) {
				LOG_ERROR(L"Error registering backup PSClsid for interface "<<(backup.name)<<L" from "<<(reg->dllPath)<<L", code "<<res);
			}
	}
	if((res=CoRevokeClassObject((DWORD)(reg->classObjectRegistrationCookie)))!=S_OK) {
		LOG_ERROR(L"Error unregistering class object from "<<(reg->dllPath)<<L", code "<<res);
	} else {
		CoFreeUnusedLibrariesEx(INFINITE,0);
	}
	delete reg;
	return true;
}

