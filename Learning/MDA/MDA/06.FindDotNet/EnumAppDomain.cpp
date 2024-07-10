#include "Defines.h"

HRESULT EnumerateAppDomains(HANDLE processHandle) {
    ICLRMetaHost *pMetaHost = NULL;
    HRESULT hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pMetaHost));
    if (FAILED(hr)) {
        printf("Failed to create CLR Meta Host. HRESULT: %s", hr);
        return hr;
    }

    IEnumUnknown *pEnum = NULL;
    hr = pMetaHost->EnumerateLoadedRuntimes(processHandle, &pEnum);
    if (FAILED(hr)) {
        printf("Failed. HRESULT: %s", hr);
        return hr;
    }

    ICLRRuntimeInfo *pRuntimeInfo = NULL;
    while (pEnum->Next(1, (IUnknown**)&pRuntimeInfo, NULL) == S_OK) {
        // Extract version, enumerate AppDomains, etc.
        printf("Found a CLR");
    }

    return S_OK;
}
