#pragma once

namespace Hijack {
	BOOLEAN HijackViaHook(process::Process& process, PVOID entry, LPCWSTR moduleName, LPCSTR functionName);
}