#pragma once

#include <windows.h>
#include <string>

bool dump_module(HMODULE mod, const std::wstring& path);
