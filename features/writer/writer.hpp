#pragma once

#include <string>

#include "../natives/natives.hpp"
#include "../parser/parser.hpp"

bool write_sdk(const sdk_model& m, const std::wstring& dir);
bool write_natives(const std::vector<native_info>& natives, const std::wstring& dir);
