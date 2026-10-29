#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

struct native_info
{
    uint64_t hash = 0;
    uint64_t handler = 0;
    uint64_t body = 0;
    uint64_t command = 0;
    uint64_t original = 0;
    int command_index = -1;
    int call_count = 0;
    std::vector<uint32_t> calls;
    std::string name;
    std::string ns;
};

bool trace_handler(const uint8_t* base, uint32_t size, uint32_t handler, std::vector<uint32_t>& calls, uint32_t& body);
bool collect_natives(HMODULE game, std::vector<native_info>& out);
void name_natives(std::vector<native_info>& natives, const std::wstring& path);
void pick_commands(std::vector<native_info>& natives);
