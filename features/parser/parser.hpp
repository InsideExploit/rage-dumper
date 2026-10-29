#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

enum par_type : uint8_t
{
    type_string = 11,
    type_struct = 12,
    type_array = 13,
    type_enum = 14,
    type_bitset = 15,
    type_map = 16,
    type_invalid = 0xFF,
};

struct member_desc
{
    uint8_t type = type_invalid;
    uint8_t subtype = 0;
    uint32_t count = 0;
    std::string ref;
    std::vector<member_desc> sub;
};

struct field_info
{
    std::string name;
    uint64_t offset = 0;
    member_desc desc;
};

struct struct_info
{
    std::string name;
    uint32_t hash = 0;
    uint64_t size = 0;
    std::string base;
    uint64_t base_offset = 0;
    std::vector<field_info> fields;
};

struct enum_info
{
    std::string name;
    uint32_t hash = 0;
    uint32_t size = 4;
    bool bits = false;
    std::vector<std::pair<std::string, int32_t>> values;
};

struct sdk_model
{
    std::vector<struct_info> structs;
    std::vector<enum_info> enums;
    std::vector<uint32_t> missing;
};

bool collect_parser(HMODULE game, const std::wstring& dir, sdk_model& out);
