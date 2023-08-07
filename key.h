#pragma once
#include <cstdint>

bool create_roundkey(uint8_t const* key, uint8_t const* iv, uint64_t counter, uint8_t* roundkey);

