#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#define PROGMEM
#include <math.h>
inline float radians(float degrees) { return degrees * 0.017453292519943295f; }
using String = std::string;
class __FlashStringHelper;
