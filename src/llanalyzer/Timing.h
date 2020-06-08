#pragma once

#include <string>

namespace Timing {

std::string FmtTime(uint64_t time);
void StartTM(const std::string& identifier);
void EndTM(const std::string& identifier);
void PrintAllTM();
void PrintAllTMRelative(const std::string& identifier);
void PrintAllTMAvg();
void PrintAllTMAvgRelative(const std::string& identifier);
void PrintAllTMOPS();
void PrintAllTMOPSRelative(const std::string& identifier);
void ToCSV(const std::string& name);

}
