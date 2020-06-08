#include "Timing.h"

#include <chrono>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>

std::map<std::string, uint64_t> measurements;
std::map<std::string, uint64_t> num_measurements;
std::map<std::string, std::chrono::time_point<std::chrono::high_resolution_clock>> measure_starts;

std::string Timing::FmtTime(uint64_t time)
	{
	std::stringstream ss;
	ss << std::setprecision(3) << std::fixed << std::setfill(' ') << std::setw(11);
	if ( time < 10'000 )
		ss << (double)time << "ns";
	else if ( time < 10'000'000 )
		ss << time / 1E3 << "µs";
	else if ( time < 10'000'000'000 )
		ss << time / 1E6 << "ms";
	else
		ss << time / 1E9 << "s";

	return ss.str();
	}

void Timing::StartTM(const std::string& identifier)
	{
	if ( measure_starts.count(identifier) != 0 )
		{
		std::cout << "The timer '" << identifier << "' is already running!" << std::endl;
		abort();
		}

	measure_starts.emplace(identifier, std::chrono::high_resolution_clock::now());
	}

void Timing::EndTM(const std::string& identifier)
	{
	auto end = std::chrono::high_resolution_clock::now();
	if ( measure_starts.count(identifier) == 0 )
		{
		std::cout << "The timer '" << identifier << "' isn't running!" << std::endl;
		abort();
		}

	long time = std::chrono::duration_cast<std::chrono::nanoseconds>(end - measure_starts.at(identifier)).count();
	if ( ! measurements.count(identifier) )
		{
		measurements.emplace(identifier, time);
		num_measurements.emplace(identifier, 1);
		}
	else
		{
		measurements.at(identifier) += time;
		num_measurements.at(identifier)++;
		}

	measure_starts.erase(identifier);
	}

size_t GetPadding()
	{
	size_t max = 0;
	for ( const auto& current : measurements )
		max = std::max(current.first.length(), max);

	return max;
	}

void Timing::PrintAllTM()
	{
	if ( ! measure_starts.empty() )
		{
		std::cout << "There is still a timer running: " << measure_starts.begin()->first << std::endl;
		abort();
		}

	size_t padding = GetPadding();

	std::cout << std::endl
			  << "##### TIMINGS #####" << std::endl;

	std::cout << std::setprecision(2) << std::fixed;
	for ( const auto& entry : measurements )
		{
		int64_t new_time = entry.second;
		std::cout << std::left << std::setfill(' ') << std::setw(padding) << entry.first << std::right;
		std::cout << " - ";
		std::cout << FmtTime(new_time);
		std::cout << std::endl;
		}
	}

void Timing::PrintAllTMRelative(const std::string& identifier)
	{
	if ( ! measure_starts.empty() )
		{
		std::cout << "There is still a timer running: " << measure_starts.begin()->first << std::endl;
		abort();
		}

	if ( measurements.count(identifier) == 0 )
		{
		std::cout << "The base timer doesn't exist!" << std::endl;
		abort();
		}

	size_t padding = GetPadding();

	std::cout << std::endl
			  << "##### TIMINGS #####" << std::endl;
	int64_t base_time = measurements[identifier];
	std::cout << std::left << std::setfill(' ') << std::setw(padding) << identifier << " - " << std::right;
	std::cout << FmtTime(base_time) << std::endl;

	std::cout << std::setprecision(2) << std::fixed;
	for ( const auto& entry : measurements )
		{
		if ( entry.first == identifier )
 			continue;

		int64_t new_time = entry.second;
		std::cout << std::left << std::setfill(' ') << std::setw(padding) << entry.first << std::right;
		std::cout << " - ";
		std::cout << FmtTime(new_time);
		std::cout << ", ";
		std::cout << std::setfill(' ') << std::setw(7) << (double)(new_time - base_time) / base_time * 100;
		std::cout << "%";
		std::cout << ", factor " << std::setfill(' ') << std::setw(5) << (double)new_time / base_time << std::endl;
		}
	}

void Timing::PrintAllTMAvg()
	{
	if ( ! measure_starts.empty() )
		{
		std::cout << "There is still a timer running: " << measure_starts.begin()->first << std::endl;
		abort();
		}

	if ( num_measurements.size() != measurements.size() )
		{
		std::cout << "The number of measurement groups is inconsistent!" << std::endl;
		abort();
		}

	size_t padding = GetPadding();

	std::cout << std::endl
			  << "##### TIME PER OPERATION #####" << std::endl;
	std::cout << std::setprecision(2) << std::fixed;
	for ( const auto& current : measurements )
		{
		uint64_t count = num_measurements.at(current.first);
		int64_t new_avg = current.second / count;
		std::cout << std::left << std::setfill(' ') << std::setw(padding) << current.first << std::right;
		std::cout << " - ";
		std::cout << FmtTime(new_avg);
		std::cout << std::endl;
		}
	}

void Timing::PrintAllTMAvgRelative(const std::string& identifier)
	{
	if ( ! measure_starts.empty() )
		{
		std::cout << "There is still a timer running: " << measure_starts.begin()->first << std::endl;
		abort();
		}

	if ( num_measurements.size() != measurements.size() )
		{
		std::cout << "The number of measurement groups is inconsistent!" << std::endl;
		abort();
		}

	if ( measurements.count(identifier) == 0 )
		{
		std::cout << "The base timer doesn't exist!" << std::endl;
		abort();
		}

	size_t padding = GetPadding();

	std::cout << std::endl
			  << "##### TIME PER OPERATION #####" << std::endl;
	int64_t base_avg = measurements[identifier] / num_measurements[identifier];
	std::cout << std::left << std::setfill(' ') << std::setw(padding) << identifier << " - " << std::right;
	std::cout << FmtTime(base_avg) << std::endl;

	std::cout << std::setprecision(2) << std::fixed;
	for ( const auto& current : measurements )
		{
		if ( current.first == identifier )
			continue;

		uint64_t count = num_measurements.at(current.first);
		int64_t new_avg = current.second / count;
		std::cout << std::left << std::setfill(' ') << std::setw(padding) << current.first << std::right;
		std::cout << " - ";
		std::cout << FmtTime(new_avg);
		std::cout << ", ";
		std::cout << std::setfill(' ') << std::setw(7) << (double)(new_avg - base_avg) / base_avg * 100;
		std::cout << "%";
		std::cout << ", factor " << std::setfill(' ') << std::setw(5) << (double)new_avg / base_avg << std::endl;
		}
	}

void Timing::PrintAllTMOPS()
	{
	if ( ! measure_starts.empty() )
		{
		std::cout << "There is still a timer running: " << measure_starts.begin()->first << std::endl;
		abort();
		}

	if ( num_measurements.size() != measurements.size() )
		{
		std::cout << "The number of measurement groups is inconsistent!" << std::endl;
		abort();
		}

	size_t padding = GetPadding();

	std::cout << std::endl
			  << "##### OPERATIONS PER SECOND #####" << std::endl;
	std::cout << std::setprecision(2) << std::fixed;
	for ( const auto& current : measurements )
		{
		double time_in_secs = current.second / 1E9;
		int64_t new_ops = num_measurements.at(current.first) / time_in_secs;
		std::cout << std::left << std::setfill(' ') << std::setw(padding) << current.first << std::right;
		std::cout << " - ";
		std::cout.imbue(std::locale(""));
		std::cout << std::setfill(' ') << std::setw(13) << new_ops;
		std::cout << " Operations/s";
		std::cout << std::endl;
		}
	}

void Timing::PrintAllTMOPSRelative(const std::string& identifier)
	{
	if ( ! measure_starts.empty() )
		{
		std::cout << "There is still a timer running: " << measure_starts.begin()->first << std::endl;
		abort();
		}

	if ( num_measurements.size() != measurements.size() )
		{
		std::cout << "The number of measurement groups is inconsistent!" << std::endl;
		abort();
		}

	if ( measurements.count(identifier) == 0 )
		{
		std::cout << "The base timer doesn't exist!" << std::endl;
		abort();
		}

	size_t padding = GetPadding();

	std::cout << std::endl
			  << "##### OPERATIONS PER SECOND #####" << std::endl;
	int64_t base_ops = num_measurements[identifier] / (measurements[identifier] / 1E9);
	std::cout << std::left << std::setfill(' ') << std::setw(padding) << identifier << " - " << std::right;
	std::cout.imbue(std::locale(""));
	std::cout << std::setfill(' ') << std::setw(13) << base_ops;
	std::cout << " Operations/s" << std::endl;
	std::cout.imbue(std::locale("en_US.UTF8"));

	std::cout << std::setprecision(2) << std::fixed;
	for ( const auto& current : measurements )
		{
		if ( current.first == identifier )
			continue;

		double time_in_secs = current.second / 1E9;
		int64_t new_ops = num_measurements.at(current.first) / time_in_secs;
		std::cout << std::left << std::setfill(' ') << std::setw(padding) << current.first << std::right;
		std::cout << " - ";
		std::cout.imbue(std::locale(""));
		std::cout << std::setfill(' ') << std::setw(13) << new_ops;
		std::cout << " Operations/s";
		std::cout.imbue(std::locale("en_US.UTF8"));
		std::cout << ", ";
		std::cout << std::setfill(' ') << std::setw(7) << (double)(new_ops - base_ops) / base_ops * 100;
		std::cout << "%";
		std::cout << ", factor " << std::setfill(' ') << std::setw(5) << (double)new_ops / base_ops << std::endl;
		}
	}

void Timing::ToCSV(const std::string& name)
	{
	if ( ! measure_starts.empty() )
		{
		std::cout << "There is still a timer running: " << measure_starts.begin()->first << std::endl;
		abort();
		}

	if ( num_measurements.size() != measurements.size() )
		{
		std::cout << "The number of measurement groups is inconsistent!" << std::endl;
		abort();
		}

	// Open csv file
	std::ofstream csv;
	std::stringstream ss;
	ss << "benchmark_" << name << ".csv";
	csv.open(ss.str());

	csv << "name,runtime,time/op,op/s" << std::endl;
	for ( const auto& current : measurements )
		{
		csv << current.first << "," << current.second << "," << current.second / num_measurements.at(current.first)
			<< "," << static_cast<int64_t>(num_measurements.at(current.first) / (current.second / 1E9)) << std::endl;
		}

	csv.close();
	}
