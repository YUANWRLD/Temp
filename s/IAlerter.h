#pragma once
#include <string>

class IAlerter {
public:
    virtual ~IAlerter() = default;
    virtual void TriggerAlert(const std::string& title, const std::string& description) = 0;
};