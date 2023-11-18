#include <string>
#include <iostream>
#include <sstream>
#include <map>

std::map<std::string, std::string> ParseJson(const std::string& jsonResponse) {
    std::map<std::string, std::string> keyValuePairs;
    std::stringstream ss(jsonResponse);
    std::string item;

    // Remove the opening and closing braces
    ss.ignore(1, '{');
    while (std::getline(ss, item, ',')) {
        std::string key, value;
        std::stringstream itemStream(item);

        // Get the key and value from the item
        std::getline(itemStream, key, ':');
        std::getline(itemStream, value, ':');

        // Clean up the key and value strings
        key.erase(remove(key.begin(), key.end(), '\"'), key.end());
        value.erase(remove(value.begin(), value.end(), '\"'), value.end());
        keyValuePairs[key] = value;
    }

    return keyValuePairs;
}

int main() {
    std::string jsonResponse = "{\"Input\":\"testInput\",\"Command\":\"testCommand\",\"Args\":\"testArgs\"}";
    auto parsedJson = ParseJson(jsonResponse);

    for (const auto& pair : parsedJson) {
        std::cout << pair.first << " = " << pair.second << std::endl;
    }

    return 0;
}
