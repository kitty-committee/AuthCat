#include <iostream>
#include <regex.h>
#include <regex>

int main() {
  std::regex r("Basic (.*):(.*)");
  std::string msg = "Basic hello:world";

  std::smatch m;
  if (std::regex_match(msg, m, r)) {
    std::cout << "Matched groups: " << m.size() << std::endl;

    for (int i = 0; i < m.size(); i++) {
      std::cout << "Group " << i << ": " << m[i] << std::endl;
    }
  } else {
    std::cout << "Msg does not match" << std::endl;
  }
}
