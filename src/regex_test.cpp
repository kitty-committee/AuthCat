#include <iostream>
#include <regex.h>
#include <regex>
int main() {
  std::regex r("\\$\\$(.*)\\$\\$");
  std::string msg = "hello,\nhow is, $$name$$ today ?";
  std::smatch parameter_match;

  std::string subbedContent = "";
  std::string subContent(msg);
  while (std::regex_search(subContent, parameter_match, r)) {
    std::cout << "Found match: " << parameter_match[0] << std::endl;

    // Add the prefix of the match to the subbed content
    subbedContent.append(parameter_match.prefix().str());
    // Add the parameter value
    subbedContent.append("subbed");
    // Get the remainder of the content
    subContent = parameter_match.suffix().str();
  }

  // There are no more matches, append the remainder of the content and return.
  subbedContent.append(subContent);

  std::cout << subbedContent << std::endl;
  return 0;
}
