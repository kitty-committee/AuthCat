
#ifndef COMMON_HPP
#define COMMON_HPP

#include <fstream>
#include <nlohmann/json.hpp>
#include <string>

namespace nathcat {
namespace auth {
/**
 * @brief Get the program configuration
 *
 * @param path The file location of the config
 */
template <typename Conf> Conf getConfig(std::string path) {
  std::ifstream f(path);
  nlohmann::json data = nlohmann::json::parse(f);

  f.close();
  return data.get<Conf>();
}

class AuthFailed : public std::exception {};

class NotFound : public std::exception {};

} // namespace auth
} // namespace nathcat

#endif
