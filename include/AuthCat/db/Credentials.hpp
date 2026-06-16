/**
 * @file Credentials.hpp
 */

#ifndef _CREDENTIALS
#define _CREDENTIALS

#include <string>
namespace nathcat {
namespace auth {
class Credentials {
public:
  const std::string username;
  const std::string password;

  Credentials(std::string username, std::string password)
      : username(username), password(password) {}
};

class Credentials_Token {
public:
  const std::string token;

  Credentials_Token(std::string token) : token(token) {}
};

} // namespace auth
} // namespace nathcat

#endif
