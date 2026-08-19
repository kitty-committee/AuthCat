#include "bcrypt.h"
#include <iostream>
#include <string>

int main() {
  std::string msg;

  std::cout << "Message to hash > ";
  std::cin >> msg;

  std::string hash = bcrypt::generateHash(msg);
  std::cout << hash << std::endl;

  std::cout << bcrypt::validatePassword(msg, hash) << std::endl;

  return 0;
}
