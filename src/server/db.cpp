#include "AuthCat/auth.hpp"
#include "jdbc/cppconn/driver.h"
#include "jdbc/mysql_driver.h"
#include <AuthCat/oauth.hpp>
#include <api/sql.hpp>

namespace nathcat {
namespace auth {
sql::Driver *driver = sql::mysql::get_driver_instance();
struct ServerConfig serverConfig = {};
} // namespace auth
} // namespace nathcat

template <>
struct nathcat::auth::client
nathcat::sqlwrapper::fromRow<struct nathcat::auth::client>(
    std::unique_ptr<sql::ResultSet> &res) {
  return {res->getString("id"), res->getString("redirectionUrl")};
}
