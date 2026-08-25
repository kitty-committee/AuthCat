#include "AuthCat/auth.hpp"
#include "api/sql.hpp"
#include "jdbc/cppconn/connection.h"
#include "jdbc/cppconn/prepared_statement.h"
#include "jdbc/cppconn/resultset.h"
#include <AuthCat/auth_grant.hpp>
#include <AuthCat/oauth.hpp>
#include <fstream>
#include <memory>
#include <sstream>

namespace nathcat {
namespace auth {
namespace util {
std::regex token_auth_regex("Basic (.*):(.*)");

bool validate_auth_grant(std::unique_ptr<sql::Connection> &db, AuthGrant grant,
                         std::string client_id) {
  std::unique_ptr<sql::PreparedStatement> pStmt{
      db->prepareStatement("SELECT * FROM AuthGrants WHERE `token` = ? AND "
                           "`client` = ? AND `scope` = ?")};

  pStmt->setInt(1, grant.token);
  pStmt->setString(2, client_id);
  pStmt->setUInt64(3, grant.scope);

  std::unique_ptr<sql::ResultSet> rs{pStmt->executeQuery()};
  pStmt->close();

  if (!rs->next()) {
    rs->close();
    return false;
  } else {
    rs->close();
    return true;
  }
}
} // namespace util
} // namespace auth
} // namespace nathcat

std::string nathcat::auth::util::read_file(std::string path) {
  std::ifstream f(path);
  std::stringstream s;
  s << f.rdbuf();

  f.close();
  return s.str();
}

struct nathcat::auth::client
nathcat::auth::util::get_client(std::unique_ptr<sql::Connection> &db,
                                std::string id) {
  std::unique_ptr<sql::PreparedStatement> pStmt{
      db->prepareStatement("SELECT * FROM Clients WHERE id = ?")};
  pStmt->setString(1, id);

  std::unique_ptr<sql::ResultSet> res{pStmt->executeQuery()};
  pStmt->close();
  if (!res->next())
    throw auth::NotFound();
  return nathcat::sqlwrapper::fromRow<struct client>(res);
}
