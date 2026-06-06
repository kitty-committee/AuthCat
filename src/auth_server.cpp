#include "jdbc/cppconn/prepared_statement.h"
#include "jdbc/cppconn/resultset.h"
#include <AuthCat/auth.hpp>
#include <api/sql.hpp>
#include <bcrypt.h>
#include <memory>
using namespace nathcat::auth;
using namespace nathcat::sqlwrapper;

namespace nathcat {
namespace auth {
void from_json(const nlohmann::json &j, struct ServerConfig &conf) {
  j.at("host").get_to(conf.host);
  j.at("port").get_to(conf.port);
}
} // namespace auth
} // namespace nathcat

User nathcat::auth::authenticate(std::unique_ptr<sql::Connection> &sql,
                                 Credentials &creds) {
  std::unique_ptr<sql::PreparedStatement> stmt{sql->prepareStatement(
      "SELECT * FROM Users WHERE username = ? AND password = ?")};

  stmt->setString(1, creds.username);
  stmt->setString(2, bcrypt::generateHash(creds.password));

  std::unique_ptr<sql::ResultSet> res{stmt->executeQuery()};

  // If there are any results, the auth is successful.
  while (res->next()) {
    return fromRow<User>(res);
  }

  throw AuthFailed();
}

User nathcat::auth::authenticate(std::unique_ptr<sql::Connection> &sql,
                                 Credentials_Token &creds) {
  std::unique_ptr<sql::PreparedStatement> stmt{sql->prepareStatement(
      "SELECT Users.* FROM QuickAuth JOIN Users ON QuickAuth.id = Users.id "
      "WHERE QuickAuth.tokenHash = ?")};

  stmt->setString(1, bcrypt::generateHash(creds.token));

  std::unique_ptr<sql::ResultSet> res{stmt->executeQuery()};

  // If there are any results, the auth is successful
  while (res->next()) {
    return fromRow<User>(res);
  }

  throw AuthFailed();
}

User nathcat::auth::getById(std::unique_ptr<sql::Connection> &sql, int id) {
  std::unique_ptr<sql::PreparedStatement> stmt{
      sql->prepareStatement("SELECT * FROM Users WHERE id = ?")};

  stmt->setInt(1, id);

  std::unique_ptr<sql::ResultSet> res{stmt->executeQuery()};

  while (res->next()) {
    return fromRow<User>(res);
  }

  throw NotFound();
}

std::vector<User>
nathcat::auth::searchByUsername(std::unique_ptr<sql::Connection> &sql,
                                std::string username) {
  std::unique_ptr<sql::PreparedStatement> stmt{
      sql->prepareStatement("SELECT * FROM Users WHERE username like ?")};

  stmt->setString(1, username);

  std::unique_ptr<sql::ResultSet> res{stmt->executeQuery()};

  return toArray<User>(res);
}

std::vector<User>
nathcat::auth::searchByFullName(std::unique_ptr<sql::Connection> &sql,
                                std::string fullName) {
  std::unique_ptr<sql::PreparedStatement> stmt{
      sql->prepareStatement("SELECT * FROM Users WHERE fullName like ?")};

  stmt->setString(1, fullName);

  std::unique_ptr<sql::ResultSet> res{stmt->executeQuery()};

  return toArray<User>(res);
}
