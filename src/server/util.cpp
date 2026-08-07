#include "AuthCat/auth.hpp"
#include "api/sql.hpp"
#include "jdbc/cppconn/prepared_statement.h"
#include "jdbc/cppconn/resultset.h"
#include <AuthCat/oauth.hpp>
#include <fstream>
#include <memory>
#include <sstream>

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
