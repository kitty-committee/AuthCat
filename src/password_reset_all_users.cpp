
#include "jdbc/cppconn/connection.h"
#include "jdbc/cppconn/exception.h"
#include "jdbc/cppconn/prepared_statement.h"
#include "jdbc/cppconn/resultset.h"
#include "jdbc/cppconn/statement.h"
#include "jdbc/mysql_driver.h"
#include <memory>
int main() {
  sql::Driver *driver = sql::mysql::get_driver_instance();
  // Attempt to open a connection to the database
  std::unique_ptr<sql::Connection> db;
  try {
    db = std::unique_ptr<sql::Connection>{
        driver->connect("localhost:3306", "sso", "")};
    db->setSchema("SSO");
  } catch (sql::SQLException &e) {
    std::cerr << "Couldn't connect to MySQL DB. " << e.what() << std::endl;
    return 0;
  }

  std::unique_ptr<sql::ResultSet> users;
  std::unique_ptr<sql::Statement> stmt;
  try {
    stmt = std::unique_ptr<sql::Statement>{db->createStatement()};
    users = std::unique_ptr<sql::ResultSet>{
        stmt->executeQuery("SELECT email FROM Users")};
    stmt->close();
  } catch (sql::SQLException &e) {
    std::cerr << "Failed to get users. " << e.what() << std::endl;
    return 0;
  }

  try {
    stmt = std::unique_ptr<sql::Statement>{db->createStatement()};
    stmt->executeUpdate("START TRANSACTION");

    while (users->next()) {
      stmt->executeUpdate(std::string("CALL request_password_reset(")
                              .append(users->getString("email"))
                              .append(")"));
    }

    stmt->executeUpdate("COMMIT");
    stmt->close();
  } catch (sql::SQLException &e) {
    std::cerr << "Failed to execute all reset calls. " << e.what() << std::endl;
    stmt->executeUpdate("ROLLBACK");
    stmt->close();
  }

  std::cout << "Done" << std::endl;
  return 0;
}
