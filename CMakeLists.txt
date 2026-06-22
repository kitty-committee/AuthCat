cmake_minimum_required(VERSION 3.28.3)

if(NOT DEFINED CLIENTBUILD OR NOT CLIENTBUILD)

  project(AuthCat-Server)

  add_subdirectory(libs)

  add_executable(AuthCat-Server src/server/main.cpp)

  target_sources(AuthCat-Server PUBLIC
  src/server/User.cpp
  src/server/auth.cpp
)

  target_include_directories(AuthCat-Server PUBLIC
  include
  libs/bcrypt/include
  libs/apiserver/include
  libs/json/include
  libs/apiserver/libs/mysql/include
)

  target_link_libraries(AuthCat-Server PUBLIC
  apiserver
  bcrypt
  nlohmann_json::nlohmann_json
)

else()

  project(AuthCat-Client)

  add_subdirectory(libs)

  add_library(AuthCat-Client STATIC
  src/client/User.cpp
  src/client/auth.cpp
  )

  target_include_directories(AuthCat-Client PUBLIC
  include
  libs/bcrypt/include
  libs/json/include
  libs/apiserver/libs/httplib
)

  target_link_libraries(AuthCat-Client PUBLIC
  bcrypt
  nlohmann_json::nlohmann_json
)

endif()

