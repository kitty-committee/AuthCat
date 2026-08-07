if(NOT DEFINED CLIENTBUILD OR NOT CLIENTBUILD)
  add_subdirectory(apiserver)
  add_subdirectory(cryptorand)
  #else()
  #  add_subdirectory(apiserver/libs/httplib)
endif()

add_subdirectory(bcrypt)

add_subdirectory(json)
