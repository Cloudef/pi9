add_executable(server server.c)
target_link_libraries(server PRIVATE pi9 ${CHCK_LIBRARIES})
