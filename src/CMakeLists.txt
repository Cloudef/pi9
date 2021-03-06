add_library(pi9 pi9.c pi9_string.c)
target_link_libraries(pi9 PRIVATE ${CHCK_LIBRARIES})

# Parse soversion version
string(REGEX MATCHALL "[0-9]+" VERSION_COMPONENTS ${PROJECT_VERSION})
list(GET VERSION_COMPONENTS 0 SOVERSION)
set_target_properties(pi9 PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION ${SOVERSION})

set(PI9_LIBRARIES pi9 CACHE STRING "Libraries of pi9" FORCE)
set(PI9_INCLUDE_DIRS "${PROJECT_BINARY_DIR}/include" CACHE STRING "Include directories of pi9" FORCE)
mark_as_advanced(PI9_LIBRARIES PI9_INCLUDE_DIRS)

# Add pkgconfig
configure_file(pi9.pc.in pi9.pc @ONLY)

install(TARGETS pi9 DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(DIRECTORY "${PROJECT_BINARY_DIR}/include/pi9" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/pi9.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
