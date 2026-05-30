# 包含头文件目录
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/test_include)
include_directories(${PROJECT_SOURCE_DIR}/src/include)
include_directories(${CMAKE_DEPENDENCY_INCLUDEDIR}/securec)

# 编译client可执行文件，并链接test_utils_lib scf
function(add_client_server NAME)
    file(GLOB TEST_UTILS_SOURCES "test_utils/*.cpp")
    add_executable(${NAME} ${NAME}.cpp ${TEST_UTILS_SOURCES})
    target_link_libraries(${NAME} PRIVATE scf)
endfunction()

add_client_server(client_main)
add_client_server(server_main)
add_client_server(client_main_tcp)
add_client_server(server_main_tcp)

# === SCF v2.0 新 API 示例 ===
# 新 API 连接层不需要手动 TCP 管理，示例极简
add_executable(client_main_new client_main_new.cpp)
target_link_libraries(client_main_new PRIVATE scf)

add_executable(server_main_new server_main_new.cpp)
target_link_libraries(server_main_new PRIVATE scf)