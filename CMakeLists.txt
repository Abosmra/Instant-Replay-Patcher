cmake_minimum_required(VERSION 3.20)
project(InstantReplayPatcher LANGUAGES C CXX RC)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")

# Verify 64-bit architecture
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "InstantReplayPatcher must be built for 64-bit (x64). Use: cmake -B build -A x64")
endif()

# Use static MSVC C Runtime (/MT for Release, /MTd for Debug)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# Output binaries into bin/ directory
set(OUTPUT_BIN_DIR "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${OUTPUT_BIN_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE "${OUTPUT_BIN_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG "${OUTPUT_BIN_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${OUTPUT_BIN_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE "${OUTPUT_BIN_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG "${OUTPUT_BIN_DIR}")

# -----------------------------------------------------------------------------
# Detours dependency (use prebuilt lib if available, otherwise compile from source)
# -----------------------------------------------------------------------------
set(DETOURS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/Detours")
set(DETOURS_LIB "${DETOURS_DIR}/lib.X64/detours.lib")
set(DETOURS_INCLUDE "${DETOURS_DIR}/include")

if(EXISTS "${DETOURS_LIB}")
    add_library(detours STATIC IMPORTED)
    set_target_properties(detours PROPERTIES
        IMPORTED_LOCATION "${DETOURS_LIB}"
        INTERFACE_INCLUDE_DIRECTORIES "${DETOURS_INCLUDE}"
    )
elseif(EXISTS "${DETOURS_DIR}/src/detours.cpp")
    add_library(detours STATIC
        "${DETOURS_DIR}/src/detours.cpp"
        "${DETOURS_DIR}/src/disasm.cpp"
        "${DETOURS_DIR}/src/image.cpp"
        "${DETOURS_DIR}/src/modules.cpp"
        "${DETOURS_DIR}/src/creatwth.cpp"
    )
    target_include_directories(detours PUBLIC "${DETOURS_DIR}/src")
else()
    message(FATAL_ERROR "Microsoft Detours not found in Detours/. Please run: git clone https://github.com/microsoft/detours Detours")
endif()

# -----------------------------------------------------------------------------
# Target 1: hook.dll
# -----------------------------------------------------------------------------
add_library(hook SHARED
    src/hook.cpp
)
target_link_libraries(hook PRIVATE
    detours
    psapi
    user32
    advapi32
)
set_target_properties(hook PROPERTIES
    PREFIX ""
    OUTPUT_NAME "hook"
)

# -----------------------------------------------------------------------------
# Target 2: IRPatcher.exe (embeds hook.dll, icon, and UAC manifest)
# -----------------------------------------------------------------------------
set(HOOK_DLL_PATH "${OUTPUT_BIN_DIR}/hook.dll")
set(ICON_PATH "${CMAKE_CURRENT_SOURCE_DIR}/res/icon.ico")
set(MANIFEST_PATH "${CMAKE_CURRENT_SOURCE_DIR}/res/app.manifest")

file(TO_CMAKE_PATH "${HOOK_DLL_PATH}" HOOK_DLL_PATH)
file(TO_CMAKE_PATH "${ICON_PATH}" ICON_PATH)
file(TO_CMAKE_PATH "${MANIFEST_PATH}" MANIFEST_PATH)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/res/hook.rc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/hook.rc"
    @ONLY
)

add_executable(IRPatcher WIN32
    src/main.cpp
    src/gui.cpp
    "${CMAKE_CURRENT_BINARY_DIR}/hook.rc"
)

add_dependencies(IRPatcher hook)

target_link_libraries(IRPatcher PRIVATE
    advapi32
    user32
    gdi32
    gdiplus
    shell32
    dwmapi
)

# Copy final artifacts to bin/ in project root for distribution
add_custom_command(TARGET IRPatcher POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_SOURCE_DIR}/bin"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_FILE:hook>" "${CMAKE_CURRENT_SOURCE_DIR}/bin/hook.dll"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_FILE:IRPatcher>" "${CMAKE_CURRENT_SOURCE_DIR}/bin/IRPatcher.exe"
    COMMENT "Copying compiled binaries to project bin/ directory"
)

