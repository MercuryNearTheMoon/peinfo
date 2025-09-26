# peinfo

`peinfo` is a simple command-line tool for inspecting **Portable Executable (PE)** files (such as `.exe`, `.dll`, `.sys`).  
It can display information about headers, sections, imports, exports, and more.


---

## Build / Compilation
### Via Makefile (Recommanded)

Build
```bash
make
```

Clean up
```bash
make clean
```

### Via MSVC
Build
```cmd
cl /Fe:peinfo.exe src/* /I include
```

Clean up
```cmd
del *.obj
```

After building, the executable will be available in the project root (e.g., ./peinfo).

## Usage
```sh
./peinfo <PE_FILE>
```

## Development

### Formatter

Download LLVM (Windows): [https://llvm.org/builds/](https://llvm.org/builds/)

Download clang-format (Ubuntu):
```sh
    sudo apt update
    sudo apt install clang-format
```

VScode extensions (Optional): [https://marketplace.visualstudio.com/items?itemName=xaver.clang-format](https://marketplace.visualstudio.com/items?itemName=xaver.clang-format)

### Reference
PE Format: [https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-standard-fields-image-only](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-standard-fields-image-only)