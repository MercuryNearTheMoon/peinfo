# peinfo

`peinfo` is a simple command-line tool for inspecting **Portable Executable (PE)** files (such as `.exe`, `.dll`, `.sys`).  
It can display information about headers, sections, imports, exports, and more.


---

## Build / Compilation

This project uses a simple `Makefile` for building.

```bash
# Build the project
make

# Clean up build artifacts
make clean
```

After building, the executable will be available in the project root (e.g., ./peinfo).

## Usage
```sh
./peinfo <PE_FILE>
```