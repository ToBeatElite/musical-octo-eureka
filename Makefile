make:

	@echo "compiling..."

	@x86_64-w64-mingw32-gcc -masm=intel -fdiagnostics-color main.c -o main.exe

	@ls -la main.exe
	@echo "done!"
