PROJECT = NvdClient
CONFIG = Release
OUTPUT_DIR = dist

DLL_PATH = $(shell find $(PROJECT)/bin/$(CONFIG) -name "$(PROJECT).dll" | head -n 1)

all: build copy

build:
	dotnet build $(PROJECT)/$(PROJECT).csproj -c $(CONFIG)

copy:
	mkdir -p $(OUTPUT_DIR)
	cp $(DLL_PATH) $(OUTPUT_DIR)/

clean:
	dotnet clean $(PROJECT)/$(PROJECT).csproj
	rm -rf $(OUTPUT_DIR)
