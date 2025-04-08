.PHONY: all clean vibe-cli vibe-node

# Default target: builds both the CLI and the node
all: vibe-cli vibe-node

# Target to build the vibe-cli
vibe-cli:
	@echo "Building vibe-cli..."
	@go build -v -o vibe-cli ./cmd/vibe-cli/main.go

# Target to build the vibe-node
vibe-node:
	@echo "Building vibe-node..."
	@go build -v -o vibe-node ./cmd/vibe-node/main.go

# Target to clean the built binaries
clean:
	@echo "Cleaning build artifacts..."
	@rm -f vibe-cli vibe-node 