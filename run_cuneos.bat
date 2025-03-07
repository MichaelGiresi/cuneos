@echo off
cls
echo Starting Cuneos build process...
cargo clean
echo Clean complete. Building project...
cargo build
echo Build complete. Running Cuneos...
cargo run
echo Done!
pause