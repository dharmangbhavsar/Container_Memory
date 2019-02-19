sudo rmmod memory_container
cd kernel_module
sudo make clean
sudo make
sudo make install
cd ..
cd library
sudo make clean
sudo make
sudo make install
cd ..
cd benchmark
make clean
make
cd ..