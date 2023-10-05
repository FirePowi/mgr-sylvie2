# Install Python 3.8 or higher (3.9 recommended) and pip

## Windows
### MSYS2 MSYS (Recommended) – Note this may work with UCRT64 but not tested
*If you test it with UCRT64, please let me know if it works or not via DM or issue/PR. – Thank you!*
1. Install MSYS2 MSYS from [msys2.org](https://www.msys2.org/)
2. Open MSYS2 MSYS
3. (Optional but enjoyable) add "ILoveCandy" at the options section in /etc/pacman.conf:
```bash
sed -i 's/\[options\]/\[options\]\nILoveCandy/g' /etc/pacman.conf
```
4. Update MSYS2 MSYS and install python3, python3-pip, gcc, make and git
```bash
pacman -Syu python3 python3-pip gcc make git
```

### With cygwin (not recommended, may not work properly, especially in the future)
Open cygwin setup and install python3 and python3-pip:
Search python3 and double click on Skip for both to set it to the latest version.

### Common, manual way (please avoid) – The follow-up may *NOT* work
Download and install from [python.org](https://www.python.org/downloads/)
Pip is included in the installation but may not function properly.
Even if I ask to avoid and do **not** want to put additional, feel free to try it out and give a feedback – You can open an issue/PR or contact me directly either it works or not. – I will edit this section accordingly. – Thank you!

### With chocolatey (please avoid) – The follow-up may *NOT* work
* In powershell
```powershell
choco install python3
```
* In cmd
```cmd
choco install python3
```
Pip is included in the installation but may not function properly.
Even if I ask to avoid and do **not** want to put additional, feel free to try it out and give a feedback – You can open an issue/PR or contact me directly either it works or not. – I will edit this section accordingly. – Thank you!

## GNU/Linux
### Debian/Ubuntu
```bash
sudo apt update && sudo apt install python3 python3-pip gcc make git
```
### Fedora
**Note:** This has not been tested yet. – If you test it, please let me know if it works or not via DM or issue/PR. – Thank you!
```bash
sudo dnf update && sudo dnf install python3 python3-pip gcc make git
```

### Arch Linux
```bash
sudo pacman -Syu python3 python3-pip gcc make git
```

## MacOS (not tested, can't test, therefore cannot give support)
```bash
brew install python3 python3-pip gcc make git
```

# Install dependencies

## Using bash (recommended), any OS
```bash
pip3 install -r requirements.txt
```
# To generate requirements.txt
```bash
pip3 freeze > requirements.txt
```