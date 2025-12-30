# FFXI-AutoLogin

**Created by: jaku  |  https://twitter.com/jaku**

## What is this?
A simple tool to automate logging into Final Fantasy XI using either Windower or POL directly. It supports multiple characters and can be used to launch several accounts in sequence.

---

## How to Use (Most Users)

### 1. Place the EXE
- Put `autoPOL.exe` in the same folder as your `pol.exe` or `Windower.exe`.
  - For Windower users, this is usually your Windower install folder.
  - For vanilla POL users, it's usually located in `C:\Program Files (x86)\PlayOnline\SquareEnix\PlayOnlineViewer`.

### 2. First Run: Setup
- Run `autoPOL.exe` (double-click or from command line).
- On first run, it will walk you through creating a `config.json` file:
  - You will enter a name for each character (no spaces, must be unique)
  - Password
  - TOTP secret (if you use one)
  - Slot number (1-4)
  - (Optional) Windower arguments (e.g. `-p="ProfileName"`)

## How to get your TOTP Secret
If you use a one-time password (TOTP) for your FFXI account, you will need the secret key:

1. **Remove your current authenticator** from your Square Enix account.
2. **Register a new authenticator**. When you get to the QR code select "Can't stand this image"
3. Copy the secret provided on that page and use this value as your TOTP secret in the launcher setup.
4. Done!

Note: If you use any TOTP generator that remembers the secret (such as bitwarden), you can just copy that secret and do not need to forget the old one.

#### Older steps on how to get your TOTP Secret
1. **Remove your current authenticator** from your Square Enix account.
2. **Register a new authenticator**. When you get to the QR code step, **save the QR code as a PNG file**.
3. Go to: [https://iamyuthan.github.io/2FA-Solver/2FA-Solver.html](https://iamyuthan.github.io/2FA-Solver/2FA-Solver.html)
4. Click on **QR Code (Image) Scanner/Decoder**.
5. Select your saved QR code image and click **Decode**.
6. In the decoded value, look for the part after `SECRET=`. It should be all capital letters. Use this value as your TOTP secret in the launcher setup.

You will still want to register your new QR code in your authenicator app, but this way this application can now generate the required code when it goes to login.

WARNING: This will open you up to a little more risk if your PC is compromised as your login info and 2FA secret would now be stored on the PC. But who really wants your FFXI account in 2025?

### 3. Subsequent Runs: Login
- Run `autoPOL.exe` again this time as admin.
- If you have more than one character, you will be prompted to select which one to log in with.
- If you only have one character, it will log in with that one automatically.
- You can also skip the prompt by running:
  ```
  autoPOL.exe --character NAME
  ```
  Replace `NAME` with the character name you set up in the config.
- While the application is logging you in, your mouse and keyboard will be locked to prevent interfering with the process. This should only last about 5 seconds.
- If it lasts longer than expected you can press Windows + L, or Ctrl+Alt+Del to disable the lock and resume control of your keyboard and mouse!



### 4. Launching Multiple Accounts (Batch File)
You can create a batch file (e.g. `start.bat`) to launch multiple characters. Example:

```
autoPOL.exe --character jaku
timeout /t 10
autoPOL.exe --character jaku_mule
```

- Adjust the timeout as needed for your PC (10 seconds is a good starting point).
- Each line launches a different character/account.


Some additional notes, if you have more than 4 characters this application can technically support this. Since you can store all of their details when you run the setup, however you will be responsible for managing your own login_w.bin files and setting them up in a way to use this application. But as an example you could have something like the following for the batch script.

```
autoPOL.exe --character jaku
timeout /t 10
autoPOL.exe --character jaku_mule
timeout /t 5
copy "C:\Program Files (x86)\PlayOnline\SquareEnix\PlayOnlineViewer\usr\all\login_w.bin" "C:\Program Files (x86)\PlayOnline\SquareEnix\PlayOnlineViewer\usr\all\login_w.bin.org"
copy "C:\Program Files (x86)\PlayOnline\SquareEnix\PlayOnlineViewer\usr\all\other.bin" "C:\Program Files (x86)\PlayOnline\SquareEnix\PlayOnlineViewer\usr\all\login_w.bin"
timeout /t 10
autoPOL.exe --character jaku_new

```

I cannot support multiboxing as I don't have experience doing it, but from what I understand the above example should provide enough information for those that know how to multibox to get started.

One additional note is that there might be some issues with multiple POL processes, so extending the timeout from 10 seconds to 15 or 20 seconds might be needed for some setups. 

---

## Other Notes

This is all provided as is, I originally just built this to support my SteamDeck login and figured I'd share it for others. I'm 100% open to PRs and don't typically code in C++ for things like this. I know there could be some other improvements and so if there are bugs I will try to do what I can, but my time is limited and I already have a lot of side-projects.

If you're on the Phoenix server, my main on there is Jakubowski, just waving hi sometime would be awesome.

---

## Advanced: Building from Source

1. Clone the repository.
2. Open the project in Visual Studio (or use your preferred C++ build environment).
3. Make sure you have the following dependencies:
   - Windows SDK
   - nlohmann/json (header-only)
   - httplib.h (header-only)
   - sha1.h (included)
4. Build the project (Release x86 recommended).
5. Place the resulting `autoPOL.exe` in your Windower or POL folder as above.

---

## Troubleshooting

### Login Issues

- **Partial Character Entry**: If the program only enters some characters of your password, try increasing the delay in your configuration. Start by adding 1-2 seconds at a time until it works reliably.
- **Starting 0 character**: If you notice the cursor when going to the password screen is starting on 0, and it's entering it as your password. Update your password to include the 0 (as a quick workaround) or try and adjust your timing as mentioned above.
- **Controller Interference**: Some users have reported that having the controller enabled can cause key entry issues. Try disabling controller support to see if the error persists. (Controller support should work)
- **Auto-Login in POL**: While the program supports auto-login, it's recommended to disable auto-login in the POL window as it can be unreliable. The program will handle the login process more reliably without auto-login.
- **Locked keyboard/mouse**: If the application locks your keyboard and mouse and you can't control it after a long time, you can always press CTRL+ALT+DEL to regain control.

### Linux/Steam Deck Users

If you're using Linux or Steam Deck, you'll need to manually add an entry to your hosts file to get the autoPOL login to fully log you into the game after entering your password:

```bash
echo "127.0.0.1 wh000.pol.com" | sudo tee -a /etc/hosts
```

To remove this entry when you no longer want to use the program:

```bash
sudo sed -i '/wh000.pol.com/d' /etc/hosts
```

Note: While this entry is in your hosts file, you must use this program to log in, or login will fail. 

Windows users do not need to do this.

### Reporting Issues

When reporting issues, please include:
- Your version of autoPOL (try to use the latest version)
- Your configuration details (delay settings, etc.)
- Your operating system (Windows/Linux/Steam Deck)
- What you've tried to resolve the issue
- Any error messages you've received

---

Enjoy! 
