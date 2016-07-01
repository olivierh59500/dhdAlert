# dhdAlert - abstract
Win32 Keylogger with the purpose of identifying key injection tools like the USB Rubber Ducky or Teensy and their payloads.

## Key Injection Tools
<img align="right" src="http://cdn.shopify.com/s/files/1/0068/2142/products/duck_thumb_fa2571a3-a36f-460a-b68b-d29d74d87b2f.jpg?v=1415666031" width="400">
To describe key injection tools and their advantages, let me use a quote from Rubber Ducky:
"*Nearly every computer including desktops, laptops, tablets and smartphones take input from Humans via Keyboards. It's why there's a specification with the ubiquitous USB standard known as HID - or Human Interface Device. Simply put, any USB device claiming to be a Keyboard HID will be automatically detected and accepted by most modern operating systems. Whether it be a Windows, Mac, Linux or Android device the Keyboard is King.*

*By taking advantage of this inherent trust with scripted keystrokes at speeds beyond 1000 words per minute traditional countermeasures can be bypassed by this tireless trooper - the USB Rubber Ducky.*"

These scripted keyboards allow an attacker with physical access to secure payloads in a timely fashion, just by plugging in the USB device. On top of that a well written script is able to clean up after itself. That way it can be hard to notice security breaches and identify the payload of the attacker. In addition to that the innocent disguise can lead to the user plugging in the device themselves, thinking it is an orphaned UBS drive.

---
## dhdAlert - features
* Win32 Keyboard Hook - detects all incoming keyboard events on the machine.
* Detailed Log.
* 'full' English and German keyboard setting support. Other countries may vary.
* Runs in the System Tray, waiting for suspicious activity, then starts recording. 
* Detects: Windows Run Command (Winkey + R), which is commonly used in malicious key injections.
* Detects: Unhuman amount of key strokes per second. ( > 300wpm )
* Attempts to obstruct the Command Prompt with a messagebox when possible.
* Also compile ready in: **Silent Mode** (no obstructions that could alert an attacker.)
* Also compile ready with: **No KPS detection** (for people who use a lot of keystroke macros.)

*Remember that dhdAlert can only do its job when it is running and will rarely have to do it. So put it on Autostart or use it before plugging in orphaned USB devices.*

---
The following gif shows dhdAlert reacting to a simple AutoHotKey script:
![alt tag](http://i.imgur.com/YD6G9Ly.gif "dhdAlert preventing and identifying Autohotkey script.")
