tell application "Terminal.app"
    activate
    set targetWindow to 0
    do script "cd /Users/marijajovicic/Desktop/blockchainProjectCSC435 && java -cp \".:gson-2.8.2.jar\" Blockchain 0"

    tell application "System Events" to keystroke "t" using command down
    do script "cd /Users/marijajovicic/Desktop/blockchainProjectCSC435 && java -cp \".:gson-2.8.2.jar\" Blockchain 1" in window 0

    delay 0.3
    tell application "System Events" to keystroke "t" using command down
    do script "cd /Users/marijajovicic/Desktop/blockchainProjectCSC435 && java -cp \".:gson-2.8.2.jar\" Blockchain 2" in window 0
end tell
