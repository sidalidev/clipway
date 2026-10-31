# Non-goals

What Clipway will not do, and why.

- **Accounts, sign-in, recovery by email.** The 12 words are the account. Nobody can recover them, us included.
- **Reading the phone's clipboard in the background.** Android forbids it since Android 10, for good reasons. The phone sends with one gesture.
- **Sending passwords.** What password managers or Android mark as sensitive is skipped, always. There is no switch to change that.
- **Syncing a clipboard history across devices.** Each device keeps its own history of what it sent and received.
- **Large transfers.** 25 MB per image or file, and texts of 64 KB. For more, use a file sync tool.
- **Images and files through a server.** Never. Nobody can check what travels end to end encrypted without an account, so our relay carries texts only. Images and files go directly between your devices on the same network.
- **Windows, Linux, iOS.** Not now. The protocol is open and documented for anyone who wants to try.
- **Permanent storage on the relay.** 24 hours, in memory, then gone.
