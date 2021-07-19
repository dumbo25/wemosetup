# wemosetup
Tool for discovering WeMo devices on a home LAN.

Derived from: https://github.com/vadimkantorov/wemosetup

Made a few minor changes, which included improving the help output, and changes to allow it to run under python3 on a MacBook.

I changed the command discover to work on my LAN rather than on WeMo bridge, and moved the old discover command to one called bridge.

I added several commands.

One of the more useful changes to discover is it will detect rogue APs, which caused my WeMo devices to lose connection or become unctrollable via the WeMo app, Alexa or Voice control via Echo.
