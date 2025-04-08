# CREATED WITH PAELLADOC, CURSOR, GOOGLE GEMINI 2.5 PRO

VIBE AI is a fully vibe coded PoW blockchain in Golang.

build cli and node with:

make

Then create a wallet

mkdir data // make data directory for wallet
./vibe-cli createwallet

use wallet generated in above command:
./vibe-node -mine -mineraddress <wallet> -port 9001

This will connect you to the seed nodes, and get you started mining VIBE!
