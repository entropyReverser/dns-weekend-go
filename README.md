# Implement DNS in a weekend in *go*

A crude implementation of Julia Evans's [Implement DNS in a Weekend](https://implement-dns.wizardzines.com) project in Golang. 

If I had written this Python I would have ended up just copying and pasting. Writing in go stopped me from doing. e.g Julia uses Bytes IO to avoid keeping track of the reader. I had to manually pass the current location from the functions.

This is just the bare bones without any of the exercises implemented, all the functions were created one-to-one from the python code into a file without any thoughts on optimizations.

Keeping the exercises.ipynb file if I ever want to come back to this.

To check out the original project check out the link above or the repo this project is forked from.
