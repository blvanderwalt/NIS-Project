# NIS
NIS Assignment
Authors:  Chiadika Emeruem, Ryan McCarlie, Ceara Mullins, Brent van der Walt

// ------------------------------------------------------------------------- //

Run requires 2 consoles, running the server first and then the client (See end for use with makefile)
To Start Server --> java Server
To Start Client --> java Client [ip]
(ip is optional - used if run on separate devices)
--- These commands are done assuming bouncycastle is linked to the runtime,
    that the files have been compiled in the same folder,
    and that they are being done in a console in the src files.
    -> use makefile for easier usage

To send messages, type the message on either client side and press enter.
/quit to quit client

// ------------------------------------------------------------------------- //
Makefile Usage:

make
    - compiles the program
make server
    - runs the server
make client
    - runs client connecting to local host

// ------------------------------------------------------------------------- //
