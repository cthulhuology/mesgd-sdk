mesgd-sdk
=========

polyglot SDK for dealing with JWKs on the <a href="https://mesgd.org">mesgd</a> platform.


Premise
-------

The goal of this repo is to make a polyglot library for using JWKs for signing, verification, encrypting and decrypting for the mesgd platform.  This is currently just an experiment in implementing JWK support across multiple languages:

* javascript
* erlang
* perl
* python
* ruby
* lua
* php
* swift
* golang
* rust
* c / c++
* java
* haskell
* ocaml
* forth
* and many more

Current Thinking
----------------

In the world of mesgd, you should only have to implement two functions:

* send(to,message)
* on(message,from,do)

Ideally, that would be implemented at the top level event loop of your application, or would be handled natively by your language and runtime of choice.

But to make that a scalable reality, we need encryption and cryptographic signatures.

As I implement tests, the supported languages will increase.  Right now the goal is an API that looks like:

* sign(message)
* verify(message,signature)
* encrypt(message)
* decrypt(message)
* import(filename)
* export(filename)
* public()
* private()

The core concept is it should be trivially easy to share keys and encrypt + sign and verify + decrypt 
any message sent via the <a href="https://mesgd.org/">mesgd</a> platform, or between any applications.

Currently, mesgd doesn't enforce encryption in transit other than through wss:// encryption.  However,
in the ideal world, every message crossing the platform will have an envelope containing an application
specific encrypted payload.  While mesgd enforces message routing policies based on JWT tokens, we not
only want to sign and verify the connection request, but we want to be able to route messages to specific
recipients only, using their public keys to ensure that only they are able to decrypt the content.

This SDK endeavours to make that entire process seamless, send will encrypt the payload and sign it,
on will recieve the message, verify the sender, and decrypt it, passing it on the appropriate callback.
As long as both sender and reciever have their public keys properly registered with <a href="https://mesgd.org">mesgd.org</a>
the messaging will work seamlessly.

Also since the mesgd JWT claims will also be supported, route partitioning and other strategies could
be implemented using the same set of keys, but with strong cryptographic guarantees on the route and claim assertions.
Unlike most pub/sub messaging platforms, this will solve the SPAM problem, as those lousy Vikings will only be able to
access those keys provided by the key-master.

How it Works
------------

When you subscribe to a mesgd URL your path segments are compared with the list of claims in your Bearer JWT token.
The token must be signed by a known good key who has rights to one or more of the path segments.  In return, anyone
granted rights to access the public keys associated with said path segments may encrypt and sign their messages that
they send using their granted JWT, to the appropriate destinations.  Likewise, any recipient with granting authority,
may choose to verify any known good key sending them a message, and may decide how best to handle the inbound message.

Unlike typical HTTP flows, all flows are treated unidirectionally, and may be one-to-many interactions.  For example,
multiple AI and consumer agents may all be listening on the same destination address ( thing to: mailinglist in email terms )
but each recipient may have access to their own private key.  Mesgd validates the incoming message, decrypts, and then
re-encrypts the message for each unique recipient based on their public keys.  The JWT validated that the recipients were
authorized to listen to the message, and mesgd handles the translation from the sender's scope to the recipient's.

Does this mean that mesgd mitm attacks?
---------------------------------------

Only if you want it to.  Typically, when a message is sent to mesgd with the intent to distribute to multiple recipients,
the sender will encrypt it with the public key of the distribtion list and then mesgd then translates the distribution list
message to the consumer specific messages.  Likewise, when a recipient receives the message, it may use the mesgd public
key to respond to all recipients.  However, if the message is sent with a specific recipient's public key for the encrypt side,
then mesgd will pass it through to that recipient, and all other potential recipients will not be able to read or verify 
the message contents, even if they receive it by intent or accident.

Wait a second, mesgd may send encrypted messages to unintended recipients?
--------------------------------------------------------------------------

Sure, because you gave that recipient a JWT token that said explicitly via claims that they could get that message.  Look
we know this shit is hard and people are in general dumb, which is why we aren't stopping you from sending encrypted messages
to the wrong recipients when you tell us to do exactly that.  If we don't have the associated private key, we can't do anything
other than pass it on or drop it, but if someone says they have a right to recieve that message based on a claim you gave them
we don't want to argue, and will honor your decision.

Isn't that just a security cop-out?
-----------------------------------

Look, you signed the message, you encrypted it for your desired target, you gave your recipients a JWT token that said they could
receive it, and they got the message.  At what point will you take responsibilty for your own actions?  The reason mesgd supports
key translation services is because you might now know all your consumers, but we know them.  To support the concept of the commons,
mesgd provides a translation service to make cryptographically signed messages available to the public at large.  You still get
to decide whose that public may be.

Why would you do this?
----------------------

Because in a world of AI & humans all trying to figure out what is true or not, we need a system where we can at least prove:

1.) I said this
2.) I meant for you to hear this

If what you said is true or not is not our here nor there, we just want to have a record we can rely on.

How much will that record cost?
-------------------------------

Nothing in life is free, but free speach has never been free.  For running the key service mesgd will seek donations and paid subscriptions.
The current thinking is we will sell keys which will have unlimited usage, and we will sell translation services on a token basis.
Ideally, the end goal will be to have mesgd broker a p2p connection so you talk to your recipient directly, but if you need a one to many
broadcast service you will pay for the cost of doing the one to many translation.

Can I register 1000 anonymous accounts and sock puppet the universe
-------------------------------------------------------------------

Sure go ahead knock yourself out.  As Paulie says, "fuck you pay me".

Why isn't this selling out to the Man?
--------------------------------------

Because you get to choose who to listen to.  Don't give the Man your public key.  Don't give out your JWTs to the Man.

What is your north star, what is your guiding principle?
--------------------------------------------------------

Freedom isn't free, but we want to maximize freedom.  As individuals we can't be maximally free, but voluntarily together we can be.
I am giving you this wonderful solution as a gift, please gift to me in turn a life where my children don't freeze or go hungry.

