# Communication Between `MASQNode` and User Interfaces

## Background

### Project Architecture

The `MASQNode` (or `MASQNode.exe` for Windows) binary is used for two different purposes. One is called the Daemon;
the other is called the Node.

The Node contains all the communications capabilities MASQ is known for. Its job is to start with root privilege,
open low ports, drop privilege to user level, and settle into sending and receiving CORES packages.

The Daemon is different. Its job is to start when the machine boots, with root privilege, and keep running with
root privilege until the machine shuts down. It is not allowed to communicate over the Internet, or with the Node.
This reduces the chance that an attacker's hack of the Node could gain root privilege on a user's machine.

Since the Daemon is always running, it listens on a `localhost`-only port (5333 by default) for connections
from user interfaces. UIs connect first to the Daemon on its well-known port. There are certain conversations that
the Daemon can carry on with the UI (one of which tells the Daemon to start up the Node), but when it's time, the
Daemon will tell the UI where the Node is so that the UI can connect directly to the Node.

If the Node crashes, the UI should reconnect to the Daemon. From there, if desired, it can direct the Daemon to
restart the Node.

Any number of UIs can connect to the Daemon and the Node. Information that is relevant only to one UI is sent only
to that UI; information that is relevant to all is broadcast. Currently there is no way for a UI to subscribe
only to those broadcasts in which it is interested; it will receive all broadcasts and has the responsibility to
ignore those it doesn't care about. If necessary, the subscription functionality can be added to the Node in the
future.

### Communications Architecture

#### Level 1

If the Daemon is started without specific settings, like this

```
$ ./MASQNode --initialization
```

it will try to come up listening for UI connections on port 5333. But if it's started like this

```
$ ./MASQNode --initialization --ui-port 12345
```

it will try to come up listening for UI connections on port 12345. If it finds the target port already occupied, it
will fail to start.

The Node is started by the Daemon. When the Daemon starts the Node, it will choose an unused port and direct the
Node to listen for UIs on that port. When the Daemon redirects a UI to the Node, it will supply in the redirect
message the port on which the Node is running.

The Daemon and the Node listen for UIs only on the `localhost` pseudo-NIC. This means that all the UIs for a particular
Daemon or Node must run on the same computer as the Daemon or Node: they cannot call in over the network from another
machine. This restriction is in place for security reasons.

#### Level 2

The link between the UIs and the Daemon or Node is insecure WebSockets, using the protocol name of `MASQNode-UIv2`.
Any other protocol name will be rejected, and no connection will be made.

#### Level 3

Once the WebSockets connection is established, all the messages passed back and forth between the UIs and the Daemon
or Node are formatted in JSON. A message packet is always a JSON object, never a scalar or an array.

#### Level 4

The low-level JSON format of `MASQNode-UIv2` messages is very simple. It looks like this:

```
{
    "opcode": <opcode>,
    "contextId": <context id>,
    "payload": {
        <... payload ...>
    }
}
```

The `opcode` is a short string that identifies the message type. Sometimes the same opcode will be used for two
different message types if they can easily be distinguished by some other context--for example, if one type is
only ever sent from the UI to the Node, and the other type is only ever sent from the Node to the UI.

The `contextId` is a positive integer best thought of as a conversation number. Just as there can be many UIs 
connected to the same Node, each UI can be carrying on many simultaneous conversations with the Node. When a 
request is sent as part of a particular conversation, the Daemon and the Node guarantee that the next message 
received in that conversation will be the response to that request. It is the responsibility of each UI to 
manage `contextId`s. When the UI wants to start a new conversation, it merely mentions a new `contextId` in 
the first message of that conversation; when it's done with a conversation, it just stops mentioning that 
conversation's `contextId`.

Some messages are always isolated, and never part of any conversation. These messages will be identifiable by
their `opcode`, and their `contextId` should be ignored. (In the real world, it's always zero, but depending on
that might be dangerous.)

Neither the Daemon nor the Node will ever start a conversation, although they will send isolated, non-conversational
messages.

The `payload` is the body of the message, with its structure being signaled by the contents of the `opcode` field.

#### Level 5

The structure of the `payload` of a `MASQNode-UIv2` message depends on the `opcode` of that message. See the
Message Reference section below.

## General Operational Concepts

### Daemon

#### Setup

The Node requires quite a bit of configuration information before it can start up properly. There are several
possible sources of this configuration information. The primary source, though, is the command line that's used
to start the Node. There are many parameters that can be specified on that command line, and the Daemon needs to
know them all in order to start the Node.

Accumulating this information is the purpose of the Daemon's Setup functionality, which is a large proportion of
what it does.

The Daemon has a space inside it to hold Setup information for the Node. A UI can query the Daemon to get a dump
of the information in the Setup space. When the Node is not running, the information in the Setup space can be
changed by the UI. When the Node is running, the information in the Setup space is frozen and immutable. This is
so that when the Node is running, you can use the UI to query the Daemon to discover the configuration with which
the Node was started.

If a Node is shut down, a new Node can easily be started with exactly the same configuration as its predecessor
as long as the information in the Setup space is not disturbed.

#### Start

When the Start operation is triggered, the Daemon will try to start the Node with the information in the Setup
space. The response message will tell whether the attempt succeeded or failed. 

#### Redirect

As long as the UI sends the Daemon messages that the Daemon understands, the Daemon will respond appropriately to
them. But if the UI sends the Daemon a message the Daemon doesn't understand, the Redirect operation may come
into play.

If the Node is not running, there's nowhere to Redirect, so the Daemon will just send back an error response.

However, if the Node _is_ running, the Daemon will send back a Redirect response, which will contain both
information about where the Node is running and also the unexpected message sent to the Daemon. When the UI
gets a Redirect, it should drop the WebSockets connection to the Daemon, make a WebSockets connection to the
Node on the port supplied in the Redirect message (on `localhost`, using the `MASQNode-UIv2` protocol), and
resend the original message--which, in case the UI doesn't remember it anymore, is helpfully included in the
Redirect payload.  If it's a valid Node message, the Node should respond appropriately to it.

### Node

#### Shutdown

The Shutdown operation causes the Node to cease operations and terminate. The UI will receive a response, and then
the WebSockets connection will be dropped by the Node.

Whenever the WebSockets connection is dropped, whether the Shutdown operation is in progress or not, the UI should
reconnect to the Daemon.

If for some reason the WebSockets connection is _not_ dropped by the Node within a few milliseconds of the response
to the Shutdown message, that indicates that the Node has somehow become hung on the way down. In this case, the
WebSockets connection to the Node will probably be of no further use. The UI may choose to inform the user that
bad things are happening which will probably require user intervention.

## Message Reference

The following messages are listed in alphabetical order by opcode. If several messages have the same opcode,
they'll be ordered under that opcode with the request first and the response later. The `opcode` and `contextId`
fields are not included in the message layouts, but they must be provided by the UI and will be specified
by the Daemon or Node.

#### `financials`
##### Direction: Request
##### Correspondent: Node
##### Layout:
```
"payload": {
    "payableMinimumAmount" = <nonnegative integer>,
    "payableMaximumAge" = <nonnegative integer>,
    "receivableMinimumAmount" = <nonnegative integer>,
    "receivableMaximumAge" = <nonnegative integer>
}
```
##### Description:
Requests a financial report from the Node.

In most cases, there will be many records in the database, most of them irrelevant because of amount or age.
Therefore, when the UI requests a financial report, it should specify minimum amounts and maximum ages. Records
with amounts smaller than the minimums, or older than the maximums, won't be included in the results, although
their values will be included in the totals.

This request will result in a cluster of queries to the database, which are quick but not instantaneous,
especially on old databases that contain lots of records. A UI that makes this request too many times per
second will perceptibly degrade the performance of the Node.

Amounts are specified in gwei (billions of wei); ages are specified in seconds. Values less than zero or
greater than 64 bits long will cause undefined behavior.

#### `financials`
##### Direction: Response
##### Correspondent: Node
##### Layout:
```
"payload": {
    "payables": [
        {
            "wallet": <string>,
            "age": <nonnegative integer>,
            "amount": <nonnegative integer>,
            "pendingTransaction": <optional string>
        },
        < ... >
    ],
    "totalPayable": <nonnegative integer>,
    "receivables": [
        {
            "wallet": <string>,
            "age": <nonnegative integer>,
            "amount": <nonnegative integer>
        },
        < ... >
    ],
    "totalReceivable": <nonnegative integer>,
}
```
##### Description:
Contains a financial report from the Node.

In most cases, there will be accounts in the database that are too old, or whose balances are too low, to
show up in this report. The `totalPayable` and `totalReceivable` fields will be accurate, but they will
probably be larger than the sums of the `payables` and `receivables` `amount` fields. The UI may choose to
ignore this discrepancy, or it may generate an "Other" account in each case to make up the difference.

The `wallet` fields will consist of 40 hexadecimal digits, prefixed by "0x".

The `age` fields contain the age in seconds, at the time the request was received, of the most recent transaction
on the associated account. The value will not be less than zero or longer than 64 bits.

The `amount` fields contain the total amount in gwei owed to or due from the associated account at the time the
request was received. The value will not be less than zero or longer than 64 bits.

The `pendingTransaction` fields, if present, indicate that an obligation has been paid, but the payment is not
yet confirmed on the blockchain. If they appear, they will be standard 64-digit hexadecimal transaction numbers,
prefixed by "0x". If no `pendingTransaction` is given, then there were no pending payments on that account
at the time the request was received.

The `payables` and `receivables` arrays are not in any particular order.

For security reasons, the Node does not keep track of individual blockchain transactions, with the exception
of payments that have not yet been confirmed. Only cumulative account balances are retained.

[continue]
