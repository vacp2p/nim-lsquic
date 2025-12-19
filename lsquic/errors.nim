type 
    QuicError* = object of CatchableError
    QuicConfigError* = object of QuicError
    StreamError* = object of IOError
    ConnectionError* = object of IOError
    ConnectionClosedError* = object of ConnectionError
    DialError* = object of IOError