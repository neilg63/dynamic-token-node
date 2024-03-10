# Dynamic Token for Node

A Dynamic token authenticates client applications with the server via a shared API key, timestamp, random characters and an optional uuid. Unlike a JWT token, a dynamic token is not reusable and does not validate a user's session. It may supplement a JWT token and provides enhanced security without having to issue a temporary access key. As dynamic tokens change every millisecond with randomised injection of the encoded API key with extra random noise characters in a base-64-encoded string, it is almost impossible to intercept the token.
If the decoded timestamp falls outside a narrow time range, by default 5 minutes, it will be rejected. This allows for long request times and minor discrepancies in system clock times. However, the only time that matters is the initial request, not the time it takes to process and send the response. In theory, the same token would work for this limited period.


## Comparison with other authentication systems

Many systems require a long access key and client secret. While cryptic, they are static and exposed directly in the header, payload or query string. Others require a handshake, where the static API key identfies the client, but issues a temporary access token for subsequent requests. This access token may be valid for an extended user session or only long enough to let the client send a second request to fetch the required data. This complicates data flow between two tightly web applications, especially micro-services and backend APIs for mobile apps and Web applications.

### Customisation Options

At its most basic dynamic tokens only require a shared API key. Both the server and the client must use compatibile dynamic token libaries. The Rust crate is ideal for server to server communication as an HTTP header added and authenticated as middleware. The dynamic token does not expose the API key or timestamp, unless someone has deconstructed the algorithm used to inject and encode these components into the string before base-64 encoding. Even if a dynamic token is intercepted, it has a limited lifetime.

