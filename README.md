# Fediverse Public Key Directory Server Reference Implementation

This is the reference implementation for the server-side component of the
[Public Key Directory specification](https://github.com/fedi-e2ee/public-key-directory-specification),
written in Go.

## What is this, and why does it exist?

The hardest part of designing end-to-end encryption for the Fediverse, as with most cryptography undertakings, is key
management. In short: How do you know which public key belongs to a stranger you want to chat with privately? And how
do you know you weren't deceived?

Our solution is to use **Key Transparency**, which involves publishing all public key enrollments and revocations to an
append-only ledger based on Merkle trees. This allows for a verifiable, auditable log of all key-related events, 
providing a strong foundation for trust.

This project, and the accompanying specification, are the result of an open-source effort to solve this problem.
You can read more about the project's origins and design philosophy on Soatok's blog, *Dhole Moments*:

* [Towards Federated Key Transparency](https://soatok.blog/2024/06/06/towards-federated-key-transparency/)
* [Key Transparency and the Right to be Forgotten](https://soatok.blog/2024/11/21/key-transparency-and-the-right-to-be-forgotten/)

## Documentation

For detailed information on how to deploy and configure the server, please see the
[online documentation](./docs/README.md).

## License

This project is licensed under the [ISC License](LICENSE).
