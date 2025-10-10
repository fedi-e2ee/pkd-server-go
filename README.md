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

## Project Goals and Non-Goals

Our design decisions are guided by two main principles: **Build for People** and **Security Over Legacy**.

### Goals

* **Enable Secure Communication:** The primary goal is to enable more people to communicate securely with each other.
* **User-Friendly Security:** We aim to minimize the knowledge and effort required for users to use the system securely.
* **Privacy:** We value user privacy and only store the minimum amount of information necessary.
  We also provide a mechanism for data deletion.
* **Transparency:** We believe in clearly communicating errors and security incidents to users.

### Non-Goals

* **Legacy Compatibility:** We will not compromise on security or simplicity for the sake of compatibility with
  existing, but flawed, standards.
* **Manual Key Verification:** While we provide a strong foundation for trust, advanced key verification mechanisms
  (e.g., comparing key fingerprints) are out of scope for this project but can be built on top of it.

## License

This project is licensed under the [ISC License](LICENSE).
