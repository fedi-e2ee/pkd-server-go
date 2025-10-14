# Contributing to the Public Key Directory Server

First off, thank you for considering contributing! This document provides guidelines for contributing to the project.

## How to Contribute

We welcome contributions in the form of bug reports, feature requests, and pull requests.

### Reporting Bugs

If you find a bug, please open an issue on our GitHub repository. Be sure to include a clear title and description,
as much relevant information as possible, and a code sample or an executable test case demonstrating the expected
behavior that is not occurring.

### Suggesting Enhancements

If you have an idea for an enhancement, please open an issue to discuss it. This allows us to coordinate our efforts and
prevent duplication of work.

### Pull Requests

We welcome pull requests for bug fixes and new features. Before submitting a pull request, please ensure the following:

1.  You have opened an issue to discuss the change.
2.  Your code adheres to the project's coding standards.
3.  You have added or updated tests to cover your changes.
4.  All tests pass.

## Local Development Environment

To set up a local development environment, you will need to have Go installed on your system.

1.  **Clone the repository:**

    ```sh
    git clone https://github.com/fedi-e2ee/pkd-server-go
    cd pkd-server
    ```

2.  **Install dependencies:**

    ```sh
    go mod tidy
    ```

## Running Tests

### SigSum Integration

For tests involving the SigSum integration, a SigSum server must be running in the background. You can start a local
SigSum server using the following command:

```sh
go run github.com/sigsum/sigsum-go/cmd/sigsum-log-server@v0.2.0 &
```

This project uses both unit tests and mutation tests to ensure code quality.

### Unit Tests

To run the unit tests, use the following command:

```sh
go test -v ./...
```

### Mutation Tests

We use `go-gremlins` for mutation testing. To run the mutation tests, use the following command:

```sh
go-gremlins
```

Please ensure that all tests pass before submitting a pull request.
