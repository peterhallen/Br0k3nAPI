# Contributing to Br0K3nAPI

We welcome contributions to `Br0K3nAPI`! Whether you're fixing a bug, improving documentation, or suggesting a new vulnerability to include, your help is appreciated.

## How to Contribute

1.  **Fork the repository:** Start by forking the project to your own GitHub account.
2.  **Create a new branch:** Create a branch for your changes in your fork.
3.  **Make your changes:** Implement your bug fix or feature.
4.  **Test your changes:** Ensure that your changes do not break existing functionality and that all tests pass.
5.  **Submit a pull request:** Open a pull request from your fork to the main `Br0K3nAPI` repository.

## Running Tests

To ensure the stability and reliability of the API, we have a suite of tests that verify both the core functionality and the intentional vulnerabilities. Before submitting a pull request, please run the tests to ensure everything is working as expected.

To run the full test suite, execute the following command from the root of the project directory:

```sh
go test -v
```

This command will run all unit, integration, and vulnerability confirmation tests. The `-v` flag provides verbose output, showing the status of each individual test.

Thank you for helping to make `Br0K3nAPI` a better learning tool!