# Contributing to Serde

Serde welcomes contribution from everyone in the form of suggestions, bug
reports, pull requests, and feedback. This document gives some guidance if you
are thinking of helping us.

Please reach out here in a GitHub issue or in the #serde IRC channel on
[`irc.mozilla.org`] if we can do anything to help you contribute.

[`irc.mozilla.org`]: https://wiki.mozilla.org/IRC

## Submitting bug reports and feature requests

Serde development is spread across lots of repositories, but this serde-rs/serde
repository is always a safe choice for opening any issues related to Serde.

When reporting a bug or asking for help, please include enough details so that
the people helping you can reproduce the behavior you are seeing. For some tips
on how to approach this, read about how to produce a [Minimal, Complete, and
Verifiable example].

[Minimal, Complete, and Verifiable example]: https://stackoverflow.com/help/mcve

When making a feature request, please make it clear what problem you intend to
solve with the feature, any ideas for how Serde could support solving that
problem, any possible alternatives, and any disadvantages.

## Running the test suite

We encourage you to check that the test suite passes locally before submitting a
pull request with your changes. If anything does not pass, typically it will be
easier to iterate and fix it locally than waiting for the CI servers to run
tests for you.

##### In the [`serde`] directory

```sh
# Test all the example code in Serde documentation
cargo test
```

##### In the [`test_suite/deps`] directory

```sh
# This is a prerequisite for running the full test suite
cargo clean && cargo update && cargo build
```

##### In the [`test_suite`] directory

```sh
# Run the full test suite, including tests of unstable functionality
cargo test --features unstable
```

[`serde`]: https://github.com/serde-rs/serde/tree/master/serde
[`test_suite/deps`]: https://github.com/serde-rs/serde/tree/master/test_suite/deps
[`test_suite`]: https://github.com/serde-rs/serde/tree/master/test_suite

## Conduct

In all Serde-related forums, we follow the [Rust Code of Conduct]. For
escalation or moderation issues please contact Erick (erick.tryzelaar@gmail.com)
instead of the Rust moderation team.

[Rust Code of Conduct]: https://www.rust-lang.org/conduct.html
