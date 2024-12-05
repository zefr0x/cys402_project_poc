Use `cargo` to compile and run the program:
```sh
RUST_LOG=info cargo run --
```

Pass the `--help` argument to list avialable options.

## List of coomands
Those commands can be passed to the program while running.
- **ls**: List all the blocks in the blockchain
- **lsp**: List connected peers
- **create global**: To create global key after all nodes shared thier public key shares.
- **vote**: Create your vote (every node must run ti).
- **tally**: Calculate and partially decrept the result (every node must run it).
- **result**: Print the final result.

> [!NOTE]
> You might need to configure or turn off your firewall for peers to be able to connect.
