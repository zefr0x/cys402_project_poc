> [!Warning]
> This repository/project is a univertiy project. It neither has quality standards nor had security auditing and is no longer maintained. If you are interested in the project, it's free software under the GPL-3.0 license.

A blockchain-based voting system, where votes are encrypted using multiparty homomorphic encryption.

Each participant contributes their public key to the blockchain, which is then combined to be used to encrypt votes before they're published. The decryption proccess is done cooperatively, so no single person is able to decrypt the result. The system allows for private voting by performing calculations on encrypted data without decrypting them, ensuring transparency and security throughout the process.

## Known Issues and Limitations

- **Input Validation and Data Types**: The system assumes that input data are valid, either 0 or 1 value for a vote, which enables any malicious peer to vote with a larger number. This should be addressed by the cryptographic algorithm at the data type level.
- **Blockchain Limitations**: Peers don't have any limitation on adding blocks to the blockchain. This can lead to voting more than one time.
- **Fault Tolerance Limitations**: If some peers didn't participate in the decryption process, we will not be able to decrypt the final result. Can be solved using https://github.com/zama-ai/tfhe-rs/issues/381.

## Usage

Use `cargo` to compile and run the program:
```sh
RUST_LOG=info cargo run --
```

Pass the `--help` argument to list avialable options.

### List of coomands
Those commands can be passed to the program while running.
- **ls**: List all the blocks in the blockchain
- **lsp**: List connected peers
- **vote**: Create your vote (every node must run it).
- **decrypt**: Calculate and partially decrept the result (every node must run it).
- **result**: Print the final result.

> [!NOTE]
> You might need to configure or turn off your firewall for peers to be able to connect.
