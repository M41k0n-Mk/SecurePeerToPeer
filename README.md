# SecurePeerToPeer

Peer2Peer Secure is an app for secure, end-to-end encrypted communication between users without servers. It uses digital keys to ensure privacy and authenticity, and is designed to evolve for messaging, photos, and videos, all fully peer-to-peer.

## Features

- **End-to-End Encryption**: Messages are encrypted using Ed25519 digital signatures
- **Peer-to-Peer Communication**: Direct connection between users without central servers
- **Secure Handshake**: Identity verification through cryptographic signatures
- **Continuous Chat**: Real-time messaging after initial connection
- **Timestamp Support**: Message ordering with timestamps
- **Cross-Platform Compatibility**: Java 11+ with BouncyCastle fallback

## Current Implementation

### ✅ Completed Features
- Secure identity generation with Ed25519 keys
- Encrypted handshake protocol
- Continuous chat loop with message verification
- Timestamp support for message ordering
- BouncyCastle integration for Java 11 compatibility

### 🔄 Next Priorities (GitHub Issues)
- User interface (CLI to GUI)
- Proxy/Tor support for anonymous communication
- File transfer capabilities
- Group chat functionality
- Mobile app versions

## Architecture

```
src/main/java/me.m41k0n/
├── PeerToPeerApp.java      # Main application with server/client modes
├── domain/
│   ├── Message.java        # Message model with encryption
│   └── PeerIdentity.java   # User identity and key management
└── infra/
    └── CryptoUtils.java    # Cryptographic utilities (Ed25519)
```

## Testing

The project includes comprehensive testing:

- **Unit Tests**: Core cryptographic functions
- **Integration Tests**: Full P2P communication simulation
- **Code Quality**: Checkstyle linting
- **Coverage**: JaCoCo coverage reports

### Running Tests

```bash
# Run all tests
mvn test

# Run integration tests only
mvn verify

# Run with coverage report
mvn test jacoco:report
```

## CI/CD Pipeline

Automated pipeline with GitHub Actions:

- **Build**: Maven compilation
- **Linting**: Checkstyle code quality checks
- **Unit Tests**: JUnit 5 test execution
- **Integration Tests**: End-to-end P2P communication tests
- **Coverage**: JaCoCo coverage reporting
- **Artifacts**: JAR file generation

## Building and Running

### Prerequisites
- Java 11 or higher
- Maven 3.6+

### Build
```bash
mvn clean compile
```

### Run
```bash
# Start as server
java -cp target/classes:$(mvn dependency:build-classpath | grep -v '\[' | tail -1) me.m41k0n.PeerToPeerApp

# Or build JAR and run
mvn package
java -jar target/p2p-secure-app-1.0.0.jar
```

### Manual Testing
1. Start server: Choose 's' and enter port (e.g., 8080)
2. Start client: Choose 'c', enter server IP/port and server's public key
3. Chat continuously until 'exit' is typed

## Security

- Ed25519 digital signatures for message authenticity
- Public key exchange during handshake
- No central server storing messages or keys
- All communication is peer-to-peer and encrypted

## Development

### Project Structure
```
SecurePeerToPeer/
├── src/
│   ├── main/java/me.m41k0n/
│   └── test/java/me.m41k0n/
├── .github/workflows/ci.yml    # CI/CD pipeline
├── checkstyle.xml             # Code quality rules
├── pom.xml                    # Maven configuration
└── README.md
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure CI/CD pipeline passes
5. Submit a pull request

# Disclaimer

This project is for educational and personal experimentation only.

- Run tools in isolated lab environments (VMs or private networks). Defaults bind to `127.0.0.1`.
- Do not use in production. If you explicitly expose this service to the Internet, you accept full responsibility for any risks.
- Do not commit or publish real private keys, credentials, or personal data.
- Found a bug or improvement? Fork the repo and submit a pull request, or open an issue with reproduction steps.
